// Package rtrtest provides a scriptable fake RTR cache (RFC 8210) for tests
// of RTR clients and of code wired to them.
package rtrtest

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// PDU types (RFC 8210 §5).
const (
	pduSerialNotify  = 0
	PDUSerialQuery   = 1
	PDUResetQuery    = 2
	pduCacheResponse = 3
	pduIPv4Prefix    = 4
	pduIPv6Prefix    = 6
	pduEndOfData     = 7
	pduCacheReset    = 8
	pduErrorReport   = 10
	pduASPA          = 11
)

// Query is a query a client sent the cache, and the connection it came on,
// for the test to answer.
type Query struct {
	Version uint8
	Type    uint8  // PDUResetQuery or PDUSerialQuery
	Session uint16 // Serial Query only
	Serial  uint32 // Serial Query only
	At      time.Time
	Conn    *Conn
}

// Conn is one client connection to the cache.
type Conn struct {
	t    testing.TB
	nc   net.Conn
	done <-chan struct{} // the cache's: closed when the test ends
	mu   sync.Mutex      // serializes Send: one call's PDUs are never interleaved with another's
}

// Send writes PDUs to the client, all of them before any other Send on the
// connection writes. A write error is logged, not fatal: the client may
// have closed the connection on purpose.
func (c *Conn) Send(pdus ...[]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range pdus {
		if _, err := c.nc.Write(p); err != nil {
			select {
			case <-c.done: // the test is over; logging now would panic
			default:
				c.t.Logf("rtrtest: send: %v", err)
			}
			return
		}
	}
}

// Close closes the connection from the cache's side cleanly (a FIN): the
// client reads EOF once it has read everything sent before.
func (c *Conn) Close() { c.nc.Close() }

// Reset closes the connection abruptly, with a TCP RST instead of a FIN
// (SO_LINGER 0), as a cache does that closes with client bytes still
// unread. The client's next read fails with "connection reset by peer";
// anything it had not read yet may be lost.
func (c *Conn) Reset() {
	if tc, ok := c.nc.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	c.nc.Close()
}

// Cache is a fake RTR cache listening on 127.0.0.1. It answers nothing on
// its own: every query the client sends arrives on Queries. For a cache
// that answers from a data set, see Server.
type Cache struct {
	t       testing.TB
	ln      net.Listener
	Queries chan Query
	done    chan struct{} // closed when the test ends

	mu    sync.Mutex
	conns []net.Conn
}

// NewCache starts a fake cache; it is closed when the test ends.
func NewCache(t testing.TB) *Cache {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("rtrtest: listen: %v", err)
	}
	c := &Cache{t: t, ln: ln, Queries: make(chan Query, 64), done: make(chan struct{})}
	go c.accept()
	t.Cleanup(func() {
		close(c.done)
		ln.Close()
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, nc := range c.conns {
			nc.Close()
		}
	})
	return c
}

// Addr is the address to point a client at.
func (c *Cache) Addr() string { return c.ln.Addr().String() }

func (c *Cache) accept() {
	for {
		nc, err := c.ln.Accept()
		if err != nil {
			return
		}
		c.mu.Lock()
		c.conns = append(c.conns, nc)
		c.mu.Unlock()
		go c.read(&Conn{t: c.t, nc: nc, done: c.done})
	}
}

func (c *Cache) read(conn *Conn) {
	r := bufio.NewReader(conn.nc)
	for {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint32(hdr[4:8]))-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		q := Query{Version: hdr[0], Type: hdr[1], At: time.Now(), Conn: conn}
		if q.Type == PDUSerialQuery && len(body) >= 4 {
			q.Session = binary.BigEndian.Uint16(hdr[2:4])
			q.Serial = binary.BigEndian.Uint32(body[0:4])
		}
		select {
		case c.Queries <- q:
		case <-c.done:
			return
		}
	}
}

// Next returns the next query, failing the test if none arrives within
// timeout.
func (c *Cache) Next(timeout time.Duration) Query {
	c.t.Helper()
	select {
	case q := <-c.Queries:
		return q
	case <-time.After(timeout):
		c.t.Fatalf("rtrtest: no query within %v", timeout)
		return Query{}
	}
}

// None fails the test if a query arrives within d.
func (c *Cache) None(d time.Duration, why string) {
	c.t.Helper()
	select {
	case q := <-c.Queries:
		c.t.Fatalf("rtrtest: unexpected query (type %d, serial %d) %s", q.Type, q.Serial, why)
	case <-time.After(d):
	}
}

func pdu(version, typ uint8, session uint16, body ...[]byte) []byte {
	n := 8
	for _, b := range body {
		n += len(b)
	}
	out := make([]byte, 8, n)
	out[0], out[1] = version, typ
	binary.BigEndian.PutUint16(out[2:4], session)
	binary.BigEndian.PutUint32(out[4:8], uint32(n))
	for _, b := range body {
		out = append(out, b...)
	}
	return out
}

func u32(vs ...uint32) []byte {
	var out []byte
	for _, v := range vs {
		out = binary.BigEndian.AppendUint32(out, v)
	}
	return out
}

// CacheResponse starts the cache's answer to a query.
func CacheResponse(version uint8, session uint16) []byte {
	return pdu(version, pduCacheResponse, session)
}

// IPv4Prefix announces (or withdraws) a VRP.
func IPv4Prefix(version uint8, announce bool, prefix netip.Prefix, maxLen uint8, asn uint32) []byte {
	flags := byte(0)
	if announce {
		flags = 1
	}
	a := prefix.Addr().As4()
	return pdu(version, pduIPv4Prefix, 0,
		[]byte{flags, byte(prefix.Bits()), maxLen, 0}, a[:], u32(asn))
}

// IPv6Prefix announces (or withdraws) an IPv6 VRP.
func IPv6Prefix(version uint8, announce bool, prefix netip.Prefix, maxLen uint8, asn uint32) []byte {
	flags := byte(0)
	if announce {
		flags = 1
	}
	a := prefix.Addr().As16()
	return pdu(version, pduIPv6Prefix, 0,
		[]byte{flags, byte(prefix.Bits()), maxLen, 0}, a[:], u32(asn))
}

// EndOfData ends the cache's answer. Version 0 carries only the serial.
func EndOfData(version uint8, session uint16, serial, refresh, retry, expire uint32) []byte {
	if version == 0 {
		return pdu(version, pduEndOfData, session, u32(serial))
	}
	return pdu(version, pduEndOfData, session, u32(serial, refresh, retry, expire))
}

// ErrorReport sends an Error Report with the given code and text and no
// encapsulated PDU.
func ErrorReport(version uint8, code uint16, text string) []byte {
	return pdu(version, pduErrorReport, code, u32(0), u32(uint32(len(text))), []byte(text))
}

// ASPA announces (or withdraws) a customer AS's providers (version 2), in
// the layout the client parses: flags in the high byte of the header's
// session field, then the customer and provider ASNs.
func ASPA(announce bool, customer uint32, providers ...uint32) []byte {
	flags := uint16(0)
	if announce {
		flags = 1
	}
	return pdu(2, pduASPA, flags<<8, u32(append([]uint32{customer}, providers...)...))
}

// CacheReset tells the client the cache cannot answer its Serial Query
// incrementally; the client must send a Reset Query.
func CacheReset(version uint8) []byte {
	return pdu(version, pduCacheReset, 0)
}

// SerialNotify tells the client the cache has a new serial.
func SerialNotify(version uint8, session uint16, serial uint32) []byte {
	return pdu(version, pduSerialNotify, session, u32(serial))
}

// Gauge returns the value of the gauge name{cache=cache} from the default
// registry, or -1 if there is no such series.
func Gauge(name, cache string) float64 {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return -1
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "cache" && lp.GetValue() == cache {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	return -1
}

// CounterSum returns the sum over every series of the counter
// name{cache=cache,...} in the default registry (for example
// raven_rtr_anomaly_total across severities), or 0 if there is none.
func CounterSum(name, cache string) float64 {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return 0
	}
	sum := 0.0
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "cache" && lp.GetValue() == cache {
					sum += m.GetCounter().GetValue()
				}
			}
		}
	}
	return sum
}
