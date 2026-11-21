package bmp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// spoofListener accepts real loopback connections but reports them as coming
// from remote, and counts the bytes the listener reads from each.
type spoofListener struct {
	net.Listener
	remote net.Addr
	read   *atomic.Int64
}

func (l *spoofListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &spoofConn{Conn: c, remote: l.remote, read: l.read}, nil
}

type spoofConn struct {
	net.Conn
	remote net.Addr
	read   *atomic.Int64
}

func (c *spoofConn) RemoteAddr() net.Addr { return c.remote }
func (c *spoofConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

func rejectedCount(t *testing.T) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "raven_bmp_rejected_connections_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" && l.GetValue() == "not_allowed" {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// bmpInitiation is a BMP Initiation message with no TLVs: common header only.
var bmpInitiation = []byte{3, 0, 0, 0, 6, 4}

// dialFrom starts a listener allowing allow, makes it see a connection from
// remote, sends a BMP message, and reports whether the listener read it and
// whether the client then saw its connection closed.
func dialFrom(t *testing.T, allow []string, remote string) (read int64, closed bool) {
	t.Helper()
	prefixes, err := config.ParseAllowedRouters(allow)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int64
	l := NewListener("unused", nil, make(chan types.IngestEvent, 64), slog.New(slog.NewTextHandler(io.Discard, nil)))
	l.SetAllowedRouters(prefixes)
	l.listener = &spoofListener{Listener: inner, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote)), read: &n}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); l.Start(ctx) }()
	defer func() { cancel(); wg.Wait() }()

	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(bmpInitiation)
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, rerr := c.Read(make([]byte, 1))
	closed = rerr != nil && !isTimeout(rerr)
	deadline := time.Now().Add(2 * time.Second)
	for !closed && n.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	return n.Load(), closed
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestAllowedRouters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		allow  []string
		remote string
		accept bool
	}{
		{"allowed address", []string{"192.0.2.10", "198.51.100.1"}, "192.0.2.10:179", true},
		{"prefix match", []string{"10.0.0.0/8"}, "10.20.30.40:179", true},
		{"IPv6 prefix match", []string{"2001:db8::/32"}, "[2001:db8:1::5]:179", true},
		{"IPv4-mapped source, IPv4 entry", []string{"80.81.194.180"}, "[::ffff:80.81.194.180]:179", true},
		{"IPv4 source, IPv4-mapped entry", []string{"::ffff:10.0.0.0/104"}, "10.1.2.3:179", true},
		{"empty list allows all", nil, "203.0.113.99:179", true},
		{"disallowed address", []string{"192.0.2.10"}, "192.0.2.11:179", false},
		{"outside prefix", []string{"10.0.0.0/8"}, "11.0.0.1:179", false},
		{"IPv4-mapped source outside", []string{"10.0.0.0/8"}, "[::ffff:11.0.0.1]:179", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := rejectedCount(t)
			read, closed := dialFrom(t, tc.allow, tc.remote)
			rejected := rejectedCount(t) - before
			if tc.accept {
				if read == 0 || rejected != 0 {
					t.Errorf("read %d bytes, rejected %v: want the BMP message read and nothing rejected", read, rejected)
				}
				return
			}
			if read != 0 || !closed || rejected != 1 {
				t.Errorf("read %d bytes, closed %v, rejected %v: want 0 bytes read, the connection closed, 1 rejection",
					read, closed, rejected)
			}
		})
	}
}

// With no allowlist, a listener bound beyond loopback warns once at startup;
// on loopback, or with an allowlist, it does not.
func TestOpenListenerWarns(t *testing.T) {
	for _, tc := range []struct {
		addr  string
		allow []string
		warn  bool
	}{
		{"0.0.0.0:0", nil, true},
		{"127.0.0.1:0", nil, false},
		{"0.0.0.0:0", []string{"192.0.2.10"}, false},
	} {
		var buf bytes.Buffer
		l := NewListener(tc.addr, nil, make(chan types.IngestEvent), slog.New(slog.NewTextHandler(&buf, nil)))
		prefixes, _ := config.ParseAllowedRouters(tc.allow)
		l.SetAllowedRouters(prefixes)
		if _, err := l.Listen(); err != nil {
			t.Fatal(err)
		}
		l.listener.Close()
		got := strings.Count(buf.String(), "level=WARN")
		if want := map[bool]int{true: 1, false: 0}[tc.warn]; got != want {
			t.Errorf("%s allow=%v: %d WARN lines, want %d:\n%s", tc.addr, tc.allow, got, want, buf.String())
		}
	}
}
