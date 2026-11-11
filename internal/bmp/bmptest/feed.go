// Package bmptest is a fake monitored router for tests: it dials a BMP
// listener (RFC 7854) and sends what a router would, a message at a time,
// with BGP UPDATEs encoded by GoBGP's packet library, independently of
// RAVEN's own decoder.
package bmptest

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// BMP message types (RFC 7854 §4.1).
const (
	msgRouteMonitoring = 0
	msgPeerDown        = 2
	msgPeerUp          = 3
	msgInitiation      = 4
	msgTermination     = 5
)

// Peer is a BGP peer of the fake router, in the global instance.
type Peer struct {
	Addr  netip.Addr // the peer's address, IPv4 or IPv6
	ASN   uint32
	BGPID netip.Addr // the peer's BGP identifier (IPv4)
	// PostPolicy sends the peer's routes as Adj-RIB-In post-policy; by
	// default they are pre-policy.
	PostPolicy bool
}

// Route is one announcement. Prefix may be IPv4 (sent in the UPDATE's NLRI,
// with NEXT_HOP) or IPv6 (in MP_REACH_NLRI).
type Route struct {
	Prefix  netip.Prefix
	ASPath  []uint32   // one AS_SEQUENCE, the peer's AS first
	NextHop netip.Addr // defaults to the peer's address (IPv4) or 2001:db8::1
	// Communities are RFC 1997 communities, as high<<16 | low.
	Communities []uint32
	// LargeCommunities are RFC 8092 large communities: global, data1, data2.
	LargeCommunities [][3]uint32
}

// Feed is one BMP session to a listener.
type Feed struct {
	t    testing.TB
	conn net.Conn
	mu   sync.Mutex
	// LocalASN and LocalID are the monitored router's AS and BGP ID, in the
	// OPEN it sent each peer (Peer Up).
	LocalASN uint32
	LocalID  netip.Addr
}

// Dial connects to the BMP listener at addr. The connection is closed when
// the test ends.
func Dial(t testing.TB, addr string) *Feed {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("bmptest: dial %s: %v", addr, err)
	}
	f := &Feed{t: t, conn: conn, LocalASN: 64496, LocalID: netip.MustParseAddr("192.0.2.254")}
	t.Cleanup(func() { conn.Close() })
	return f
}

// LocalAddr is the feed's source address: the router address RAVEN sees.
func (f *Feed) LocalAddr() netip.Addr {
	return f.conn.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
}

func (f *Feed) send(msgType uint8, body []byte) {
	f.t.Helper()
	msg := make([]byte, 6, 6+len(body))
	msg[0] = 3 // BMP version 3
	binary.BigEndian.PutUint32(msg[1:5], uint32(6+len(body)))
	msg[5] = msgType
	msg = append(msg, body...)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.conn.Write(msg); err != nil {
		f.t.Fatalf("bmptest: send BMP message type %d: %v", msgType, err)
	}
}

func tlv(typ uint16, value []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
	return append(b, value...)
}

// Initiation sends the Initiation message, with the router's sysName and
// sysDescr.
func (f *Feed) Initiation(sysName string) {
	f.t.Helper()
	f.send(msgInitiation, append(tlv(2, []byte(sysName)), tlv(1, []byte("bmptest"))...))
}

// perPeerHeader is the 42-byte per-peer header for p (RFC 7854 §4.2).
func perPeerHeader(p Peer) []byte {
	h := make([]byte, 42)
	h[0] = 0 // global instance peer
	if p.Addr.Is6() {
		h[1] |= 0x80
	}
	if p.PostPolicy {
		h[1] |= 0x40
	}
	a := p.Addr.As16()
	if p.Addr.Is4() {
		a = [16]byte{}
		a4 := p.Addr.As4()
		copy(a[12:], a4[:])
	}
	copy(h[10:26], a[:])
	binary.BigEndian.PutUint32(h[26:30], p.ASN)
	id := p.BGPID.As4()
	copy(h[30:34], id[:])
	now := time.Now()
	binary.BigEndian.PutUint32(h[34:38], uint32(now.Unix()))
	binary.BigEndian.PutUint32(h[38:42], uint32(now.Nanosecond()/1000))
	return h
}

func (f *Feed) open(asn uint32, id netip.Addr) []byte {
	f.t.Helper()
	as2 := uint16(asn)
	if asn > 0xffff {
		as2 = 23456 // AS_TRANS
	}
	caps := []bgp.ParameterCapabilityInterface{
		bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC),
		bgp.NewCapMultiProtocol(bgp.RF_IPv6_UC),
		bgp.NewCapFourOctetASNumber(asn),
	}
	msg, err := bgp.NewBGPOpenMessage(as2, 90, id, []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})
	if err != nil {
		f.t.Fatalf("bmptest: OPEN: %v", err)
	}
	b, err := msg.Serialize()
	if err != nil {
		f.t.Fatalf("bmptest: serialize OPEN: %v", err)
	}
	return b
}

// PeerUp sends a Peer Up for p, with the OPENs the router sent and received
// (both four-octet AS capable, IPv4 and IPv6 unicast).
func (f *Feed) PeerUp(p Peer) {
	f.t.Helper()
	body := perPeerHeader(p)
	local := make([]byte, 16)
	if f.LocalAddr().Is4() {
		a := f.LocalAddr().As4()
		copy(local[12:], a[:])
	}
	body = append(body, local...)
	body = binary.BigEndian.AppendUint16(body, 179)   // local port
	body = binary.BigEndian.AppendUint16(body, 50179) // remote port
	body = append(body, f.open(f.LocalASN, f.LocalID)...)
	body = append(body, f.open(p.ASN, p.BGPID)...)
	f.send(msgPeerUp, body)
}

// Announce sends one Route Monitoring message per route from p.
func (f *Feed) Announce(p Peer, routes ...Route) {
	f.t.Helper()
	for _, r := range routes {
		f.routeMonitoring(p, f.update(p, r))
	}
}

// Withdraw sends one Route Monitoring message withdrawing prefixes (IPv4 in
// the UPDATE's Withdrawn Routes, IPv6 in MP_UNREACH_NLRI) from p.
func (f *Feed) Withdraw(p Peer, prefixes ...netip.Prefix) {
	f.t.Helper()
	var v4, v6 []bgp.PathNLRI
	for _, pfx := range prefixes {
		n := pathNLRI(f.t, pfx)
		if pfx.Addr().Is4() {
			v4 = append(v4, n)
		} else {
			v6 = append(v6, n)
		}
	}
	var attrs []bgp.PathAttributeInterface
	if len(v6) > 0 {
		mp, err := bgp.NewPathAttributeMpUnreachNLRI(bgp.RF_IPv6_UC, v6)
		if err != nil {
			f.t.Fatalf("bmptest: MP_UNREACH_NLRI: %v", err)
		}
		attrs = append(attrs, mp)
	}
	f.routeMonitoring(p, bgp.NewBGPUpdateMessage(v4, attrs, nil))
}

// PeerDown sends a Peer Down for p: the remote system closed the session,
// with no notification (reason 4).
func (f *Feed) PeerDown(p Peer) {
	f.t.Helper()
	f.send(msgPeerDown, append(perPeerHeader(p), 4))
}

// Terminate sends a Termination message (reason 0, administratively closed)
// and closes the connection.
func (f *Feed) Terminate() {
	f.t.Helper()
	f.send(msgTermination, tlv(1, []byte{0, 0}))
	f.conn.Close()
}

// Close closes the connection without a Termination.
func (f *Feed) Close() { f.conn.Close() }

func pathNLRI(t testing.TB, p netip.Prefix) bgp.PathNLRI {
	t.Helper()
	n, err := bgp.NewIPAddrPrefix(p)
	if err != nil {
		t.Fatalf("bmptest: prefix %s: %v", p, err)
	}
	return bgp.PathNLRI{NLRI: n}
}

func (f *Feed) update(p Peer, r Route) *bgp.BGPMessage {
	f.t.Helper()
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0), // IGP
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, r.ASPath),
		}),
	}
	if len(r.Communities) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeCommunities(r.Communities))
	}
	if len(r.LargeCommunities) > 0 {
		var lcs []*bgp.LargeCommunity
		for _, c := range r.LargeCommunities {
			lcs = append(lcs, bgp.NewLargeCommunity(c[0], c[1], c[2]))
		}
		attrs = append(attrs, bgp.NewPathAttributeLargeCommunities(lcs))
	}
	nlri := pathNLRI(f.t, r.Prefix)
	if r.Prefix.Addr().Is4() {
		nh := r.NextHop
		if !nh.IsValid() {
			nh = p.Addr
			if !nh.Is4() {
				nh = netip.MustParseAddr("192.0.2.1")
			}
		}
		a, err := bgp.NewPathAttributeNextHop(nh)
		if err != nil {
			f.t.Fatalf("bmptest: NEXT_HOP: %v", err)
		}
		attrs = append(attrs, a)
		return bgp.NewBGPUpdateMessage(nil, attrs, []bgp.PathNLRI{nlri})
	}
	nh := r.NextHop
	if !nh.IsValid() {
		nh = netip.MustParseAddr("2001:db8::1")
	}
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{nlri}, nh)
	if err != nil {
		f.t.Fatalf("bmptest: MP_REACH_NLRI: %v", err)
	}
	return bgp.NewBGPUpdateMessage(nil, append(attrs, mp), nil)
}

func (f *Feed) routeMonitoring(p Peer, msg *bgp.BGPMessage) {
	f.t.Helper()
	b, err := msg.Serialize()
	if err != nil {
		f.t.Fatalf("bmptest: serialize UPDATE: %v", err)
	}
	f.send(msgRouteMonitoring, append(perPeerHeader(p), b...))
}
