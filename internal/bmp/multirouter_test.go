package bmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// addPathCap is an ADD-PATH capability (code 69) for (afi, safi) with the
// given Send/Receive value: 1 receive, 2 send, 3 both.
func addPathCap(entries ...[3]uint16) []byte {
	var v []byte
	for _, e := range entries {
		v = binary.BigEndian.AppendUint16(v, e[0])
		v = append(v, byte(e[1]), byte(e[2]))
	}
	return append([]byte{bgpCapAddPath, byte(len(v))}, v...)
}

// openMsg is a BGP OPEN from asn carrying the given capabilities.
func openMsg(asn uint16, caps ...[]byte) []byte {
	var capParam []byte
	for _, c := range caps {
		capParam = append(capParam, c...)
	}
	var opt []byte
	if len(capParam) > 0 {
		opt = append([]byte{bgpOptParamCapabilities, byte(len(capParam))}, capParam...)
	}
	body := []byte{4}
	body = binary.BigEndian.AppendUint16(body, asn)
	body = append(body, 0, 90, 192, 0, 2, 1, byte(len(opt)))
	body = append(body, opt...)
	msg := bytes.Repeat([]byte{0xff}, 16)
	msg = binary.BigEndian.AppendUint16(msg, uint16(19+len(body)))
	msg = append(msg, bgpMsgTypeOpen)
	return append(msg, body...)
}

// perPeerHeaderRD is a per-peer header for peer in instance rd (0 = global).
func perPeerHeaderRD(peer netip.Addr, rd uint64) []byte {
	h := perPeerHeader(peer)
	if rd != 0 {
		h[0] = PeerTypeRDLocal
		binary.BigEndian.PutUint64(h[2:10], rd)
	}
	return h
}

// peerUpWithOpens is a Peer Up for peer in instance rd, with the OPEN the
// router sent and the one it received.
func peerUpWithOpens(peer netip.Addr, rd uint64, sent, received []byte) []byte {
	body := append(perPeerHeaderRD(peer, rd), make([]byte, 20)...)
	body = append(body, sent...)
	body = append(body, received...)
	return bmpMsg(MsgTypePeerUp, body)
}

type pathNLRI struct {
	pathID uint32
	prefix netip.Prefix
}

// encodeNLRI encodes prefixes as NLRI, with path identifiers if addPath.
func encodeNLRI(addPath bool, entries ...pathNLRI) []byte {
	var out []byte
	for _, e := range entries {
		if addPath {
			out = binary.BigEndian.AppendUint32(out, e.pathID)
		}
		b := e.prefix.Addr().AsSlice()
		out = append(out, byte(e.prefix.Bits()))
		out = append(out, b[:(e.prefix.Bits()+7)/8]...)
	}
	return out
}

// updateBody is a BGP UPDATE body: IPv4 withdrawals and announcements, and
// IPv6 announcements in MP_REACH_NLRI, each encoded with or without path
// identifiers.
func updateBody(v4AddPath, v6AddPath bool, withdrawn, v4, v6 []pathNLRI) []byte {
	attrs := []byte{
		0x40, 1, 1, 0, // ORIGIN IGP
		0x40, 2, 6, 2, 1, 0, 0, 0xfb, 0xf5, // AS_PATH [64501]
		0x40, 3, 4, 192, 0, 2, 254, // NEXT_HOP
	}
	if len(v6) > 0 {
		mp := []byte{0, 2, 1, 16}
		mp = append(mp, netip.MustParseAddr("2001:db8::fe").AsSlice()...)
		mp = append(mp, 0)
		mp = append(mp, encodeNLRI(v6AddPath, v6...)...)
		attrs = append(attrs, 0x90, 14)
		attrs = binary.BigEndian.AppendUint16(attrs, uint16(len(mp)))
		attrs = append(attrs, mp...)
	}
	w := encodeNLRI(v4AddPath, withdrawn...)
	body := binary.BigEndian.AppendUint16(nil, uint16(len(w)))
	body = append(body, w...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	return append(body, encodeNLRI(v4AddPath, v4...)...)
}

func routeMonitoringRD(peer netip.Addr, rd uint64, update []byte) []byte {
	bgp := bytes.Repeat([]byte{0xff}, 16)
	bgp = binary.BigEndian.AppendUint16(bgp, uint16(19+len(update)))
	bgp = append(bgp, 2)
	bgp = append(bgp, update...)
	return bmpMsg(MsgTypeRouteMonitoring, append(perPeerHeaderRD(peer, rd), bgp...))
}

var (
	v4uni = [3]uint16{1, 1, 0}
	v6uni = [3]uint16{2, 1, 0}
)

func withSR(fam [3]uint16, sr uint16) [3]uint16 { fam[2] = sr; return fam }

// ADD-PATH is in effect per direction and per address family only when both
// OPENs agree (RFC 7911 §4): updates from the peer carry path identifiers if
// the router can receive them and the peer can send them; updates to the
// peer, the other way round.
func TestPeerUpNegotiatesAddPath(t *testing.T) {
	peer := netip.MustParseAddr("80.81.194.180")
	for _, tc := range []struct {
		name       string
		sent, recv [][3]uint16
		want       AddPathState
	}{
		{"none", nil, nil, AddPathState{}},
		{"router receives, peer sends: in only", [][3]uint16{withSR(v4uni, 1)}, [][3]uint16{withSR(v4uni, 2)},
			AddPathState{In: AFIIPv4Unicast}},
		{"router sends, peer receives: out only", [][3]uint16{withSR(v4uni, 2)}, [][3]uint16{withSR(v4uni, 1)},
			AddPathState{Out: AFIIPv4Unicast}},
		{"both receive: neither", [][3]uint16{withSR(v4uni, 1)}, [][3]uint16{withSR(v4uni, 1)}, AddPathState{}},
		{"both send: neither", [][3]uint16{withSR(v4uni, 2)}, [][3]uint16{withSR(v4uni, 2)}, AddPathState{}},
		{"router only: neither", [][3]uint16{withSR(v4uni, 3)}, nil, AddPathState{}},
		{"peer only: neither", nil, [][3]uint16{withSR(v4uni, 3)}, AddPathState{}},
		{"both ways, per family", [][3]uint16{withSR(v4uni, 3), withSR(v6uni, 1)},
			[][3]uint16{withSR(v4uni, 3), withSR(v6uni, 3)},
			AddPathState{In: AFIIPv4Unicast | AFIIPv6Unicast, Out: AFIIPv4Unicast}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sentCaps, recvCaps [][]byte
			if tc.sent != nil {
				sentCaps = append(sentCaps, addPathCap(tc.sent...))
			}
			if tc.recv != nil {
				recvCaps = append(recvCaps, addPathCap(tc.recv...))
			}
			msg := peerUpWithOpens(peer, 0, openMsg(64500, sentCaps...), openMsg(64501, recvCaps...))
			pu, err := ParsePeerUp(msg[CommonHeaderLen:])
			if err != nil {
				t.Fatal(err)
			}
			if pu.AddPath != tc.want || pu.LocalASN != 64500 {
				t.Errorf("AddPath %+v LocalASN %d, want %+v and 64500", pu.AddPath, pu.LocalASN, tc.want)
			}
		})
	}
}

// The UPDATE decoder reads path identifiers exactly when told ADD-PATH is in
// effect for the address family. The same bytes read with the wrong setting
// give wrong prefixes, which is why the setting comes from Peer Up.
func TestDecodeUpdateAddPathOnAndOff(t *testing.T) {
	router := netip.MustParseAddr("192.0.2.1")
	pph := BMPPerPeerHeader{PeerAddr: netip.MustParseAddr("80.81.194.180"), PeerASN: 64501}
	p1, p2 := netip.MustParsePrefix("1.1.1.0/24"), netip.MustParsePrefix("8.8.8.0/24")
	v6 := netip.MustParsePrefix("2001:db8:1::/48")
	type got struct {
		prefix netip.Prefix
		pathID uint32
	}
	decode := func(body []byte, addPath AFIMask) (routes, withdrawals []got) {
		rs, ws, m := parseBGPUpdate(body, pph, router, 0, addPath)
		if m.action != actNone {
			t.Fatalf("%+v", m)
		}
		for _, r := range rs {
			if r.Router != router || r.PeerAddr != pph.PeerAddr {
				t.Errorf("route %s keyed to router %s peer %s", r.Prefix, r.Router, r.PeerAddr)
			}
			routes = append(routes, got{r.Prefix, r.PathID})
		}
		for _, w := range ws {
			withdrawals = append(withdrawals, got{w.Prefix, w.PathID})
		}
		return
	}

	// ADD-PATH on for IPv4 and IPv6: two paths to one prefix, a withdrawn
	// path, and an IPv6 path.
	on := updateBody(true, true, []pathNLRI{{3, p2}}, []pathNLRI{{1, p1}, {2, p1}}, []pathNLRI{{7, v6}})
	rs, ws := decode(on, AFIIPv4Unicast|AFIIPv6Unicast)
	if want := []got{{p1, 1}, {p1, 2}, {v6, 7}}; !slices.Equal(rs, want) {
		t.Errorf("ADD-PATH on: routes %v, want %v", rs, want)
	}
	if want := []got{{p2, 3}}; !slices.Equal(ws, want) {
		t.Errorf("ADD-PATH on: withdrawals %v, want %v", ws, want)
	}

	// ADD-PATH off: plain NLRI, path ID 0.
	off := updateBody(false, false, []pathNLRI{{0, p2}}, []pathNLRI{{0, p1}}, []pathNLRI{{0, v6}})
	rs, ws = decode(off, 0)
	if want := []got{{p1, 0}, {v6, 0}}; !slices.Equal(rs, want) {
		t.Errorf("ADD-PATH off: routes %v, want %v", rs, want)
	}
	if want := []got{{p2, 0}}; !slices.Equal(ws, want) {
		t.Errorf("ADD-PATH off: withdrawals %v, want %v", ws, want)
	}

	// Per family: IPv4 with path IDs, IPv6 without.
	mixed := updateBody(true, false, nil, []pathNLRI{{4, p1}}, []pathNLRI{{0, v6}})
	rs, _ = decode(mixed, AFIIPv4Unicast)
	if want := []got{{p1, 4}, {v6, 0}}; !slices.Equal(rs, want) {
		t.Errorf("ADD-PATH IPv4 only: routes %v, want %v", rs, want)
	}

	// The wrong setting misreads the NLRI: here it no longer parses.
	if rs, _, m := parseBGPUpdate(on, pph, router, 0, 0); len(rs) == 3 || m.action == actNone {
		t.Errorf("ADD-PATH NLRI read without ADD-PATH gave %v (%+v): the test does not exercise the setting", rs, m)
	}
}

// dialFrom connects to h's listener from the given loopback source address,
// as a router at that address would, and starts the session.
func (h *sessionHarness) connectFrom(ctx context.Context, t *testing.T, src string) (net.Conn, *bmpSession, <-chan struct{}) {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	client, err := d.Dial("tcp", h.ln.Addr().String())
	if err != nil {
		t.Skipf("cannot dial from %s here: %v", src, err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := h.ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	sess, old := h.l.register(server)
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		h.l.handleSession(ctx, sess, old)
	}()
	return client, sess, ch
}

// Routes from BMP are keyed by the router (session source), the peer's
// instance, and, with ADD-PATH negotiated in Peer Up, the path identifier;
// a peer without ADD-PATH on the same session decodes plain NLRI.
func TestRoutesCarryRouterDistinguisherAndPathID(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _, _ := h.connectFrom(ctx, t, "127.0.0.2")

	vrfPeer, plainPeer := netip.MustParseAddr("80.81.194.180"), netip.MustParseAddr("80.81.194.181")
	const rd = uint64(0x0000fde8_00000064) // 65000:100
	p := netip.MustParsePrefix("1.1.1.0/24")
	send(t, client,
		initiationMsg("br1.nyc"),
		peerUpWithOpens(vrfPeer, rd, openMsg(64500, addPathCap(withSR(v4uni, 1))), openMsg(64501, addPathCap(withSR(v4uni, 2)))),
		peerUpWithOpens(plainPeer, 0, openMsg(64500), openMsg(64502)),
		routeMonitoringRD(vrfPeer, rd, updateBody(true, false, nil, []pathNLRI{{1, p}, {2, p}}, nil)),
		routeMonitoringRD(plainPeer, 0, updateBody(false, false, nil, []pathNLRI{{0, p}}, nil)),
	)
	router := netip.MustParseAddr("127.0.0.2")
	var got []types.RouteKey
	for len(got) < 3 {
		if ev := h.next(t); ev.Route != nil {
			got = append(got, ev.Route.Key())
		}
	}
	want := []types.RouteKey{
		{Peer: types.PeerRef{Router: router, Distinguisher: rd, Addr: vrfPeer}, Prefix: p, PathID: 1},
		{Peer: types.PeerRef{Router: router, Distinguisher: rd, Addr: vrfPeer}, Prefix: p, PathID: 2},
		{Peer: types.PeerRef{Router: router, Addr: plainPeer}, Prefix: p},
	}
	if !slices.Equal(got, want) {
		t.Errorf("route keys\n got  %+v\n want %+v", got, want)
	}
	if name := h.l.RouterName(router); name != "br1.nyc" {
		t.Errorf("RouterName = %q, want br1.nyc", name)
	}
	if got := h.l.RoutersNamed("br1.nyc"); !slices.Equal(got, []netip.Addr{router}) {
		t.Errorf("RoutersNamed = %v, want [%s]", got, router)
	}
}

// A reconnect from router A supersedes A's old session only; router B's
// session, from another address, is untouched.
func TestReconnectSupersedesOnlyThatRouter(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, a1, a1done := h.connectFrom(ctx, t, "127.0.0.2")
	bConn, b, _ := h.connectFrom(ctx, t, "127.0.0.3")
	_, a2, _ := h.connectFrom(ctx, t, "127.0.0.2")

	superseded := map[uint64]bool{}
	ended := map[uint64]bool{}
	for !superseded[a1.id] || !ended[a1.id] {
		ev := h.next(t)
		if ev.Superseded {
			superseded[ev.Session] = true
		}
		if ev.Withdrawal != nil && ev.Withdrawal.SessionEnd {
			ended[ev.Session] = true
		}
	}
	<-a1done
	if superseded[b.id] || ended[b.id] || superseded[a2.id] {
		t.Errorf("superseded %v ended %v: only router A's old session %d should be", superseded, ended, a1.id)
	}
	// Router B's session still works.
	send(t, bConn, peerUpMsg(netip.MustParseAddr("80.81.194.180")),
		routeMonitoringMsg(netip.MustParseAddr("80.81.194.180"), netip.MustParsePrefix("1.1.1.0/24")))
	for {
		ev := h.next(t)
		if ev.Route != nil {
			if ev.Session != b.id || ev.Route.Router != netip.MustParseAddr("127.0.0.3") {
				t.Errorf("route from session %d router %s, want router B's session %d", ev.Session, ev.Route.Router, b.id)
			}
			return
		}
	}
}

// A peer with ADD-PATH negotiated towards it only (router sends, peer
// receives): Adj-RIB-Out messages (RFC 8671, O flag) carry path IDs and are
// decoded with them; Adj-RIB-In messages from the same peer do not.
func TestAdjRIBOutUsesOutboundAddPath(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := h.connect(ctx, t)
	peer := netip.MustParseAddr("80.81.194.180")
	p := netip.MustParsePrefix("1.1.1.0/24")
	ribOut := routeMonitoringRD(peer, 0, updateBody(true, false, nil, []pathNLRI{{9, p}}, nil))
	ribOut[CommonHeaderLen+1] |= PeerFlagAdjRIBOut
	send(t, client,
		peerUpWithOpens(peer, 0, openMsg(64500, addPathCap(withSR(v4uni, 2))), openMsg(64501, addPathCap(withSR(v4uni, 1)))),
		ribOut,
		routeMonitoringRD(peer, 0, updateBody(false, false, nil, []pathNLRI{{0, p}}, nil)),
	)
	var got []uint32
	for len(got) < 2 {
		if ev := h.next(t); ev.Route != nil {
			if ev.Route.Prefix != p {
				t.Fatalf("decoded %s, want %s: wrong ADD-PATH setting", ev.Route.Prefix, p)
			}
			got = append(got, ev.Route.PathID)
		}
	}
	if !slices.Equal(got, []uint32{9, 0}) {
		t.Errorf("path IDs %v, want [9 0] (Adj-RIB-Out with, Adj-RIB-In without)", got)
	}
}
