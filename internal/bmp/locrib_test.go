package bmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// locRIBHeader is a Loc-RIB per-peer header (RFC 9069 §4.1): peer type 3, the
// zero peer address, the router's own AS as Peer AS and its BGP ID.
func locRIBHeader(rd uint64, flags uint8, localAS uint32) []byte {
	h := make([]byte, PerPeerHeaderLen)
	h[0] = PeerTypeLocRIB
	h[1] = flags
	binary.BigEndian.PutUint64(h[2:10], rd)
	binary.BigEndian.PutUint32(h[26:30], localAS)
	copy(h[30:34], []byte{10, 0, 12, 1}) // BGP ID
	return h
}

// infoTLV is a Peer Up information TLV.
func infoTLV(typ uint16, v string) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

// locRIBPeerUp is a Loc-RIB Peer Up with fabricated OPENs and, unless
// tableName is "", a VRF/Table Name TLV after a free-form string TLV.
func locRIBPeerUp(rd uint64, flags uint8, localAS uint32, tableName string) []byte {
	body := append(locRIBHeader(rd, flags, localAS), make([]byte, 20)...)
	body = append(body, openMsg(uint16(localAS))...)
	body = append(body, openMsg(uint16(localAS))...)
	if tableName != "" {
		body = append(body, infoTLV(0, "fabricated")...)
		body = append(body, infoTLV(peerUpInfoTableName, tableName)...)
	}
	return bmpMsg(MsgTypePeerUp, body)
}

func locRIBPeerDown(rd uint64, localAS uint32) []byte {
	return bmpMsg(MsgTypePeerDown, append(locRIBHeader(rd, 0, localAS), 2)) // reason 2: local, no notification
}

func locRIBRouteMonitoring(rd uint64, flags uint8, localAS uint32, update []byte) []byte {
	bgp := bytes.Repeat([]byte{0xff}, 16)
	bgp = binary.BigEndian.AppendUint16(bgp, uint16(19+len(update)))
	bgp = append(bgp, 2)
	bgp = append(bgp, update...)
	return bmpMsg(MsgTypeRouteMonitoring, append(locRIBHeader(rd, flags, localAS), bgp...))
}

// endOfRIB is an empty UPDATE: the IPv4 unicast End-of-RIB marker.
var endOfRIB = []byte{0, 0, 0, 0}

// peerState returns raven_bmp_peer_state for a peer of the router named
// sysName, and whether the series exists.
func peerState(t *testing.T, sysName string, peer netip.Addr, rd string) (float64, bool) {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "raven_bmp_peer_state" {
			continue
		}
		for _, m := range mf.GetMetric() {
			l := map[string]string{}
			for _, lp := range m.GetLabel() {
				l[lp.GetName()] = lp.GetValue()
			}
			if l["router"] == sysName && l["peer"] == peer.String() && l["peer_distinguisher"] == rd {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func waitPeerState(t *testing.T, sysName string, peer netip.Addr, rd string, want float64) {
	t.Helper()
	waitFor(t, fmt.Sprintf("raven_bmp_peer_state{router=%s, peer=%v, rd=%q} = %v", sysName, peer, rd, want), func() bool {
		v, ok := peerState(t, sysName, peer, rd)
		return ok && v == want
	})
}

var zeroAddr = netip.IPv4Unspecified()

// hasLogLine reports whether one line of logs contains every part.
func hasLogLine(logs string, parts ...string) bool {
	for _, line := range strings.Split(logs, "\n") {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(line, p)
		}
		if all {
			return true
		}
	}
	return false
}

// A Loc-RIB header defines only the F flag, 0x80 (RFC 9069 §4.2): it is not
// the V flag, so a filtered Loc-RIB's zero address is IPv4 0.0.0.0, not ::;
// and no other flag applies, so the A bit does not make the AS_PATH 2-byte
// and no Loc-RIB route is post-policy or Adj-RIB-Out.
func TestLocRIBPerPeerHeader(t *testing.T) {
	all := PeerFlagLocRIBFiltered | PeerFlagPostPolicy | PeerFlagAS2 | PeerFlagAdjRIBOut
	h, err := ParsePerPeerHeader(locRIBHeader(0, all, 65000))
	if err != nil {
		t.Fatal(err)
	}
	if !h.IsLocRIB() || !h.IsLocRIBFiltered() {
		t.Errorf("IsLocRIB %v, IsLocRIBFiltered %v, want both", h.IsLocRIB(), h.IsLocRIBFiltered())
	}
	if h.IsIPv6() || h.IsPostPolicy() || h.IsAS2() || h.IsAdjRIBOut() {
		t.Errorf("Loc-RIB flags read as V %v, L %v, A %v, O %v; want none", h.IsIPv6(), h.IsPostPolicy(), h.IsAS2(), h.IsAdjRIBOut())
	}
	if h.PeerAddr != zeroAddr {
		t.Errorf("peer address %v, want %v", h.PeerAddr, zeroAddr)
	}
	if h.PeerASN != 65000 {
		t.Errorf("peer AS %d, want the router's own, 65000", h.PeerASN)
	}
	if got := ribTypeOf(h); got != types.LocRIB {
		t.Errorf("RIB %s, want loc-rib", got)
	}

	// For a BGP peer, 0x80 is still V.
	g := perPeerHeader(netip.MustParseAddr("192.0.2.1"))
	g[1] = PeerFlagIPv6
	if h, _ := ParsePerPeerHeader(g); !h.IsIPv6() || h.IsLocRIBFiltered() {
		t.Errorf("global peer with 0x80: IsIPv6 %v, IsLocRIBFiltered %v; want true, false", h.IsIPv6(), h.IsLocRIBFiltered())
	}

	// The A bit set on a Loc-RIB header must not change how its 4-byte
	// AS_PATH decodes.
	rm, err := ParseRouteMonitoring(locRIBRouteMonitoring(0, all, 65000,
		updateBody(false, false, nil, []pathNLRI{{0, netip.MustParsePrefix("1.1.1.0/24")}}, nil))[CommonHeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	routes, _, m := decodeRouteMonitoring(rm, netip.MustParseAddr("192.0.2.200"), 65000, 0)
	if m.action != actNone || len(routes) != 1 || len(routes[0].ASPath) != 1 || routes[0].ASPath[0] != 64501 {
		t.Errorf("Loc-RIB UPDATE with the A bit: routes %+v, malformation %+v; want one route with AS_PATH [64501]", routes, m)
	}
}

// The VRF/Table Name TLV (type 3) of a Loc-RIB Peer Up is read, after the
// OPENs and any other information TLV. Without one, the default Loc-RIB
// instance (zero distinguisher) has the RFC 9069 default name "global"; a
// VRF instance has no name.
func TestPeerUpTableName(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  []byte
		want string
	}{
		{"with table name", locRIBPeerUp(0, 0, 65000, "vrf-red"), "vrf-red"},
		{"without TLVs, default instance", locRIBPeerUp(0, 0, 65000, ""), "global"},
		{"without TLVs, VRF instance", locRIBPeerUp(1, 0, 65000, ""), ""},
		{"truncated TLV", func() []byte {
			m := locRIBPeerUp(1, 0, 65000, "vrf-red")
			m = m[:len(m)-3]
			binary.BigEndian.PutUint32(m[1:5], uint32(len(m)))
			return m
		}(), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pu, err := ParsePeerUp(tc.msg[CommonHeaderLen:])
			if err != nil {
				t.Fatal(err)
			}
			if pu.TableName != tc.want {
				t.Errorf("TableName %q, want %q", pu.TableName, tc.want)
			}
			if pu.LocalASN != 65000 {
				t.Errorf("LocalASN %d, want 65000", pu.LocalASN)
			}
		})
	}
}

// A Loc-RIB instance through the listener: its Peer Up registers a loc-rib
// peer with its table name, its routes are Loc-RIB routes of the zero peer
// address with the router's own AS as their local AS, and its Peer Down
// withdraws its Loc-RIB only.
func TestLocRIBSession(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _, _ := h.connectFrom(ctx, t, "127.0.0.11")
	router := netip.MustParseAddr("127.0.0.11")
	p := netip.MustParsePrefix("203.0.113.0/24")

	send(t, client, initiationMsg("lr-session.test"),
		// No VRF/Table Name TLV: the default Loc-RIB instance is named
		// "global" (RFC 9069 §5.2.1) even when the TLV is absent.
		locRIBPeerUp(0, 0, 65000, ""),
		locRIBRouteMonitoring(0, PeerFlagLocRIBFiltered, 65000, updateBody(false, false, nil, []pathNLRI{{0, p}}, nil)))
	ev := h.next(t)
	r := ev.Route
	if r == nil {
		t.Fatalf("got %+v, want a route", ev)
	}
	if r.RIBType != types.LocRIB || r.PeerType != PeerTypeLocRIB || r.PeerAddr != zeroAddr ||
		r.Router != router || r.PeerASN != 65000 || r.LocalASN != 65000 {
		t.Errorf("route: rib %s, peer type %d, peer %v, router %v, peer AS %d, local AS %d; "+
			"want loc-rib, 3, 0.0.0.0, %v, 65000, 65000",
			r.RIBType, r.PeerType, r.PeerAddr, r.Router, r.PeerASN, r.LocalASN, router)
	}
	peers := h.l.GetPeers()
	if len(peers) != 1 || peers[0].PeerType != PeerTypeLocRIB || peers[0].TableName != "global" ||
		peers[0].Addr != zeroAddr || peers[0].LocalASN != 65000 {
		t.Errorf("peers %+v, want the one Loc-RIB instance, table global, local AS 65000", peers)
	}
	waitPeerState(t, "lr-session.test", zeroAddr, "", 1)
	if !hasLogLine(h.logs.String(), `level=INFO`, `msg="BMP Loc-RIB registered"`, `peer_up=true`) {
		t.Errorf("no INFO log of the Loc-RIB registration from its Peer Up; logs:\n%s", h.logs)
	}

	send(t, client, locRIBPeerDown(0, 65000))
	ev = h.next(t)
	w := ev.Withdrawal
	if w == nil || !w.WithdrawAll || w.RIBType != types.LocRIB || w.Peer() != types.NewPeerRef(router, 0, zeroAddr) {
		t.Fatalf("after Peer Down: %+v, want a withdraw-all of the Loc-RIB of (%v, 0.0.0.0)", w, router)
	}
	waitPeerState(t, "lr-session.test", zeroAddr, "", 0)
}

// A BGP peer's Peer Down withdraws its Adj-RIBs, never a Loc-RIB.
func TestBGPPeerDownScope(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := h.connect(ctx, t)
	peer := netip.MustParseAddr("192.0.2.77")
	send(t, client, peerUpMsg(peer), bmpMsg(MsgTypePeerDown, append(perPeerHeader(peer), 2)))
	w := h.next(t).Withdrawal
	if w == nil || !w.WithdrawAll || w.RIBType == types.LocRIB {
		t.Fatalf("BGP Peer Down: %+v, want a withdraw-all of the peer's Adj-RIBs", w)
	}
}

// FRR 10.2 sends no Loc-RIB Peer Up. The Loc-RIB is registered from its first
// Route Monitoring with routes or withdrawals (not from an End-of-RIB alone),
// with the header's Peer AS as its local AS, and again after a Peer Down. Its
// raven_bmp_peer_state follows, and goes to 0 when the session ends.
func TestLocRIBRegisteredWithoutPeerUp(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _, done := h.connectFrom(ctx, t, "127.0.0.12")
	const sys = "lr-nopeerup.test"
	const rd = uint64(0x0000fde8_00000064) // 65000:100
	p := netip.MustParsePrefix("198.51.100.0/24")
	global := netip.MustParseAddr("192.0.2.12")
	locRIBs := func() (n int, up bool, localASN uint32) {
		for _, pr := range h.l.GetPeers() {
			if pr.PeerType == PeerTypeLocRIB {
				n++
				up, localASN = pr.State == "up", pr.LocalASN
			}
		}
		return
	}
	// locRIBPeer is the Loc-RIB instance with the given peer distinguisher,
	// nil if there is none.
	locRIBPeer := func(rd uint64) *Peer {
		for _, pr := range h.l.GetPeers() {
			if pr.PeerType == PeerTypeLocRIB && pr.Distinguisher == rd {
				return &pr
			}
		}
		return nil
	}

	// An End-of-RIB alone registers nothing. The global peer's route after
	// it orders the check.
	send(t, client, initiationMsg(sys), locRIBRouteMonitoring(rd, 0, 65000, endOfRIB),
		peerUpMsg(global), routeMonitoringMsg(global, p))
	if ev := h.next(t); ev.Route == nil || ev.Route.RIBType != types.AdjRIBInPre {
		t.Fatalf("got %+v, want the global peer's route", ev)
	}
	if n, _, _ := locRIBs(); n != 0 {
		t.Fatalf("%d Loc-RIB peers after an End-of-RIB alone, want none", n)
	}

	// Its first route registers it.
	send(t, client, locRIBRouteMonitoring(rd, 0, 65000, updateBody(false, false, nil, []pathNLRI{{0, p}}, nil)))
	if ev := h.next(t); ev.Route == nil || ev.Route.RIBType != types.LocRIB || ev.Route.LocalASN != 65000 {
		t.Fatalf("got %+v, want a Loc-RIB route with local AS 65000", ev)
	}
	if n, up, local := locRIBs(); n != 1 || !up || local != 65000 {
		t.Fatalf("Loc-RIB peers %d (up %v, local AS %d), want 1, up, 65000", n, up, local)
	}
	// A VRF instance registered without a Peer Up has no name: only the
	// default instance has one (RFC 9069 §5.2.1).
	pr := locRIBPeer(rd)
	if pr == nil {
		t.Fatal("the 65000:100 Loc-RIB is not registered")
	}
	if pr.TableName != "" {
		t.Errorf("Loc-RIB 65000:100 table name %q, want none", pr.TableName)
	}
	waitPeerState(t, sys, zeroAddr, "65000:100", 1)
	if !hasLogLine(h.logs.String(), `level=INFO`, `msg="BMP Loc-RIB registered"`, `peer_up=false`) {
		t.Errorf("no log of the registration; logs:\n%s", h.logs)
	}

	// Peer Down, then routes again: registered again.
	send(t, client, locRIBPeerDown(rd, 65000))
	if w := h.next(t).Withdrawal; w == nil || !w.WithdrawAll || w.RIBType != types.LocRIB {
		t.Fatalf("got %+v, want the Loc-RIB withdraw-all", w)
	}
	waitPeerState(t, sys, zeroAddr, "65000:100", 0)
	send(t, client, locRIBRouteMonitoring(rd, 0, 65000, updateBody(false, false, []pathNLRI{{0, p}}, nil, nil)))
	if ev := h.next(t); ev.Withdrawal == nil || ev.Withdrawal.RIBType != types.LocRIB {
		t.Fatalf("got %+v, want the Loc-RIB withdrawal", ev)
	}
	if n, up, _ := locRIBs(); n != 1 || !up {
		t.Fatalf("after routes following the Peer Down: %d Loc-RIB peers (up %v), want 1, up", n, up)
	}
	waitPeerState(t, sys, zeroAddr, "65000:100", 1)

	// The default instance, registered without a Peer Up as well, is named
	// "global" (RFC 9069 §5.2.1).
	send(t, client, locRIBRouteMonitoring(0, 0, 65000,
		updateBody(false, false, nil, []pathNLRI{{0, netip.MustParsePrefix("203.0.113.0/24")}}, nil)))
	if ev := h.next(t); ev.Route == nil || ev.Route.RIBType != types.LocRIB {
		t.Fatalf("got %+v, want a Loc-RIB route", ev)
	}
	pr = locRIBPeer(0)
	if pr == nil {
		t.Fatal("the default Loc-RIB is not registered")
	}
	if pr.TableName != "global" {
		t.Errorf("default Loc-RIB table name %q, want global", pr.TableName)
	}
	if !hasLogLine(h.logs.String(), `level=INFO`, `msg="BMP Loc-RIB registered"`, `peer_up=false`, `table_name=global`) {
		t.Errorf("no log of the default Loc-RIB registration with its name; logs:\n%s", h.logs)
	}
	waitPeerState(t, sys, zeroAddr, "", 1)

	// The session ends with no Peer Down: every peer's state goes to 0.
	client.Close()
	<-done
	for _, pk := range []struct {
		addr netip.Addr
		rd   string
	}{{zeroAddr, "65000:100"}, {zeroAddr, ""}, {global, ""}} {
		if v, ok := peerState(t, sys, pk.addr, pk.rd); !ok || v != 0 {
			t.Errorf("raven_bmp_peer_state{peer=%v, rd=%q} = %v (exists %v) after the session ended, want 0",
				pk.addr, pk.rd, v, ok)
		}
	}
	if peers := h.l.GetPeers(); len(peers) != 0 {
		t.Errorf("peers after the session ended: %+v, want none", peers)
	}
}

// VRF Loc-RIBs share the zero address; their Peer Distinguishers keep their
// peers and routes apart.
func TestVRFLocRIBsKeptApart(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := h.connect(ctx, t)
	const red = uint64(0x0002_0000_fde8_0001) // 65000L:1
	p := netip.MustParsePrefix("1.1.1.0/24")
	send(t, client,
		locRIBPeerUp(0, 0, 65000, "global"), locRIBPeerUp(red, 0, 65000, "red"),
		locRIBRouteMonitoring(0, 0, 65000, updateBody(false, false, nil, []pathNLRI{{0, p}}, nil)),
		locRIBRouteMonitoring(red, 0, 65000, updateBody(false, false, nil, []pathNLRI{{0, p}}, nil)))
	k1, k2 := h.next(t).Route.Key(), h.next(t).Route.Key()
	if k1 == k2 || k1.Peer.Distinguisher != 0 || k2.Peer.Distinguisher != red {
		t.Errorf("route keys %+v and %+v, want the global and the red Loc-RIB apart", k1, k2)
	}
	tables := map[string]bool{}
	for _, pr := range h.l.GetPeers() {
		tables[pr.TableName] = true
	}
	if len(tables) != 2 || !tables["global"] || !tables["red"] {
		t.Errorf("peers' tables %v, want global and red", tables)
	}
}

// A Loc-RIB route's local AS is its header's Peer AS (RFC 9069 §4.1), with
// no Peer Up, and is the RFC 6811 origin of an empty AS_PATH and of one
// holding only that AS, as FRR 10.2 sends a locally originated route. Inside
// a confederation such a path, like an empty one, has the confederation
// identifier as origin.
func TestLocRIBOriginLocalAS(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := h.connect(ctx, t)

	update := func(segs ...types.ASSegment) []byte {
		return rawUpdate(nil, cat(attrOriginIGP, asPathAttr(attrASPath, 4, segs...), attrNH), nlri1111...)
	}
	check := func(what string, wantOrigin uint32, wantSrc types.OriginSource) {
		t.Helper()
		r := h.nextRoute(t)
		if got, src := r.OriginAS(); r.RIBType != types.LocRIB || r.LocalASN != 65001 || got != wantOrigin || src != wantSrc {
			t.Errorf("%s: %s route, LocalASN %d, origin AS%d (source %d); want loc-rib, 65001, AS%d (source %d)",
				what, r.RIBType, r.LocalASN, got, src, wantOrigin, wantSrc)
		}
	}

	send(t, client,
		locRIBRouteMonitoring(0, 0, 65001, emptyPathUpdate),
		locRIBRouteMonitoring(0, 0, 65001, update(seq(65001))),
		locRIBRouteMonitoring(0, 0, 65001, update(seq(65001, 65001))),
		locRIBRouteMonitoring(0, 0, 65001, update(seq(65001, 64510, 64500))),
	)
	check("empty path", 65001, types.OriginLocalAS)
	check("[local AS]", 65001, types.OriginLocalAS)
	check("[local AS, prepended]", 65001, types.OriginLocalAS)
	check("leading local AS", 64500, types.OriginFromPath)

	// The router turns out to be confederation member AS65001 of AS64500.
	inside, outside := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	send(t, client,
		peerUpWithOpens(inside, 0, openMsg(65001), openMsg(65002)),
		peerUpWithOpens(outside, 0, openMsg(64500), openMsg(64999)),
		routeMonitoringRD(inside, 0, update(confed(65002))),
		locRIBRouteMonitoring(0, 0, 65001, update(seq(65001))),
		locRIBRouteMonitoring(0, 0, 65001, emptyPathUpdate),
	)
	if r := h.nextRoute(t); r.ConfedID != 64500 {
		t.Fatalf("confederation route: ConfedID %d, want 64500", r.ConfedID)
	}
	check("[local AS] inside the confederation", 64500, types.OriginLocalConfedID)
	check("empty path inside the confederation", 64500, types.OriginLocalConfedID)
}
