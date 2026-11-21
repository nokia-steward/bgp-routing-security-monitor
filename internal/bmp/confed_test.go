package bmp

import (
	"context"
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// A router inside a confederation sends its member AS in OPENs to peers in
// the confederation and its confederation identifier to peers outside it.
// inferConfedID takes the one local AS, other than the member AS, of the
// instance's up eBGP sessions; none or several is unknown (0).
func TestInferConfedID(t *testing.T) {
	r1, r2 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	inst := instanceKey{router: r1}
	type sess struct {
		router        netip.Addr
		rd            uint64
		local, remote uint32
		down          bool
	}
	const member, confedID = 65001, 64500
	for _, tc := range []struct {
		name string
		sess []sess
		want uint32
	}{
		{"border router: member AS inside, identifier outside",
			[]sess{{r1, 0, member, 65002, false}, {r1, 0, member, member, false}, {r1, 0, confedID, 64999, false}}, confedID},
		{"several external sessions agree",
			[]sess{{r1, 0, member, 65002, false}, {r1, 0, confedID, 64999, false}, {r1, 0, confedID, 64998, false}}, confedID},
		{"interior router: no session leaves the confederation",
			[]sess{{r1, 0, member, 65002, false}, {r1, 0, member, member, false}}, 0},
		{"two other local ASes: ambiguous",
			[]sess{{r1, 0, member, 65002, false}, {r1, 0, confedID, 64999, false}, {r1, 0, 64600, 64998, false}}, 0},
		{"external session down",
			[]sess{{r1, 0, member, 65002, false}, {r1, 0, confedID, 64999, true}}, 0},
		{"iBGP session with another local AS is not external",
			[]sess{{r1, 0, member, 65002, false}, {r1, 0, 64600, 64600, false}}, 0},
		{"local AS not known on a session",
			[]sess{{r1, 0, member, 65002, false}, {r1, 0, 0, 64999, false}}, 0},
		{"another router's or instance's sessions do not count",
			[]sess{{r1, 0, member, 65002, false}, {r2, 0, confedID, 64999, false}, {r1, 7, confedID, 64999, false}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peers := map[PeerKey]*Peer{}
			for i, s := range tc.sess {
				state := "up"
				if s.down {
					state = "down"
				}
				addr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
				peers[PeerKey{RouterAddr: s.router, Distinguisher: s.rd, PeerAddr: addr}] = &Peer{
					Router: s.router, Distinguisher: s.rd, Addr: addr, ASN: s.remote, LocalASN: s.local, State: state,
				}
			}
			if got := inferConfedID(peers, inst, member); got != tc.want {
				t.Errorf("inferConfedID = %d, want %d", got, tc.want)
			}
		})
	}
}

// emptyPathUpdate is an UPDATE for 9.9.9.0/24 with an empty AS_PATH.
var emptyPathUpdate = rawUpdate(nil, cat(attrOriginIGP, []byte{0x40, attrASPath, 0}, attrNH), nlri9999...)

// nextRoute returns the next route h's listener emits.
func (h *sessionHarness) nextRoute(t *testing.T) *types.Route {
	t.Helper()
	for {
		if ev := h.next(t); ev.Route != nil {
			return ev.Route
		}
	}
}

// Routes with confederation segments or an empty AS_PATH carry the
// router's confederation identifier, inferred from its Peer Ups, so their
// origin (RFC 6811 §2) is the AS ROAs name. An empty path carries it only
// once a route with confederation segments has shown the router is in a
// confederation. When the session that showed the identifier goes down the
// cached identifier is dropped and the origin falls back to the member AS.
// Other routes carry none.
func TestRoutesCarryConfedID(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := h.connect(ctx, t)

	inside, outside := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	confedPath := rawUpdate(nil, cat(attrOriginIGP, asPathAttr(attrASPath, 4, confed(65002)), attrNH), nlri1111...)
	plainPath := rawUpdate(nil, cat(attrOriginIGP, asPathAttr(attrASPath, 4, seq(65002, 13335)), attrNH), nlri8888...)
	check := func(what string, wantID, wantOrigin uint32) {
		t.Helper()
		if r := h.nextRoute(t); r.ConfedID != wantID || r.LocalASN != 65001 || r.OriginASN() != wantOrigin {
			t.Errorf("%s: ConfedID %d LocalASN %d origin AS%d, want %d, 65001, AS%d",
				what, r.ConfedID, r.LocalASN, r.OriginASN(), wantID, wantOrigin)
		}
	}

	send(t, client,
		peerUpWithOpens(inside, 0, openMsg(65001), openMsg(65002)),
		peerUpWithOpens(outside, 0, openMsg(64500), openMsg(64999)),
		routeMonitoringRD(inside, 0, emptyPathUpdate),
		routeMonitoringRD(inside, 0, confedPath),
		routeMonitoringRD(inside, 0, plainPath),
		routeMonitoringRD(inside, 0, emptyPathUpdate),
	)
	check("empty path before any confederation route", 0, 65001)
	check("confederation route", 64500, 64500)
	check("plain route", 0, 13335)
	check("empty path inside the confederation", 64500, 64500)

	send(t, client,
		bmpMsg(MsgTypePeerDown, append(perPeerHeader(outside), 2)),
		routeMonitoringRD(inside, 0, confedPath),
		routeMonitoringRD(inside, 0, emptyPathUpdate),
	)
	check("confederation route after the external peer went down", 0, 65001)
	check("empty path after the external peer went down", 0, 65001)
}

// A router outside any confederation with a local AS override on one
// session has two local ASes, as a confederation border router does. With
// no route showing confederation segments, an empty AS_PATH keeps its
// session's local AS as origin, not the override.
func TestEmptyPathOutsideConfederation(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := h.connect(ctx, t)

	ibgp, override := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	send(t, client,
		peerUpWithOpens(ibgp, 0, openMsg(64500), openMsg(64500)),
		peerUpWithOpens(override, 0, openMsg(64600), openMsg(64999)),
		routeMonitoringRD(ibgp, 0, emptyPathUpdate),
	)
	if r := h.nextRoute(t); r.ConfedID != 0 || r.OriginASN() != 64500 {
		t.Errorf("ConfedID %d origin AS%d, want 0 and the local AS64500", r.ConfedID, r.OriginASN())
	}
}
