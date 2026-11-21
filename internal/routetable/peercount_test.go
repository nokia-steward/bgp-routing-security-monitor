package routetable

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// checkPeerCounts asserts the per-peer counts are exactly the table's routes
// grouped by peer (router, distinguisher, address), and sum to the table's
// total.
func checkPeerCounts(t *testing.T, tbl *Table, step string) {
	t.Helper()
	actual := map[types.PeerRef]types.RIBCounts{}
	var byRIB types.RIBCounts
	for _, r := range tbl.All() {
		c := actual[r.Peer()]
		c[r.RIBType]++
		actual[r.Peer()] = c
		byRIB[r.RIBType]++
	}
	got := tbl.PeerRouteCounts()
	var sum uint64
	for p, c := range got {
		for _, n := range c {
			sum += n
		}
		if actual[p] != c {
			t.Fatalf("%s: peer %+v counted %v, holds %v", step, p, c, actual[p])
		}
	}
	for p, c := range actual {
		if got[p] != c {
			t.Fatalf("%s: peer %+v holds %v, counted %v", step, p, c, got[p])
		}
	}
	if total := tbl.Count(); sum != total {
		t.Fatalf("%s: per-peer counts sum to %d, table holds %d", step, sum, total)
	}
	if got := tbl.CountByRIB(); got != byRIB {
		t.Fatalf("%s: CountByRIB %v, table holds %v", step, got, byRIB)
	}
}

// Property: two routers reporting the same peer addresses (one also in a
// VRF), with ADD-PATH paths, through random announcements, re-announcements,
// withdrawals, peer-downs, session supersedes, snapshot restores and stale
// evictions, applied whole or a step at a time: each peer's count is the
// number of its routes in the table, per router.
func TestPeerRouteCountsInvariant(t *testing.T) {
	routerA, routerB := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	addrs := []netip.Addr{
		netip.MustParseAddr("80.81.194.180"), // the route servers both routers peer with
		netip.MustParseAddr("80.81.195.180"),
		netip.MustParseAddr("::ffff:206.82.106.254"), // stored mapped
		netip.MustParseAddr("2001:7f8::1"),
	}
	var peers []types.PeerRef
	for _, r := range []netip.Addr{routerA, routerB} {
		for _, a := range addrs {
			peers = append(peers, types.PeerRef{Router: r, Addr: a})
		}
	}
	peers = append(peers, types.PeerRef{Router: routerA, Distinguisher: 0x0000fde8_00000064, Addr: addrs[0]}) // a VRF
	for seed := uint64(1); seed <= 30; seed++ {
		rng := rand.New(rand.NewPCG(seed, 3))
		tbl := New()
		session := map[netip.Addr]uint64{routerA: 1, routerB: 2} // each router's current BMP session
		prefix := func() netip.Prefix {
			return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(rng.IntN(30)), 0}), 24)
		}
		route := func(p types.PeerRef, owner uint64, stale bool) *types.Route {
			return &types.Route{
				Router: p.Router, PeerDistinguisher: p.Distinguisher, PeerAddr: p.Addr,
				Prefix: prefix(), PathID: uint32(rng.IntN(3)),
				ASPath:  []uint32{64500, uint32(64501 + rng.IntN(3))},
				RIBType: types.AdjRIBInPre, OwnerSession: owner, Stale: stale,
			}
		}
		apply := func(rm *Removal) {
			if rng.IntN(2) == 0 {
				rm.Apply()
				return
			}
			for {
				_, done := rm.Step(1 + rng.IntN(5))
				checkPeerCounts(t, tbl, "mid-removal")
				if done {
					return
				}
			}
		}
		for step := 0; step < 400; step++ {
			p := peers[rng.IntN(len(peers))]
			var op string
			switch r := rng.IntN(20); {
			case r < 9:
				op = "announce or re-announce"
				tbl.Insert(route(p, session[p.Router], false))
			case r < 13:
				op = "withdraw"
				rt := route(p, 0, false)
				tbl.WithdrawFromSession(rt.Key(), session[p.Router])
			case r < 14:
				op = "peer down"
				apply(tbl.DetachPeer(p, session[p.Router], types.AdjRIBInPre))
			case r < 16:
				// A new BMP session from the router supersedes the old one,
				// re-announces some routes, then the old one ends.
				op = "session supersede"
				old := session[p.Router]
				session[p.Router] = old + 100
				for n := rng.IntN(10); n > 0; n-- {
					q := peers[rng.IntN(len(peers))]
					if q.Router == p.Router {
						tbl.Insert(route(q, session[p.Router], false))
					}
				}
				apply(tbl.DetachSession(old))
			case r < 18:
				op = "snapshot restore (stale)"
				tbl.Insert(route(p, 0, true))
			default:
				op = "stale eviction"
				apply(tbl.DetachUnowned())
			}
			checkPeerCounts(t, tbl, op)
		}
	}
}
