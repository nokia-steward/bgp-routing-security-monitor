package routetable

import (
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

var (
	keyRouterA = netip.MustParseAddr("192.0.2.1")
	keyPeer    = netip.MustParseAddr("80.81.194.180")
	keyPrefix  = netip.MustParsePrefix("1.1.1.0/24")
)

func keyedRoute(router netip.Addr, rd uint64, pathID uint32, rib types.RIBType) *types.Route {
	return &types.Route{
		Router: router, PeerDistinguisher: rd, PeerAddr: keyPeer, Prefix: keyPrefix,
		PathID: pathID, RIBType: rib, ASPath: []uint32{64500, 13335}, OwnerSession: 1,
	}
}

// The same peer address in two VRFs of one router (different Peer
// Distinguishers) is two peers: both routes are kept and counted apart.
func TestVRFPeersKeptApart(t *testing.T) {
	tbl := New()
	global := keyedRoute(keyRouterA, 0, 0, types.AdjRIBInPre)
	vrf := keyedRoute(keyRouterA, 0x0000fde8_00000064, 0, types.AdjRIBInPre)
	tbl.Insert(global)
	tbl.Insert(vrf)
	if tbl.Get(global.Key()) != global || tbl.Get(vrf.Key()) != vrf || tbl.Count() != 2 {
		t.Fatalf("table holds %d routes; global kept %v, VRF kept %v", tbl.Count(),
			tbl.Get(global.Key()) == global, tbl.Get(vrf.Key()) == vrf)
	}
	counts := tbl.PeerRouteCounts()
	if counts[global.Peer()][types.AdjRIBInPre] != 1 || counts[vrf.Peer()][types.AdjRIBInPre] != 1 {
		t.Errorf("counts %v, want 1 per instance", counts)
	}
	if n := len(tbl.GetByPrefix(keyPrefix)); n != 2 {
		t.Errorf("prefix index lists %d routes, want 2", n)
	}
}

// ADD-PATH: two paths to one prefix from one peer are two routes; withdrawing
// one leaves the other.
func TestAddPathPathsKeptApart(t *testing.T) {
	tbl := New()
	p1 := keyedRoute(keyRouterA, 0, 1, types.AdjRIBInPre)
	p2 := keyedRoute(keyRouterA, 0, 2, types.AdjRIBInPre)
	tbl.Insert(p1)
	tbl.Insert(p2)
	if tbl.Count() != 2 || tbl.PeerRouteCounts()[p1.Peer()][types.AdjRIBInPre] != 2 {
		t.Fatalf("table holds %d routes, peer count %d; want both paths", tbl.Count(), tbl.PeerRouteCounts()[p1.Peer()][types.AdjRIBInPre])
	}
	if !tbl.WithdrawFromSession(p1.Key(), 1) {
		t.Fatal("withdrawing path 1 removed nothing")
	}
	if tbl.Get(p2.Key()) != p2 || tbl.Get(p1.Key()) != nil || tbl.PeerRouteCounts()[p1.Peer()][types.AdjRIBInPre] != 1 {
		t.Errorf("after withdrawing path 1: path 2 kept %v, path 1 gone %v, count %d",
			tbl.Get(p2.Key()) == p2, tbl.Get(p1.Key()) == nil, tbl.PeerRouteCounts()[p1.Peer()][types.AdjRIBInPre])
	}
}

// A withdrawal removes only its own RIB's route: a post-policy withdrawal
// (inbound policy now rejects the route) leaves the pre-policy route the
// peer still announces. It used to remove both.
func TestWithdrawalIsPerRIB(t *testing.T) {
	tbl := New()
	pre := keyedRoute(keyRouterA, 0, 0, types.AdjRIBInPre)
	post := keyedRoute(keyRouterA, 0, 0, types.AdjRIBInPost)
	tbl.Insert(pre)
	tbl.Insert(post)
	tbl.WithdrawFromSession(post.Key(), 1)
	if tbl.Get(pre.Key()) != pre || tbl.Get(post.Key()) != nil {
		t.Errorf("post-policy withdrawal: pre kept %v, post removed %v", tbl.Get(pre.Key()) == pre, tbl.Get(post.Key()) == nil)
	}
}

// A peer-down on router A takes A's routes, owned or restored from a
// snapshot, and none of router B's for the same peer address.
func TestDetachPeerStaysOnItsRouter(t *testing.T) {
	routerB := netip.MustParseAddr("192.0.2.2")
	tbl := New()
	aOwned := keyedRoute(keyRouterA, 0, 0, types.AdjRIBInPre)
	aStale := keyedRoute(keyRouterA, 0, 0, types.AdjRIBInPost)
	aStale.OwnerSession = 0
	bOwned := keyedRoute(routerB, 0, 0, types.AdjRIBInPre)
	bOwned.OwnerSession = 2
	bStale := keyedRoute(routerB, 0, 0, types.AdjRIBInPost)
	bStale.OwnerSession = 0
	for _, r := range []*types.Route{aOwned, aStale, bOwned, bStale} {
		tbl.Insert(r)
	}
	if n := tbl.WithdrawAllFromPeer(aOwned.Peer(), 1, types.AdjRIBInPre); n != 2 {
		t.Errorf("peer-down on router A removed %d routes, want 2 (A's owned and restored)", n)
	}
	if tbl.Get(bOwned.Key()) != bOwned || tbl.Get(bStale.Key()) != bStale {
		t.Error("peer-down on router A removed router B's routes")
	}
	checkPeerCounts(t, tbl, "after peer-down on A")
}
