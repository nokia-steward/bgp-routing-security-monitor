package whatif

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// ribFixture is one router reporting one Invalid prefix from BGP peer
// 192.0.2.9 pre- and post-policy, from its local-instance peer 135.92.55.33
// (its own address, AS38016's br1.nyc) post-policy only, and in its
// Loc-RIB.
func ribFixture() (*Simulator, netip.Addr, netip.Addr) {
	router := netip.MustParseAddr("192.0.2.1")
	bgp := netip.MustParseAddr("192.0.2.9")
	local := netip.MustParseAddr("135.92.55.33")
	p := netip.MustParsePrefix("203.0.113.0/24")
	invalid := types.ROVResult{State: types.ROVInvalid, Code: types.ROVReasonInvalidOrigin}
	table := routetable.New()
	add := func(peer netip.Addr, peerType uint8, rib types.RIBType) {
		table.Insert(&types.Route{Router: router, PeerAddr: peer, PeerType: peerType, PeerASN: 64501, Prefix: p,
			ASPath: []uint32{64501, 64666}, RIBType: rib, ROV: invalid,
			SecurityPosture: types.PosturePathSuspect})
	}
	add(bgp, types.PeerTypeGlobal, types.AdjRIBInPre)
	add(bgp, types.PeerTypeGlobal, types.AdjRIBInPost)
	add(local, types.PeerTypeLocal, types.AdjRIBInPost)
	add(netip.IPv4Unspecified(), types.PeerTypeLocRIB, types.LocRIB)
	return NewSimulator(table), bgp, local
}

// what-if runs on adj-rib-in-pre unless --rib says otherwise, and its result
// says which RIBs it covered. Post-policy routes are counted only when asked
// for; all counts a route once per RIB it is reported in.
func TestSimulationRIBs(t *testing.T) {
	s, bgp, local := ribFixture()
	for _, tc := range []struct {
		rib        string
		total      int
		ribs       []string
		peerTotals map[string]int
	}{
		{"", 1, []string{"adj-rib-in-pre"}, map[string]int{bgp.String(): 1}},
		{"adj-rib-in-pre", 1, []string{"adj-rib-in-pre"}, map[string]int{bgp.String(): 1}},
		{"post-policy", 2, []string{"adj-rib-in-post"}, map[string]int{bgp.String(): 1, local.String(): 1}},
		{"loc-rib", 1, []string{"loc-rib"}, map[string]int{"0.0.0.0": 1}},
		{"all", 4, []string{"adj-rib-in-pre", "adj-rib-in-post", "loc-rib"},
			map[string]int{bgp.String(): 2, local.String(): 1, "0.0.0.0": 1}},
	} {
		ribs, err := ParseRIBs(tc.rib)
		if err != nil {
			t.Fatalf("ParseRIBs(%q): %v", tc.rib, err)
		}
		res, err := s.SimulateRejectInvalid(context.Background(), &Options{RIBs: ribs})
		if err != nil {
			t.Fatal(err)
		}
		peers := map[string]int{}
		for _, p := range res.ByPeer {
			peers[p.PeerAddr] = p.Total
		}
		if res.TotalRoutes != tc.total || res.RejectedRoutes != tc.total || !slices.Equal(res.RIBs, tc.ribs) || len(peers) != len(tc.peerTotals) {
			t.Errorf("--rib %q: total %d rejected %d ribs %v peers %v, want %d, %d, %v, %v",
				tc.rib, res.TotalRoutes, res.RejectedRoutes, res.RIBs, peers, tc.total, tc.total, tc.ribs, tc.peerTotals)
		}
		for p, n := range tc.peerTotals {
			if peers[p] != n {
				t.Errorf("--rib %q: peer %s total %d, want %d", tc.rib, p, peers[p], n)
			}
		}
		aspa, err := s.SimulateASPAEnforce(context.Background(), &Options{RIBs: ribs})
		if err != nil {
			t.Fatal(err)
		}
		if aspa.TotalRoutes != tc.total || aspa.RejectedRoutes != tc.total || !slices.Equal(aspa.RIBs, tc.ribs) {
			t.Errorf("--rib %q aspa-enforce: total %d rejected %d ribs %v, want %d, %d, %v",
				tc.rib, aspa.TotalRoutes, aspa.RejectedRoutes, aspa.RIBs, tc.total, tc.total, tc.ribs)
		}
	}
	// With no options at all (the API before --rib), still pre-policy.
	res, err := s.SimulateRejectInvalid(context.Background(), nil)
	if err != nil || res.TotalRoutes != 1 || !slices.Equal(res.RIBs, []string{"adj-rib-in-pre"}) {
		t.Errorf("nil options: %+v %v, want adj-rib-in-pre, 1 route", res, err)
	}
}

// what-if is about import policy: Adj-RIB-Out is refused, as is a typo.
func TestParseRIBsRefusesOutbound(t *testing.T) {
	for _, bad := range []string{"adj-rib-out-pre", "adj-rib-in-pre,adj-rib-out-post", "everything"} {
		if _, err := ParseRIBs(bad); err == nil {
			t.Errorf("ParseRIBs(%q): no error", bad)
		}
	}
	if s, err := ParseRIBs("pre-policy, loc-rib"); err != nil || s != types.RIBSetOf(types.AdjRIBInPre, types.LocRIB) {
		t.Errorf("ParseRIBs list: %v %v", s, err)
	}
}
