package audit

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// An audit covers one RIB: a route the router reports pre- and post-policy is
// counted once. Peer rows are per router, instance and address. A Loc-RIB,
// whose peer address is zero, is audited by its router's address.
func TestAnalyzeOneRIB(t *testing.T) {
	router := netip.MustParseAddr("192.0.2.100")
	mk := func(rib types.RIBType, peer string, rd uint64, prefix string) *types.Route {
		r := makeRoute("10.0.0.1", peer, 65001, prefix, []uint32{65001}, types.ROVValid, types.ASPAValid)
		r.Router, r.RIBType, r.PeerDistinguisher = router, rib, rd
		return r
	}
	routes := []*types.Route{
		mk(types.AdjRIBInPre, "192.0.2.1", 0, "1.0.0.0/24"),
		mk(types.AdjRIBInPost, "192.0.2.1", 0, "1.0.0.0/24"),
		mk(types.AdjRIBInPre, "192.0.2.1", 0x0000fde8_00000001, "2.0.0.0/24"),
		mk(types.AdjRIBInPre, "192.0.2.1", 0x0002_0000_fde8_0001, "3.0.0.0/24"),
		mk(types.LocRIB, "0.0.0.0", 0, "1.0.0.0/24"),
		mk(types.LocRIB, "0.0.0.0", 0, "2.0.0.0/24"),
	}

	pre := Analyze("192.0.2.1", types.AdjRIBInPre, routes)
	if pre.RIB != "adj-rib-in-pre" || pre.TotalRoutes != 3 || len(pre.Peers) != 3 {
		t.Fatalf("adj-rib-in-pre audit: rib %q, %d routes, %d peer rows; want adj-rib-in-pre, 3, 3", pre.RIB, pre.TotalRoutes, len(pre.Peers))
	}
	rds := map[string]bool{}
	for _, p := range pre.Peers {
		rds[p.PeerDistinguisher] = true
		if p.Router != router.String() {
			t.Errorf("peer row router %q, want %s", p.Router, router)
		}
	}
	if !rds[""] || !rds["65000:1"] || !rds["65000L:1"] {
		t.Errorf("peer rows' distinguishers %v, want \"\", 65000:1 and 65000L:1 apart", rds)
	}

	if post := Analyze("192.0.2.1", types.AdjRIBInPost, routes); post.TotalRoutes != 1 || post.RIB != "adj-rib-in-post" {
		t.Errorf("adj-rib-in-post audit: %d routes (rib %q), want 1", post.TotalRoutes, post.RIB)
	}

	loc := Analyze(router.String(), types.LocRIB, routes)
	if loc.TotalRoutes != 2 || len(loc.Peers) != 1 {
		t.Fatalf("Loc-RIB audit by router address: %d routes, %d peer rows; want 2, 1", loc.TotalRoutes, len(loc.Peers))
	}
	if got := Analyze("0.0.0.0", types.LocRIB, routes); got.TotalRoutes != 0 {
		t.Errorf("Loc-RIB audit by the zero address: %d routes, want 0 (matched by router)", got.TotalRoutes)
	}
	if !strings.Contains(FormatTable(loc), "loc-rib of "+router.String()) || !strings.Contains(FormatTable(loc), "RIB:           loc-rib") {
		t.Errorf("Loc-RIB audit table:\n%s", FormatTable(loc))
	}
	if !strings.Contains(FormatTable(pre), "192.0.2.1 rd 65000L:1") || !strings.Contains(FormatMarkdown(pre), "| RIB | adj-rib-in-pre |") {
		t.Errorf("pre-policy audit output:\n%s\n%s", FormatTable(pre), FormatMarkdown(pre))
	}
}

// Addresses are compared with IPv4-mapped forms unmapped, as the API filter
// does: a Loc-RIB route whose router is ::ffff:192.0.2.3, and a peer route
// from ::ffff:192.0.2.1, are found by the plain IPv4 address.
func TestAnalyzeUnmapsAddresses(t *testing.T) {
	peer := makeRoute("10.0.0.1", "::ffff:192.0.2.1", 65001, "1.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAValid)
	peer.RIBType = types.AdjRIBInPre
	loc := makeRoute("10.0.0.1", "0.0.0.0", 65001, "1.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAValid)
	loc.Router, loc.PeerType, loc.RIBType = netip.MustParseAddr("::ffff:192.0.2.3"), types.PeerTypeLocRIB, types.LocRIB
	routes := []*types.Route{peer, loc}

	if got := Analyze("192.0.2.1", types.AdjRIBInPre, routes); got.TotalRoutes != 1 {
		t.Errorf("adj-rib-in-pre audit of 192.0.2.1: %d routes, want 1 (peer ::ffff:192.0.2.1)", got.TotalRoutes)
	}
	if got := Analyze("192.0.2.3", types.LocRIB, routes); got.TotalRoutes != 1 {
		t.Errorf("Loc-RIB audit of 192.0.2.3: %d routes, want 1 (router ::ffff:192.0.2.3)", got.TotalRoutes)
	}
}
