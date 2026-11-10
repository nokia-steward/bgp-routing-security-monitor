package whatif

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// What an import policy would drop is a pre-policy question: a prefix the
// router reports both pre-policy and in its Loc-RIB is one route received,
// counted once, and the Loc-RIB instance is not a peer.
func TestSimulationsCountPrePolicyOnly(t *testing.T) {
	router := netip.MustParseAddr("192.0.2.1")
	bgp := netip.MustParseAddr("192.0.2.9")
	p := netip.MustParsePrefix("203.0.113.0/24")
	invalid := types.ROVResult{State: types.ROVInvalid, Reason: "origin AS mismatch"}
	table := routetable.New()
	table.Insert(&types.Route{Router: router, PeerAddr: bgp, PeerASN: 64501, Prefix: p,
		ASPath: []uint32{64501, 64666}, RIBType: types.AdjRIBInPre, ROV: invalid,
		SecurityPosture: types.PostureOriginInvalid})
	table.Insert(&types.Route{Router: router, PeerType: types.PeerTypeLocRIB, PeerAddr: netip.IPv4Unspecified(),
		PeerASN: 65000, LocalASN: 65000, Prefix: p, ASPath: []uint32{64501, 64666}, RIBType: types.LocRIB,
		ROV: invalid, SecurityPosture: types.PostureOriginInvalid})
	s := NewSimulator(table)

	res, err := s.SimulateRejectInvalid(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalRoutes != 1 || res.RejectedRoutes != 1 {
		t.Errorf("reject-invalid: total %d, rejected %d, want 1 and 1", res.TotalRoutes, res.RejectedRoutes)
	}
	if len(res.ByPeer) != 1 || res.ByPeer[0].PeerAddr != bgp.String() {
		t.Errorf("reject-invalid: by peer %+v, want %s only", res.ByPeer, bgp)
	}
	if len(res.RejectedRouteList) != 1 || res.RejectedRouteList[0].RIBType != types.AdjRIBInPre {
		t.Errorf("reject-invalid: rejected list %+v, want the adj-rib-in-pre route only", res.RejectedRouteList)
	}

	aspa, err := s.SimulateASPAEnforce(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if aspa.TotalRoutes != 1 {
		t.Errorf("aspa-enforce: total %d, want 1", aspa.TotalRoutes)
	}
}

// reject-invalid breaks its rejections down by ROV reason code, routes and
// distinct prefixes, counts the rejected routes carrying BLACKHOLE (RFC
// 7999), and gives each top origin the reason of its most common code.
// Every Invalid used to show the reason of whichever route came first, and
// that reason was "not authorized" even for length mismatches.
func TestRejectInvalidReasonAndBlackholeBreakdown(t *testing.T) {
	table := routetable.New()
	router := netip.MustParseAddr("192.0.2.1")
	add := func(peer, prefix string, origin uint32, rov types.ROVResult, comms ...types.Community) {
		state := types.PostureOriginInvalid
		if rov.State != types.ROVInvalid {
			state = types.PostureOriginOnly
		}
		table.Insert(&types.Route{Router: router, PeerAddr: netip.MustParseAddr(peer), PeerASN: 64501,
			Prefix: netip.MustParsePrefix(prefix), ASPath: []uint32{64501, origin}, RIBType: types.AdjRIBInPre,
			ROV: rov, SecurityPosture: state, Communities: comms})
	}
	length := func(p string) types.ROVResult {
		return types.ROVResult{State: types.ROVInvalid, Code: types.ROVReasonInvalidLength,
			Reason: "prefix length /32 exceeds maxLength /24 of VRP " + p + " AS202744"}
	}
	origin := types.ROVResult{State: types.ROVInvalid, Code: types.ROVReasonInvalidOrigin,
		Reason: "origin AS202744 not authorized by any covering VRP; nearest VRP 94.177.0.0/16 AS64511 maxLength /24"}
	as0 := types.ROVResult{State: types.ROVInvalid, Code: types.ROVReasonInvalidAS0,
		Reason: "every covering VRP is AS0 (RFC 6483 §4); nearest VRP 192.0.2.0/24 AS0 maxLength /24"}
	bh := types.CommunityBlackhole

	// AS202744: an origin mismatch first, then three length mismatches on
	// two prefixes, two of them blackholed, one prefix from two peers.
	add("192.0.2.10", "94.177.200.0/24", 202744, origin)
	add("192.0.2.10", "94.177.129.126/32", 202744, length("94.177.129.0/24"), bh)
	add("192.0.2.11", "94.177.129.126/32", 202744, length("94.177.129.0/24"), bh, types.Community{High: 6695, Low: 1})
	add("192.0.2.10", "94.177.129.127/32", 202744, length("94.177.129.0/24"))
	add("192.0.2.10", "192.0.2.0/24", 64666, as0)
	// Not rejected, though blackholed.
	add("192.0.2.10", "198.51.100.1/32", 64500, types.ROVResult{State: types.ROVValid, Code: types.ROVReasonValid}, bh)

	res, err := NewSimulator(table).SimulateRejectInvalid(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalRoutes != 6 || res.RejectedRoutes != 5 || res.AffectedPrefixes != 4 {
		t.Errorf("total %d rejected %d prefixes %d, want 6, 5, 4", res.TotalRoutes, res.RejectedRoutes, res.AffectedPrefixes)
	}
	want := []ReasonImpact{
		{ReasonCode: "invalid_length", RouteCount: 3, PrefixCount: 2},
		{ReasonCode: "invalid_origin", RouteCount: 1, PrefixCount: 1},
		{ReasonCode: "invalid_as0", RouteCount: 1, PrefixCount: 1},
	}
	if !slices.Equal(res.ByReason, want) {
		t.Errorf("by reason %+v, want %+v", res.ByReason, want)
	}
	if res.BlackholeRoutes != 2 || res.BlackholePrefixes != 1 {
		t.Errorf("blackhole %d routes %d prefixes, want 2 and 1", res.BlackholeRoutes, res.BlackholePrefixes)
	}
	if len(res.TopOrigins) != 2 {
		t.Fatalf("top origins %+v", res.TopOrigins)
	}
	top := res.TopOrigins[0]
	if top.OriginASN != 202744 || top.RouteCount != 4 || top.PrefixCount != 3 || top.ReasonCode != "invalid_length" ||
		top.Reason != length("94.177.129.0/24").Reason ||
		top.ReasonCodes["invalid_length"] != 3 || top.ReasonCodes["invalid_origin"] != 1 {
		t.Errorf("top origin %+v", top)
	}
	if got := top.ReasonSummary(); got != "invalid_length (3), invalid_origin (1)" {
		t.Errorf("REASON column %q", got)
	}
	if got := res.TopOrigins[1].ReasonSummary(); res.TopOrigins[1].OriginASN != 64666 || got != "invalid_as0" {
		t.Errorf("second origin AS%d REASON %q, want AS64666 invalid_as0", res.TopOrigins[1].OriginASN, got)
	}
}

// An Invalid route restored from a snapshot has no reason code until it is
// revalidated; it counts as unknown rather than vanishing from the
// breakdown.
func TestRejectInvalidUnknownReason(t *testing.T) {
	table := routetable.New()
	table.Insert(&types.Route{PeerAddr: netip.MustParseAddr("192.0.2.10"), Prefix: netip.MustParsePrefix("203.0.113.0/24"),
		ASPath: []uint32{64501, 64666}, RIBType: types.AdjRIBInPre, ROV: types.ROVResult{State: types.ROVInvalid},
		SecurityPosture: types.PostureOriginInvalid, Stale: true})
	res, err := NewSimulator(table).SimulateRejectInvalid(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.ByReason, []ReasonImpact{{ReasonCode: "unknown", RouteCount: 1, PrefixCount: 1}}) ||
		res.TopOrigins[0].ReasonSummary() != "unknown" {
		t.Errorf("by reason %+v, top %+v", res.ByReason, res.TopOrigins)
	}
}
