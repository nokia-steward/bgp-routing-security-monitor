package validation

import (
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// An RTR delta that changes why a route has its ROV state updates the
// stored reason code, whether or not the state changes with it. The route
// table keeps only the code: a stale one would mislabel the route in every
// listing and what-if until the next full revalidation.
func TestIncremental_ReasonCodeFollowsVRPDelta(t *testing.T) {
	f := newIncFixture(t)
	short := vrp("94.177.129.0/24", 24, 202744)
	f.vrps.ReplaceAll([]types.VRP{short, vrp("198.51.100.0/24", 24, 64511)}, 1, 1)

	// The production case: Invalid for its length, not its origin.
	prod := f.add("192.0.2.1", "94.177.129.126/32", 6939, 202744)
	// Invalid for its origin until a VRP for its own AS appears.
	other := f.add("192.0.2.1", "198.51.100.0/25", 6939, 64500)
	check := func(step string, k types.RouteKey, state types.ROVState, code types.ROVReasonCode, reason string) {
		t.Helper()
		r := f.get(k).ROV
		if r.State != state || r.Code != code || r.Reason != reason {
			t.Errorf("%s: %s %s %q, want %s %s %q", step, r.State, r.Code, r.Reason, state, code, reason)
		}
	}
	check("before", prod, types.ROVInvalid, types.ROVReasonInvalidLength,
		"prefix length /32 exceeds maxLength /24 of VRP 94.177.129.0/24 AS202744")
	check("before", other, types.ROVInvalid, types.ROVReasonInvalidOrigin,
		"origin AS64500 not authorized by any covering VRP; nearest VRP 198.51.100.0/24 AS64511 maxLength /24")

	// The holder raises maxLength to /32 (a withdrawal and an announcement,
	// as RTR sends a maxLength change), and authorizes AS64500 at /24 only.
	long := vrp("94.177.129.0/24", 32, 202744)
	own := vrp("198.51.100.0/24", 24, 64500)
	f.vrps.RemoveVRP(short)
	f.vrps.AddVRP(long)
	f.vrps.AddVRP(own)
	f.vrps.RebuildIndex()
	rv := f.run(&store.Delta{VRPAnnounced: []types.VRP{long, own}, VRPWithdrawn: []types.VRP{short}})
	if rv.Changed != 2 {
		t.Errorf("pass changed %d routes, want 2", rv.Changed)
	}
	check("after", prod, types.ROVValid, types.ROVReasonValid, "matches VRP {94.177.129.0/24, AS202744, /32}")
	// Still Invalid, now for its length: its own AS has a VRP.
	check("after", other, types.ROVInvalid, types.ROVReasonInvalidLength,
		"prefix length /25 exceeds maxLength /24 of VRP 198.51.100.0/24 AS64500")
	if p := f.get(other).SecurityPosture; p != types.PostureOriginInvalid {
		t.Errorf("posture %s, want %s: the code must not change the posture", p, types.PostureOriginInvalid)
	}
}
