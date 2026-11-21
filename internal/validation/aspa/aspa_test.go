package aspa

import (
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Section references are to draft-ietf-sidrops-aspa-verification-24.
// AS_PATHs are written as on the wire: [neighbor, ..., origin].
func TestValidateProcedure(t *testing.T) {
	tests := []struct {
		name     string
		aspas    map[uint32][]uint32 // customer → providers
		path     []uint32
		localASN uint32
		proc     types.ASPAProcedure
		want     types.ASPAState
		wantFail *[2]uint32 // failing hop {customer, provider}, nil if none
	}{
		{
			// §5.3: no hops, so max_up_ramp = min_up_ramp = N = 1; §5.4 step 6.
			// The neighbor→verifier edge is not part of COMPRESSED_AS_PATH
			// (§5.1), so LocalASN must not turn this into Unknown.
			name:     "upstream N=1 origin has no ASPA",
			path:     []uint32{13335},
			localASN: 64500,
			proc:     types.ASPAUpstream,
			want:     types.ASPAValid,
		},
		{
			// §5.3/§5.4: as above; the origin's own ASPA is never consulted
			// when there is no next AS, even if it omits the verifier.
			name:     "upstream N=1 origin has ASPA",
			aspas:    map[uint32][]uint32{64501: {64509}},
			path:     []uint32{64501},
			localASN: 64500,
			proc:     types.ASPAUpstream,
			want:     types.ASPAValid,
		},
		{
			// §5.3/§5.5: N=1, all ramps = 1, 1+1 >= 1 → Valid.
			name: "downstream N=1 no ASPA",
			path: []uint32{13335},
			proc: types.ASPADownstream,
			want: types.ASPAValid,
		},
		{
			// §5.3/§5.5: min_up_ramp = 1 (AS(1)→AS(2) No Attestation),
			// min_down_ramp = N-J+1 = 1 (AS(2)→AS(1) No Attestation);
			// 1+1 >= 2 → Valid.
			name: "downstream N=2 no ASPA",
			path: []uint32{174, 13335},
			proc: types.ASPADownstream,
			want: types.ASPAValid,
		},
		{
			// §5.3/§5.4: authorized(AS(1), AS(2)) = No Attestation, so
			// min_up_ramp = 1 < N=2 → Unknown (step 5).
			name: "upstream N=2 origin has no ASPA",
			path: []uint32{174, 13335},
			proc: types.ASPAUpstream,
			want: types.ASPAUnknown,
		},
		{
			// §5.3/§5.4: authorized(AS(1), AS(2)) = Not Provider+, so
			// max_up_ramp = 1 < N=2 → Invalid (step 4).
			name:     "upstream N=2 origin ASPA excludes next AS",
			aspas:    map[uint32][]uint32{13335: {3356}},
			path:     []uint32{174, 13335},
			proc:     types.ASPAUpstream,
			want:     types.ASPAInvalid,
			wantFail: &[2]uint32{13335, 174},
		},
		{
			// §5.1: COMPRESSED_AS_PATH holds unique ASNs, so prepends collapse
			// to N=1 → Valid as in the N=1 case.
			name:     "upstream prepended single AS is N=1",
			path:     []uint32{13335, 13335, 13335},
			localASN: 64500,
			proc:     types.ASPAUpstream,
			want:     types.ASPAValid,
		},
		{
			// §5.1: prepends collapse to [174 13335], N=2; the prepend must
			// not create a 13335→13335 hop.
			name:  "upstream prepended origin collapses to N=2",
			aspas: map[uint32][]uint32{13335: {174}},
			path:  []uint32{174, 13335, 13335, 13335},
			proc:  types.ASPAUpstream,
			want:  types.ASPAValid,
		},
		{
			// Lab demo scenario (lab/demo-master.sh, 145.102.136.0/22): AS1199
			// declares AS1103 only, edge sees [65000 1199]. §5.4 step 4:
			// authorized(1199, 65000) = Not Provider+, max_up_ramp = 1 < 2.
			name:     "upstream lab leak AS1199 via AS65000",
			aspas:    map[uint32][]uint32{1199: {1103}},
			path:     []uint32{65000, 1199},
			localASN: 65001,
			proc:     types.ASPAUpstream,
			want:     types.ASPAInvalid,
			wantFail: &[2]uint32{1199, 65000},
		},
		{
			// lab/02-route-leak.sh: AS64496 declares AS3333 only, route
			// arrives via AS65000. §5.4 step 4 as above.
			name:     "upstream lab leak AS64496 via AS65000",
			aspas:    map[uint32][]uint32{64496: {3333}},
			path:     []uint32{65000, 64496},
			proc:     types.ASPAUpstream,
			want:     types.ASPAInvalid,
			wantFail: &[2]uint32{64496, 65000},
		},
		{
			// §5.3/§5.4: every hop Provider+ → max = min = N → Valid.
			name:  "upstream N=3 fully attested",
			aspas: map[uint32][]uint32{64502: {64501}, 64501: {64509}},
			path:  []uint32{64509, 64501, 64502},
			proc:  types.ASPAUpstream,
			want:  types.ASPAValid,
		},
		{
			// §5.3/§5.5: valley-free up then down. Up: 64502→64501 Provider+,
			// 64501→64509 Not Provider+ (max_up_ramp = min_up_ramp = 2).
			// Down: 64510→64509 Provider+, 64509→64501 No Attestation
			// (min_down_ramp = 4-3+1 = 2), 64501→64502 Not Provider+
			// (max_down_ramp = 4-2+1 = 3). 2+3 >= 4 and 2+2 >= 4 → Valid.
			name: "downstream N=4 up then down",
			aspas: map[uint32][]uint32{
				64502: {64501},
				64501: {64999},
				64510: {64509},
			},
			path: []uint32{64510, 64509, 64501, 64502},
			proc: types.ASPADownstream,
			want: types.ASPAValid,
		},
		{
			// §5.3/§5.5 step 4: valley. Up ramp stops at AS(1)
			// (64502 does not list 64501, max_up_ramp = 1); down ramp stops at
			// AS(3) (64510 does not list 64509, max_down_ramp = 4-4+1 = 1).
			// 1+1 < 4 → Invalid.
			name: "downstream N=4 valley",
			aspas: map[uint32][]uint32{
				64502: {64999},
				64510: {64999},
			},
			path:     []uint32{64510, 64509, 64501, 64502},
			proc:     types.ASPADownstream,
			want:     types.ASPAInvalid,
			wantFail: &[2]uint32{64502, 64501},
		},
		{
			// §5.3/§5.4: from the origin, 13335→7738 and 7738→53072 are No
			// Attestation; AS53072's ASPA omits AS262504, so
			// authorized(53072, 262504) is Not Provider+ and max_up_ramp =
			// 3 < N=5 → Invalid. The failing hop is customer 53072 (the AS
			// whose ASPA was checked) → provider 262504 (the next AS).
			name:     "upstream route leak at AS53072",
			aspas:    map[uint32][]uint32{53072: {16735, 23106, 270735}},
			path:     []uint32{1031, 262504, 53072, 7738, 13335},
			proc:     types.ASPAUpstream,
			want:     types.ASPAInvalid,
			wantFail: &[2]uint32{53072, 262504},
		},
		{
			// AS_SET: RAVEN reports Unverifiable (the draft §5.4 step 3 says
			// Invalid; RAVEN keeps these separate).
			name: "upstream AS_SET unverifiable",
			path: []uint32{174, 13335},
			proc: types.ASPAUpstream,
			want: types.ASPAUnverifiable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aspaStore := store.NewASPAStore()
			for c, ps := range tt.aspas {
				for _, p := range ps {
					aspaStore.AddProvider(c, p)
				}
			}
			route := &types.Route{ASPath: tt.path, LocalASN: tt.localASN}
			if tt.want == types.ASPAUnverifiable {
				route.ASPathRaw = []types.ASSegment{{Type: types.ASSegmentSet}}
			}

			got := NewAnnotator(aspaStore).ValidateProcedure(route, tt.proc)

			if got.State != tt.want {
				t.Fatalf("state = %s, want %s (hops %+v)", got.State, tt.want, got.HopDetails)
			}
			if got.Procedure != tt.proc {
				t.Errorf("procedure = %d, want %d", got.Procedure, tt.proc)
			}
			if tt.wantFail == nil {
				if got.FailingHop != nil {
					t.Errorf("unexpected failing hop %+v", got.FailingHop)
				}
				return
			}
			f := got.FailingHop
			if f == nil || f.CustomerASN != tt.wantFail[0] || f.ProviderASN != tt.wantFail[1] ||
				f.Authorization != types.HopNotAuthorized {
				t.Errorf("failing hop = %+v, want customer=%d provider=%d NotAuthorized",
					f, tt.wantFail[0], tt.wantFail[1])
			}
		})
	}
}

// TestValidate_IsUpstream checks Validate keeps running the upstream
// procedure (§5.4): [174 13335] with no ASPA is Unknown upstream but Valid
// downstream.
func TestValidate_IsUpstream(t *testing.T) {
	got := NewAnnotator(store.NewASPAStore()).Validate(&types.Route{ASPath: []uint32{174, 13335}})
	if got.State != types.ASPAUnknown || got.Procedure != types.ASPAUpstream {
		t.Fatalf("got state=%s procedure=%d, want Unknown upstream", got.State, got.Procedure)
	}
}

// TestValidate_NeighborToVerifierEdgeNotChecked replaces the old
// path[0]-vs-LocalASN test. The draft never evaluates the edge from AS(N) to
// the verifying AS (§5.1), so a leaker that lists other providers is not
// caught by its own ASPA alone; [64509 64501 64502] with only 64509's ASPA is
// Unknown (min_up_ramp = 1 < 3).
func TestValidate_NeighborToVerifierEdgeNotChecked(t *testing.T) {
	aspaStore := store.NewASPAStore()
	aspaStore.AddProvider(64509, 64510)

	got := NewAnnotator(aspaStore).Validate(&types.Route{
		ASPath:   []uint32{64509, 64501, 64502},
		LocalASN: 64500,
	})
	if got.State != types.ASPAUnknown || got.FailingHop != nil {
		t.Fatalf("got state=%s failing=%+v, want Unknown with no failing hop", got.State, got.FailingHop)
	}
}

// A route with AS_CONFED_SEQUENCE or AS_CONFED_SET segments came over a
// session inside the router's AS confederation (RFC 5065 §4.1 (c), §5),
// where §6.2 does not recommend verification; the draft defines no handling
// of the segments themselves. So it is Unverifiable with ConfedReason, not
// verified with member ASes as hops, under either procedure and before the
// neighbor-AS check.
func TestConfederationNotVerified(t *testing.T) {
	aspaStore := store.NewASPAStore()
	aspaStore.AddProvider(13335, 64509) // 64500 not a provider of 13335: Invalid if verified
	route := &types.Route{
		PeerASN: 65002,
		ASPath:  []uint32{65001, 64500, 13335},
		ASPathRaw: []types.ASSegment{
			{Type: types.ASSegmentConfedSequence, ASNs: []uint32{65001}},
			{Type: types.ASSegmentSequence, ASNs: []uint32{64500, 13335}},
		},
	}
	a := NewAnnotator(aspaStore)
	for _, proc := range []types.ASPAProcedure{types.ASPAUpstream, types.ASPADownstream} {
		got := a.ValidateProcedure(route, proc)
		if got.State != types.ASPAUnverifiable || got.Reason != ConfedReason || got.Procedure != proc || got.HopDetails != nil {
			t.Errorf("%s: %+v, want Unverifiable with the confederation reason", proc, got)
		}
		got = a.ValidateSelection(route, Selection{Procedure: proc, NeighborCheck: true})
		if got.State != types.ASPAUnverifiable || got.Reason != ConfedReason {
			t.Errorf("%s with neighbor check: %+v, want Unverifiable with the confederation reason", proc, got)
		}
	}
	route.ASPathRaw[0].Type = types.ASSegmentConfedSet
	if got := a.Validate(route); got.State != types.ASPAUnverifiable {
		t.Errorf("AS_CONFED_SET: %s, want Unverifiable", got.State)
	}

	// Without the confederation segment the same path verifies (Invalid).
	route.ASPath = []uint32{64500, 13335}
	route.ASPathRaw = route.ASPathRaw[1:]
	if got := a.Validate(route); got.State != types.ASPAInvalid {
		t.Errorf("without confederation: %s, want Invalid", got.State)
	}
}

// A route with an empty AS_PATH is not verified, as before (Unknown), and the
// Reason says why: it is locally originated or iBGP-learned without an
// AS_PATH. The neighbor-AS check does not apply to it either.
func TestEmptyPathNotVerified(t *testing.T) {
	a := NewAnnotator(store.NewASPAStore())
	route := &types.Route{PeerASN: 64501, LocalASN: 64500}
	for _, proc := range []types.ASPAProcedure{types.ASPAUpstream, types.ASPADownstream} {
		got := a.ValidateSelection(route, Selection{Procedure: proc, NeighborCheck: true})
		if got.State != types.ASPAUnknown || got.Reason != EmptyPathReason || got.Procedure != proc {
			t.Errorf("%s: %s (%q), want Unknown with %q", proc, got.State, got.Reason, EmptyPathReason)
		}
	}
}
