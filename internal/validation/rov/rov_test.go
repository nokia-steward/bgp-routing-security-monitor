package rov

import (
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

func TestROVValid(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidOriginMismatch(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	// Wrong origin ASN — hijack scenario
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 64666},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidMoreSpecific(t *testing.T) {
	s := store.NewVRPStore()
	// ROA says /24 max, but route is /25 — more-specific hijack
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/25"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid (more-specific), got %s: %s", result.State, result.Reason)
	}
}

func TestROVValidWithMaxLength(t *testing.T) {
	s := store.NewVRPStore()
	// ROA allows up to /28
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 28},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/25"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid (within maxLength), got %s: %s", result.State, result.Reason)
	}
}

func TestROVNotFound(t *testing.T) {
	s := store.NewVRPStore()
	// No VRPs at all
	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/8"),
		ASPath: []uint32{64501, 64502},
	}

	result := a.Validate(route)
	if result.State != types.ROVNotFound {
		t.Errorf("expected NotFound, got %s: %s", result.State, result.Reason)
	}
}

func TestROVValidIPv6(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:2121::/48"),
		ASPath: []uint32{65000, 2121},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid for IPv6 match, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidIPv6OriginMismatch(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	// Wrong origin ASN — IPv6 hijack scenario
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:2121::/48"),
		ASPath: []uint32{65000, 65001},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid for IPv6 origin mismatch, got %s: %s", result.State, result.Reason)
	}
}

func TestROVNotFoundIPv6(t *testing.T) {
	s := store.NewVRPStore()
	// VRPs for a different IPv6 prefix — should not cover this route
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:dead::/48"),
		ASPath: []uint32{65000, 65001},
	}

	result := a.Validate(route)
	if result.State != types.ROVNotFound {
		t.Errorf("expected NotFound for uncovered IPv6, got %s: %s", result.State, result.Reason)
	}
}

// TestROVMixedFamilies confirms IPv4 validation still works when the store
// contains both IPv4 and IPv6 VRPs. Regression check for the IPv6 rollout.
func TestROVMixedFamilies(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("2001:db8:6501::/48"), ASN: 65001, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)

	v4 := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 13335},
	}
	if got := a.Validate(v4); got.State != types.ROVValid {
		t.Errorf("IPv4 with IPv6 VRPs in store: expected Valid, got %s: %s", got.State, got.Reason)
	}

	v6 := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:6501::/48"),
		ASPath: []uint32{65000, 65001},
	}
	if got := a.Validate(v6); got.State != types.ROVValid {
		t.Errorf("IPv6 with IPv4 VRPs in store: expected Valid, got %s: %s", got.State, got.Reason)
	}
}

func TestROVMultipleVRPs(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64501, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	// Origin is 64501 — second VRP should match
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{3356, 64501},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid (second VRP matches), got %s: %s", result.State, result.Reason)
	}
}

// RFC 6811 §2: with an empty AS_PATH, or one whose final segment is
// AS_CONFED_SEQUENCE or AS_CONFED_SET, the origin is the BGP speaker's own
// AS, validated like any other. Inside a confederation that is its
// confederation identifier when known, since ROAs name it, else its member
// AS (LocalASN). With
// no local AS known the route is NotFound. RAVEN used to give all of these
// origin 0 and NotFound.
func TestROVLocalOrigin(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64500, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASN: 64511, MaxLength: 24},
	}, 1, 1)
	a := NewAnnotator(s)
	confedOnly := []types.ASSegment{{Type: types.ASSegmentConfedSequence, ASNs: []uint32{65001, 65002}}}
	confedSet := []types.ASSegment{{Type: types.ASSegmentConfedSet, ASNs: []uint32{65001, 65002}}}
	emptyNote := localOriginNotes[types.OriginLocalAS]
	emptyIDNote := localOriginNotes[types.OriginLocalConfedID]
	idNote := localOriginNotes[types.OriginConfedID]
	memberNote := localOriginNotes[types.OriginConfedMember]
	for _, tc := range []struct {
		name     string
		prefix   string
		raw      []types.ASSegment
		local    uint32
		confedID uint32
		state    types.ROVState
		reason   string
	}{
		{"empty path, ROA for the local AS", "198.51.100.0/24", nil, 64500, 0,
			types.ROVValid, "matches VRP {198.51.100.0/24, AS64500, /24}; " + emptyNote},
		{"empty path, ROA for another AS", "203.0.113.0/24", nil, 64500, 0,
			types.ROVInvalid, "origin AS64500 not authorized by any covering VRP; nearest VRP 203.0.113.0/24 AS64511 maxLength /24; " + emptyNote},
		{"empty path, no covering ROA", "192.0.2.0/24", nil, 64500, 0,
			types.ROVNotFound, "no covering VRPs found; " + emptyNote},
		{"empty path, local AS not known", "198.51.100.0/24", nil, 0, 0,
			types.ROVNotFound, localASUnknownReason},
		{"empty path inside a confederation, identifier known", "198.51.100.0/24", nil, 65001, 64500,
			types.ROVValid, "matches VRP {198.51.100.0/24, AS64500, /24}; " + emptyIDNote},
		{"empty path inside a confederation, ROA for another AS", "203.0.113.0/24", nil, 65001, 64500,
			types.ROVInvalid, "origin AS64500 not authorized by any covering VRP; nearest VRP 203.0.113.0/24 AS64511 maxLength /24; " + emptyIDNote},
		{"empty path inside a confederation, identifier not known: member AS", "198.51.100.0/24", nil, 65001, 0,
			types.ROVInvalid, "origin AS65001 not authorized by any covering VRP; nearest VRP 198.51.100.0/24 AS64500 maxLength /24; " + emptyNote},
		{"confederation, identifier known", "198.51.100.0/24", confedOnly, 65001, 64500,
			types.ROVValid, "matches VRP {198.51.100.0/24, AS64500, /24}; " + idNote},
		{"AS_CONFED_SET, identifier known", "198.51.100.0/24", confedSet, 65001, 64500,
			types.ROVValid, "matches VRP {198.51.100.0/24, AS64500, /24}; " + idNote},
		{"confederation, identifier not known: member AS", "198.51.100.0/24", confedOnly, 65001, 0,
			types.ROVInvalid, "origin AS65001 not authorized by any covering VRP; nearest VRP 198.51.100.0/24 AS64500 maxLength /24; " + memberNote},
		{"confederation, member AS has the ROA", "198.51.100.0/24", confedOnly, 64500, 0,
			types.ROVValid, "matches VRP {198.51.100.0/24, AS64500, /24}; " + memberNote},
		{"confederation, no local AS known", "198.51.100.0/24", confedOnly, 0, 0,
			types.ROVNotFound, localASUnknownReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := &types.Route{Prefix: netip.MustParsePrefix(tc.prefix), ASPathRaw: tc.raw,
				LocalASN: tc.local, ConfedID: tc.confedID}
			for _, seg := range tc.raw {
				route.ASPath = append(route.ASPath, seg.ASNs...)
			}
			got := a.Validate(route)
			if got.State != tc.state || got.Reason != tc.reason {
				t.Errorf("got %s %q, want %s %q", got.State, got.Reason, tc.state, tc.reason)
			}
		})
	}
}

// Confederation segments ahead of a final AS_SEQUENCE do not change the
// origin: the sequence's last AS, not the router's own AS.
func TestROVConfederationThenSequence(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64500, MaxLength: 24},
	}, 1, 1)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{65001, 64510, 64500},
		ASPathRaw: []types.ASSegment{
			{Type: types.ASSegmentConfedSequence, ASNs: []uint32{65001}},
			{Type: types.ASSegmentSequence, ASNs: []uint32{64510, 64500}},
		},
		LocalASN: 65001,
		ConfedID: 64999,
	}
	if got := NewAnnotator(s).Validate(route); got.State != types.ROVValid || got.Reason != "matches VRP {198.51.100.0/24, AS64500, /24}" {
		t.Errorf("got %s (%s), want Valid for origin AS64500 with no local-origin note", got.State, got.Reason)
	}
}

// RFC 6811 §2: after a final AS_SET the origin is NONE, which no VRP
// matches. Covered, the route is Invalid even if a VRP names a set member
// (RAVEN used to take the last member as origin, which made this Valid);
// uncovered, it is NotFound. Each says why.
func TestROVASSetOriginIsNone(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64511, MaxLength: 24},
	}, 1, 1)
	a := NewAnnotator(s)
	route := func(prefix string) *types.Route {
		return &types.Route{
			Prefix: netip.MustParsePrefix(prefix),
			ASPath: []uint32{64501, 64510, 64511},
			ASPathRaw: []types.ASSegment{
				{Type: types.ASSegmentSequence, ASNs: []uint32{64501}},
				{Type: types.ASSegmentSet, ASNs: []uint32{64510, 64511}},
			},
		}
	}
	covered := a.Validate(route("198.51.100.0/24"))
	if covered.State != types.ROVInvalid || covered.Reason != noneOriginInvalidReason || len(covered.MatchedVRPs) != 1 {
		t.Errorf("covered: %s (%s) %d VRPs, want Invalid: %s", covered.State, covered.Reason, len(covered.MatchedVRPs), noneOriginInvalidReason)
	}
	uncovered := a.Validate(route("203.0.113.0/24"))
	if uncovered.State != types.ROVNotFound || uncovered.Reason != noneOriginNotFoundReason {
		t.Errorf("uncovered: %s (%s), want NotFound: %s", uncovered.State, uncovered.Reason, noneOriginNotFoundReason)
	}
}
