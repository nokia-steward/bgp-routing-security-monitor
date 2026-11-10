package rov

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

func v(prefix string, maxLen uint8, asn uint32) types.VRP {
	return types.VRP{Prefix: netip.MustParsePrefix(prefix), MaxLength: maxLen, ASN: asn}
}

// Every reason code, IPv4 and IPv6, with the reason naming the VRP that
// decided it, and Explain splitting the covering VRPs as Routinator does.
//
// The production report: 94.177.129.126/32 from AS202744 under VRP
// 94.177.129.0/24-24 AS202744 is Invalid because of its length, and RAVEN
// called it "origin AS202744 not authorized by any covering VRP", as it did
// 11,520 of 11,524 Invalid routes in a full table.
func TestROVReasonCodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		vrps   []types.VRP
		prefix string
		path   []uint32 // nil with set: AS_SET origin
		set    bool
		state  types.ROVState
		code   types.ROVReasonCode
		reason string
		vrp    string // deciding VRP, FormatVRP; "" for none
		// Explain's split
		matched, unAS, unLen []types.VRP
	}{
		{name: "production: /32 under its own AS's /24-24 is invalid_length",
			vrps:   []types.VRP{v("94.177.129.0/24", 24, 202744)},
			prefix: "94.177.129.126/32", path: []uint32{6939, 202744},
			state: types.ROVInvalid, code: types.ROVReasonInvalidLength,
			reason: "prefix length /32 exceeds maxLength /24 of VRP 94.177.129.0/24 AS202744",
			vrp:    "94.177.129.0/24-24 AS202744",
			unLen:  []types.VRP{v("94.177.129.0/24", 24, 202744)}},
		{name: "v6 invalid_length",
			vrps:   []types.VRP{v("2001:db8:100::/48", 48, 64500)},
			prefix: "2001:db8:100:1::/64", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidLength,
			reason: "prefix length /64 exceeds maxLength /48 of VRP 2001:db8:100::/48 AS64500",
			vrp:    "2001:db8:100::/48-48 AS64500",
			unLen:  []types.VRP{v("2001:db8:100::/48", 48, 64500)}},
		{name: "v4 valid",
			vrps:   []types.VRP{v("198.51.100.0/24", 24, 13335)},
			prefix: "198.51.100.0/24", path: []uint32{64501, 13335},
			state: types.ROVValid, code: types.ROVReasonValid,
			reason: "matches VRP {198.51.100.0/24, AS13335, /24}", vrp: "198.51.100.0/24-24 AS13335",
			matched: []types.VRP{v("198.51.100.0/24", 24, 13335)}},
		{name: "v6 valid within maxLength",
			vrps:   []types.VRP{v("2001:db8::/32", 48, 64500)},
			prefix: "2001:db8:1::/48", path: []uint32{64496, 64500},
			state: types.ROVValid, code: types.ROVReasonValid,
			reason: "matches VRP {2001:db8::/32, AS64500, /48}", vrp: "2001:db8::/32-48 AS64500",
			matched: []types.VRP{v("2001:db8::/32", 48, 64500)}},
		{name: "v4 not_found",
			vrps:   []types.VRP{v("198.51.100.0/24", 24, 13335)},
			prefix: "203.0.113.0/24", path: []uint32{64501, 13335},
			state: types.ROVNotFound, code: types.ROVReasonNotFound, reason: "no covering VRPs found"},
		{name: "v6 not_found",
			vrps:   []types.VRP{v("2001:db8::/32", 48, 64500)},
			prefix: "2001:db9::/32", path: []uint32{64496, 64500},
			state: types.ROVNotFound, code: types.ROVReasonNotFound, reason: "no covering VRPs found"},
		{name: "v4 invalid_origin",
			vrps:   []types.VRP{v("198.51.100.0/24", 24, 13335)},
			prefix: "198.51.100.0/24", path: []uint32{64501, 64666},
			state: types.ROVInvalid, code: types.ROVReasonInvalidOrigin,
			reason: "origin AS64666 not authorized by any covering VRP; nearest VRP 198.51.100.0/24 AS13335 maxLength /24",
			vrp:    "198.51.100.0/24-24 AS13335",
			unAS:   []types.VRP{v("198.51.100.0/24", 24, 13335)}},
		{name: "v6 invalid_origin names the most specific VRP",
			vrps:   []types.VRP{v("2001:db8::/32", 48, 64501), v("2001:db8:2121::/48", 48, 2121)},
			prefix: "2001:db8:2121::/48", path: []uint32{64496, 64666},
			state: types.ROVInvalid, code: types.ROVReasonInvalidOrigin,
			reason: "origin AS64666 not authorized by any covering VRP; nearest VRP 2001:db8:2121::/48 AS2121 maxLength /48",
			vrp:    "2001:db8:2121::/48-48 AS2121",
			unAS:   []types.VRP{v("2001:db8::/32", 48, 64501), v("2001:db8:2121::/48", 48, 2121)}},
		{name: "length and origin mismatch both apply: invalid_length",
			vrps:   []types.VRP{v("198.51.100.0/22", 23, 64500), v("198.51.100.0/24", 25, 64511)},
			prefix: "198.51.100.0/25", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidLength,
			reason: "prefix length /25 exceeds maxLength /23 of VRP 198.51.100.0/22 AS64500",
			vrp:    "198.51.100.0/22-23 AS64500",
			unAS:   []types.VRP{v("198.51.100.0/24", 25, 64511)},
			unLen:  []types.VRP{v("198.51.100.0/22", 23, 64500)}},
		{name: "v6 length and origin mismatch both apply: invalid_length",
			vrps:   []types.VRP{v("2001:db8::/32", 32, 64500), v("2001:db8::/32", 48, 64511)},
			prefix: "2001:db8:5::/48", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidLength,
			reason: "prefix length /48 exceeds maxLength /32 of VRP 2001:db8::/32 AS64500",
			vrp:    "2001:db8::/32-32 AS64500",
			unAS:   []types.VRP{v("2001:db8::/32", 48, 64511)},
			unLen:  []types.VRP{v("2001:db8::/32", 32, 64500)}},
		{name: "invalid_length names the origin's longest maxLength",
			vrps:   []types.VRP{v("10.0.0.0/8", 16, 64500), v("10.1.0.0/16", 20, 64500), v("10.1.0.0/16", 18, 64500)},
			prefix: "10.1.2.0/24", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidLength,
			reason: "prefix length /24 exceeds maxLength /20 of VRP 10.1.0.0/16 AS64500",
			vrp:    "10.1.0.0/16-20 AS64500",
			unLen:  []types.VRP{v("10.0.0.0/8", 16, 64500), v("10.1.0.0/16", 20, 64500), v("10.1.0.0/16", 18, 64500)}},
		{name: "v4 all AS0: invalid_as0",
			vrps:   []types.VRP{v("192.0.2.0/23", 24, 0), v("192.0.2.0/24", 24, 0)},
			prefix: "192.0.2.0/24", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidAS0,
			reason: "every covering VRP is AS0 (RFC 6483 §4); nearest VRP 192.0.2.0/24 AS0 maxLength /24",
			vrp:    "192.0.2.0/24-24 AS0",
			unAS:   []types.VRP{v("192.0.2.0/23", 24, 0), v("192.0.2.0/24", 24, 0)}},
		{name: "v6 all AS0: invalid_as0",
			vrps:   []types.VRP{v("2001:db8::/32", 128, 0)},
			prefix: "2001:db8::/48", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidAS0,
			reason: "every covering VRP is AS0 (RFC 6483 §4); nearest VRP 2001:db8::/32 AS0 maxLength /128",
			vrp:    "2001:db8::/32-128 AS0",
			unAS:   []types.VRP{v("2001:db8::/32", 128, 0)}},
		{name: "v4 AS0 plus another AS: invalid_origin, naming the other AS",
			vrps:   []types.VRP{v("192.0.2.0/23", 24, 64511), v("192.0.2.0/24", 24, 0)},
			prefix: "192.0.2.0/24", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidOrigin,
			reason: "origin AS64500 not authorized by any covering VRP; nearest VRP 192.0.2.0/23 AS64511 maxLength /24",
			vrp:    "192.0.2.0/23-24 AS64511",
			unAS:   []types.VRP{v("192.0.2.0/23", 24, 64511), v("192.0.2.0/24", 24, 0)}},
		{name: "v6 AS0 plus another AS: invalid_origin",
			vrps:   []types.VRP{v("2001:db8::/32", 48, 0), v("2001:db8::/32", 48, 64511)},
			prefix: "2001:db8:7::/48", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidOrigin,
			reason: "origin AS64500 not authorized by any covering VRP; nearest VRP 2001:db8::/32 AS64511 maxLength /48",
			vrp:    "2001:db8::/32-48 AS64511",
			unAS:   []types.VRP{v("2001:db8::/32", 48, 0), v("2001:db8::/32", 48, 64511)}},
		{name: "AS0 plus the origin's VRP: valid",
			vrps:   []types.VRP{v("192.0.2.0/24", 24, 0), v("192.0.2.0/24", 24, 64500)},
			prefix: "192.0.2.0/24", path: []uint32{64496, 64500},
			state: types.ROVValid, code: types.ROVReasonValid,
			reason: "matches VRP {192.0.2.0/24, AS64500, /24}", vrp: "192.0.2.0/24-24 AS64500",
			matched: []types.VRP{v("192.0.2.0/24", 24, 64500)},
			unAS:    []types.VRP{v("192.0.2.0/24", 24, 0)}},
		{name: "AS0 plus the origin's VRP too short: invalid_length",
			vrps:   []types.VRP{v("192.0.2.0/24", 24, 0), v("192.0.2.0/24", 24, 64500)},
			prefix: "192.0.2.128/25", path: []uint32{64496, 64500},
			state: types.ROVInvalid, code: types.ROVReasonInvalidLength,
			reason: "prefix length /25 exceeds maxLength /24 of VRP 192.0.2.0/24 AS64500",
			vrp:    "192.0.2.0/24-24 AS64500",
			unAS:   []types.VRP{v("192.0.2.0/24", 24, 0)},
			unLen:  []types.VRP{v("192.0.2.0/24", 24, 64500)}},
		{name: "valid and length mismatch for the same AS: valid",
			vrps:   []types.VRP{v("10.0.0.0/8", 8, 64500), v("10.1.0.0/16", 24, 64500)},
			prefix: "10.1.2.0/24", path: []uint32{64496, 64500},
			state: types.ROVValid, code: types.ROVReasonValid,
			reason: "matches VRP {10.1.0.0/16, AS64500, /24}", vrp: "10.1.0.0/16-24 AS64500",
			matched: []types.VRP{v("10.1.0.0/16", 24, 64500)},
			unLen:   []types.VRP{v("10.0.0.0/8", 8, 64500)}},
		{name: "v4 AS_SET origin, covered: invalid_as_set",
			vrps:   []types.VRP{v("198.51.100.0/24", 24, 64511)},
			prefix: "198.51.100.0/24", set: true,
			state: types.ROVInvalid, code: types.ROVReasonInvalidASSet,
			reason: noneOriginInvalidReason, vrp: "198.51.100.0/24-24 AS64511",
			unAS: []types.VRP{v("198.51.100.0/24", 24, 64511)}},
		{name: "v6 AS_SET origin, covered: invalid_as_set",
			vrps:   []types.VRP{v("2001:db8::/32", 48, 64511)},
			prefix: "2001:db8::/48", set: true,
			state: types.ROVInvalid, code: types.ROVReasonInvalidASSet,
			reason: noneOriginInvalidReason, vrp: "2001:db8::/32-48 AS64511",
			unAS: []types.VRP{v("2001:db8::/32", 48, 64511)}},
		{name: "AS_SET origin under AS0: invalid_as_set, AS0 not matched by origin NONE",
			vrps:   []types.VRP{v("198.51.100.0/24", 32, 0)},
			prefix: "198.51.100.0/24", set: true,
			state: types.ROVInvalid, code: types.ROVReasonInvalidASSet,
			reason: noneOriginInvalidReason, vrp: "198.51.100.0/24-32 AS0",
			unAS: []types.VRP{v("198.51.100.0/24", 32, 0)}},
		{name: "AS_SET origin, not covered: not_found",
			vrps:   []types.VRP{v("198.51.100.0/24", 24, 64511)},
			prefix: "203.0.113.0/24", set: true,
			state: types.ROVNotFound, code: types.ROVReasonNotFound, reason: noneOriginNotFoundReason},
		{name: "local AS not known, covered: not_found with every VRP unmatched",
			vrps:   []types.VRP{v("198.51.100.0/24", 24, 64511)},
			prefix: "198.51.100.0/24",
			state:  types.ROVNotFound, code: types.ROVReasonNotFound, reason: localASUnknownReason,
			unAS: []types.VRP{v("198.51.100.0/24", 24, 64511)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := store.NewVRPStore()
			s.ReplaceAll(slices.Clone(tc.vrps), 1, 1)
			a := NewAnnotator(s)
			route := &types.Route{Prefix: netip.MustParsePrefix(tc.prefix), ASPath: tc.path}
			if tc.set {
				route.ASPath = []uint32{64501, 64510, 64511}
				route.ASPathRaw = []types.ASSegment{
					{Type: types.ASSegmentSequence, ASNs: []uint32{64501}},
					{Type: types.ASSegmentSet, ASNs: []uint32{64510, 64511}},
				}
			}
			got := a.Validate(route)
			if got.State != tc.state || got.Code != tc.code || got.Reason != tc.reason {
				t.Errorf("Validate: %s %s %q\n                 want %s %s %q", got.State, got.Code, got.Reason, tc.state, tc.code, tc.reason)
			}
			e := a.Explain(route)
			vrp := ""
			if e.HasDeciding {
				vrp = FormatVRP(e.Deciding)
			}
			if e.Code != tc.code || vrp != tc.vrp {
				t.Errorf("Explain: %s, deciding %q; want %s, %q", e.Code, vrp, tc.code, tc.vrp)
			}
			if !slices.Equal(e.Matched, tc.matched) || !slices.Equal(e.UnmatchedAS, tc.unAS) || !slices.Equal(e.UnmatchedLength, tc.unLen) {
				t.Errorf("Explain split:\n got  matched %v unmatched_as %v unmatched_length %v\n want matched %v unmatched_as %v unmatched_length %v",
					e.Matched, e.UnmatchedAS, e.UnmatchedLength, tc.matched, tc.unAS, tc.unLen)
			}
		})
	}
}

func TestROVReasonCodeNames(t *testing.T) {
	want := map[types.ROVReasonCode]string{
		types.ROVReasonUnknown: "", types.ROVReasonValid: "valid", types.ROVReasonNotFound: "not_found",
		types.ROVReasonInvalidLength: "invalid_length", types.ROVReasonInvalidOrigin: "invalid_origin",
		types.ROVReasonInvalidAS0: "invalid_as0", types.ROVReasonInvalidASSet: "invalid_as_set",
	}
	for c, name := range want {
		if c.String() != name {
			t.Errorf("code %d: %q, want %q", c, c.String(), name)
		}
	}
	if len(types.ROVReasonCodes) != len(want)-1 {
		t.Errorf("ROVReasonCodes has %d codes, want %d", len(types.ROVReasonCodes), len(want)-1)
	}
}
