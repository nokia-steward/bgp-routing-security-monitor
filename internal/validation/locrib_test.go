package validation

import (
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/validation/aspa"
)

// Loc-RIB ASPA fixture. The router is AS65000 (L); it learned [N O] from its
// neighbor N = AS64510, its provider; O = AS64500 lists only AS64999 as its
// provider. Verified downstream (§5.5) the path is Valid: the hop O→N is not
// provider+, but N (no ASPA) may have learned it from its customer O. Verified
// upstream (§5.4) it is Invalid: max_up_ramp 1 < 2. So the state shows which
// procedure ran.
const (
	locL = 65000
	locN = 64510
	locO = 64500
)

func locRIBEngine(t *testing.T, peers []config.ASPAPeer) *Engine {
	t.Helper()
	aspas := store.NewASPAStore()
	aspas.AddProvider(locO, 64999)
	sel := aspa.NewSelector("upstream", peers)
	return NewEngine(store.NewVRPStore(), aspas, sel, routetable.New(), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func locRIBTestRoute(path ...uint32) *types.Route {
	return &types.Route{
		Router: netip.MustParseAddr("192.0.2.1"), PeerType: types.PeerTypeLocRIB, PeerAddr: netip.IPv4Unspecified(),
		PeerASN: locL, LocalASN: locL, Prefix: netip.MustParsePrefix("203.0.113.0/24"),
		ASPath: path, ASPathRaw: []types.ASSegment{{Type: types.ASSegmentSequence, ASNs: path}}, RIBType: types.LocRIB,
	}
}

// A Loc-RIB route has no neighbor address, only its path: the procedure
// comes from the aspa-peers asn entry for the first AS (config-asn), then
// the default. Address entries never match it, and the neighbor-AS check
// does not apply (the route's peer AS is the router's own).
func TestLocRIBASPAProcedureFromNeighborAS(t *testing.T) {
	provider := []config.ASPAPeer{{ASN: locN, NeighborRole: "provider"}}
	for _, tc := range []struct {
		name   string
		peers  []config.ASPAPeer
		path   []uint32
		state  types.ASPAState
		proc   types.ASPAProcedure
		source types.ASPAProcedureSource
	}{
		{"asn entry for the first AS", provider, []uint32{locN, locO},
			types.ASPAValid, types.ASPADownstream, types.ASPASourceConfigASN},
		{"leading local AS removed first (FRR 10.2)", provider, []uint32{locL, locN, locO},
			types.ASPAValid, types.ASPADownstream, types.ASPASourceConfigASN},
		{"leading local AS prepended", provider, []uint32{locL, locL, locN, locO},
			types.ASPAValid, types.ASPADownstream, types.ASPASourceConfigASN},
		{"no entry: the default", nil, []uint32{locL, locN, locO},
			types.ASPAInvalid, types.ASPAUpstream, types.ASPASourceDefault},
		{"an address entry for the zero address does not match", []config.ASPAPeer{{Address: "0.0.0.0", NeighborRole: "provider"}},
			[]uint32{locN, locO}, types.ASPAInvalid, types.ASPAUpstream, types.ASPASourceDefault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := locRIBEngine(t, tc.peers)
			r := locRIBTestRoute(tc.path...)
			e.ValidateRoute(r)
			got := r.ASPA
			if got.State != tc.state || got.Procedure != tc.proc || got.ProcedureSource != tc.source || got.Reason != "" {
				t.Errorf("ASPA %s/%s/%s (reason %q), want %s/%s/%s and no reason",
					got.State, got.Procedure, got.ProcedureSource, got.Reason, tc.state, tc.proc, tc.source)
			}
			if !slices.Equal(r.ASPath, tc.path) {
				t.Errorf("stored AS_PATH %v, want it as received, %v", r.ASPath, tc.path)
			}
		})
	}
}

// The same entry on an Adj-RIB-In route is matched by the peer's AS and keeps
// the neighbor-AS check: the router's own AS first fails it.
func TestAdjRIBInKeepsNeighborCheck(t *testing.T) {
	e := locRIBEngine(t, []config.ASPAPeer{{ASN: locN, NeighborRole: "provider"}})
	r := locRIBTestRoute(locN, locO)
	r.RIBType, r.PeerType, r.PeerAddr, r.PeerASN = types.AdjRIBInPre, types.PeerTypeGlobal, netip.MustParseAddr("10.0.1.2"), locN
	e.ValidateRoute(r)
	if r.ASPA.State != types.ASPAValid || r.ASPA.ProcedureSource != types.ASPASourceConfigASN {
		t.Errorf("Adj-RIB-In route: ASPA %s/%s, want Valid/config-asn", r.ASPA.State, r.ASPA.ProcedureSource)
	}
	r = locRIBTestRoute(locL, locN, locO)
	r.RIBType, r.PeerType, r.PeerAddr, r.PeerASN = types.AdjRIBInPre, types.PeerTypeGlobal, netip.MustParseAddr("10.0.1.2"), locN
	e.ValidateRoute(r)
	if r.ASPA.State != types.ASPAInvalid || r.ASPA.Reason == "" {
		t.Errorf("Adj-RIB-In route starting with another AS: ASPA %s (%q), want Invalid by the neighbor-AS check",
			r.ASPA.State, r.ASPA.Reason)
	}
}

// withoutLeadingAS removes every leading copy of the AS from the flattened
// and the raw path alike, only from AS_SEQUENCE segments, and leaves a path
// that does not start with it, or an unknown AS, alone.
func TestWithoutLeadingAS(t *testing.T) {
	sq := func(a ...uint32) types.ASSegment { return types.ASSegment{Type: types.ASSegmentSequence, ASNs: a} }
	st := func(a ...uint32) types.ASSegment { return types.ASSegment{Type: types.ASSegmentSet, ASNs: a} }
	for _, tc := range []struct {
		name     string
		asn      uint32
		raw      []types.ASSegment
		flat     []uint32 // when raw is nil
		wantRaw  []types.ASSegment
		wantFlat []uint32
		stripped bool
	}{
		{"one copy", 65000, []types.ASSegment{sq(65000, 64510, 64500)}, nil,
			[]types.ASSegment{sq(64510, 64500)}, []uint32{64510, 64500}, true},
		{"prepended, across segments", 65000, []types.ASSegment{sq(65000), sq(65000, 64510), st(1, 2)}, nil,
			[]types.ASSegment{sq(64510), st(1, 2)}, []uint32{64510, 1, 2}, true},
		{"only the local AS", 65000, []types.ASSegment{sq(65000)}, nil,
			nil, []uint32{}, true},
		{"not first", 65000, []types.ASSegment{sq(64510, 65000)}, nil,
			[]types.ASSegment{sq(64510, 65000)}, []uint32{64510, 65000}, false},
		{"first in an AS_SET", 65000, []types.ASSegment{st(65000, 64510)}, nil,
			[]types.ASSegment{st(65000, 64510)}, []uint32{65000, 64510}, false},
		{"unknown local AS", 0, []types.ASSegment{sq(0, 64510)}, nil,
			[]types.ASSegment{sq(0, 64510)}, []uint32{0, 64510}, false},
		{"no segments (from a snapshot)", 65000, nil, []uint32{65000, 65000, 64510},
			nil, []uint32{64510}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &types.Route{ASPathRaw: tc.raw, ASPath: tc.flat}
			if tc.raw != nil {
				for _, s := range tc.raw {
					r.ASPath = append(r.ASPath, s.ASNs...)
				}
			}
			before := slices.Clone(r.ASPath)
			got, stripped := withoutLeadingAS(r, tc.asn)
			if stripped != tc.stripped {
				t.Fatalf("stripped = %v, want %v", stripped, tc.stripped)
			}
			if len(got.ASPath) != len(tc.wantFlat) || (len(got.ASPath) > 0 && !slices.Equal(got.ASPath, tc.wantFlat)) {
				t.Errorf("ASPath %v, want %v", got.ASPath, tc.wantFlat)
			}
			if len(got.ASPathRaw) != len(tc.wantRaw) {
				t.Fatalf("ASPathRaw %v, want %v", got.ASPathRaw, tc.wantRaw)
			}
			for i := range tc.wantRaw {
				if got.ASPathRaw[i].Type != tc.wantRaw[i].Type || !slices.Equal(got.ASPathRaw[i].ASNs, tc.wantRaw[i].ASNs) {
					t.Errorf("ASPathRaw %v, want %v", got.ASPathRaw, tc.wantRaw)
				}
			}
			if !slices.Equal(r.ASPath, before) {
				t.Errorf("the route itself changed: %v, was %v", r.ASPath, before)
			}
		})
	}
}

// A locally originated Loc-RIB route, sent as [local AS] (FRR 10.2) or with
// an empty AS_PATH, has the router's own AS, the Loc-RIB header's Peer AS, as
// origin (RFC 6811 §2): Valid under a ROA for it, with the reason saying
// where the origin came from, and Invalid under a ROA for another AS. Its
// ASPA is Unknown, as for any empty path.
func TestLocRIBLocallyOriginatedROV(t *testing.T) {
	vrps := store.NewVRPStore()
	vrps.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASN: locL, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: locO, MaxLength: 24},
	}, 1, 1)
	e := NewEngine(vrps, store.NewASPAStore(), aspa.NewSelector("upstream", nil), routetable.New(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	const note = "origin is the router's own AS: empty AS_PATH (RFC 6811 §2)"
	for _, tc := range []struct {
		name   string
		path   []uint32
		prefix string
		state  types.ROVState
	}{
		{"[local AS], ROA for it", []uint32{locL}, "203.0.113.0/24", types.ROVValid},
		{"[local AS] prepended, ROA for it", []uint32{locL, locL}, "203.0.113.0/24", types.ROVValid},
		{"empty, ROA for it", nil, "203.0.113.0/24", types.ROVValid},
		{"[local AS], ROA for another AS", []uint32{locL}, "198.51.100.0/24", types.ROVInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := locRIBTestRoute(tc.path...)
			if tc.path == nil {
				r.ASPathRaw = nil
			}
			r.Prefix = netip.MustParsePrefix(tc.prefix)
			e.ValidateRoute(r)
			if r.ROV.State != tc.state || !strings.HasSuffix(r.ROV.Reason, note) {
				t.Errorf("ROV %s (%q), want %s with a reason ending %q", r.ROV.State, r.ROV.Reason, tc.state, note)
			}
			if r.OriginASN() != locL {
				t.Errorf("origin AS%d, want the local AS%d", r.OriginASN(), locL)
			}
			if r.ASPA.State != types.ASPAUnknown || r.ASPA.Reason != aspa.EmptyPathReason {
				t.Errorf("ASPA %s (%q), want Unknown (%q)", r.ASPA.State, r.ASPA.Reason, aspa.EmptyPathReason)
			}
		})
	}
}
