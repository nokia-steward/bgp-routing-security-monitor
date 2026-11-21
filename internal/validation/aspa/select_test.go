package aspa

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

var (
	addrA = netip.MustParseAddr("192.0.2.1")
	addrB = netip.MustParseAddr("192.0.2.2")
)

func TestSelector_Precedence(t *testing.T) {
	sel := NewSelector("upstream", []config.ASPAPeer{
		{ASN: 64500, NeighborRole: "provider"},
		{Address: "192.0.2.1", NeighborRole: "customer"},
		{Address: "::ffff:192.0.2.3", NeighborRole: "rs"},
	})
	tests := []struct {
		name string
		addr netip.Addr
		asn  uint32
		want Selection
	}{
		{
			// The address entry wins over the ASN entry for the same peer.
			name: "address beats asn",
			addr: addrA, asn: 64500,
			want: Selection{types.ASPAUpstream, types.ASPASourceConfigAddress, true},
		},
		{
			// Another session of AS64500 without its own address entry gets
			// the ASN-mapped role.
			name: "asn entry for other session",
			addr: addrB, asn: 64500,
			want: Selection{types.ASPADownstream, types.ASPASourceConfigASN, true},
		},
		{
			name: "unmapped peer uses default",
			addr: addrB, asn: 64999,
			want: Selection{types.ASPAUpstream, types.ASPASourceDefault, false},
		},
		{
			// IPv4-mapped config address matches BMP's 4-byte IPv4 address;
			// rs never gets the neighbor-AS check.
			name: "mapped address, rs role",
			addr: netip.MustParseAddr("192.0.2.3"), asn: 64999,
			want: Selection{types.ASPAUpstream, types.ASPASourceConfigAddress, false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sel.Select(tt.addr, tt.asn); got != tt.want {
				t.Fatalf("Select = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSelector_RolesAndDefaults(t *testing.T) {
	for role, want := range map[string]Selection{
		"provider":  {types.ASPADownstream, types.ASPASourceConfigASN, true},
		"customer":  {types.ASPAUpstream, types.ASPASourceConfigASN, true},
		"peer":      {types.ASPAUpstream, types.ASPASourceConfigASN, true},
		"rs":        {types.ASPAUpstream, types.ASPASourceConfigASN, false},
		"rs-client": {types.ASPAUpstream, types.ASPASourceConfigASN, true},
	} {
		got := NewSelector("upstream", []config.ASPAPeer{{ASN: 1, NeighborRole: role}}).Select(addrA, 1)
		if got != want {
			t.Errorf("role %s: Select = %+v, want %+v", role, got, want)
		}
	}
	for def, want := range map[string]types.ASPAProcedure{
		"upstream": types.ASPAUpstream, "downstream": types.ASPADownstream,
		"auto": types.ASPAUpstream, "": types.ASPAUpstream,
	} {
		got := NewSelector(def, nil).Select(addrA, 1)
		if got != (Selection{Procedure: want, Source: types.ASPASourceDefault}) {
			t.Errorf("default %q: Select = %+v, want %s from default", def, got, want)
		}
	}
	if got := (*Selector)(nil).Select(addrA, 1); got != (Selection{}) {
		t.Errorf("nil Selector: Select = %+v, want upstream default", got)
	}
}

func TestSelector_SelectDoesNotAllocate(t *testing.T) {
	sel := NewSelector("upstream", []config.ASPAPeer{
		{ASN: 64500, NeighborRole: "provider"},
		{Address: "192.0.2.1", NeighborRole: "customer"},
	})
	if n := testing.AllocsPerRun(100, func() {
		sel.Select(addrA, 64500)
		sel.Select(addrB, 64500)
		sel.Select(addrB, 1)
	}); n != 0 {
		t.Fatalf("Select allocates %v times per run, want 0", n)
	}
}

// Section references are to draft-ietf-sidrops-aspa-verification-24.
func TestValidateSelection(t *testing.T) {
	sels := NewSelector("upstream", []config.ASPAPeer{
		{Address: "192.0.2.1", NeighborRole: "provider"},
		{Address: "192.0.2.2", NeighborRole: "rs"},
		{Address: "192.0.2.3", NeighborRole: "peer"},
	})
	tests := []struct {
		name       string
		peer       string
		peerASN    uint32
		path       []uint32
		want       types.ASPAState
		wantProc   types.ASPAProcedure
		wantSource types.ASPAProcedureSource
		wantReason bool
	}{
		{
			// §5.5: [P, O], no ASPA, min_up 1 + min_down 1 >= 2 → Valid.
			name: "provider-mapped [P O] no ASPA",
			peer: "192.0.2.1", peerASN: 174, path: []uint32{174, 13335},
			want: types.ASPAValid, wantProc: types.ASPADownstream, wantSource: types.ASPASourceConfigAddress,
		},
		{
			// §5.4: same route from an unmapped peer, default upstream:
			// min_up_ramp 1 < 2 → Unknown.
			name: "unmapped [P O] default upstream",
			peer: "198.51.100.9", peerASN: 174, path: []uint32{174, 13335},
			want: types.ASPAUnknown, wantProc: types.ASPAUpstream, wantSource: types.ASPASourceDefault,
		},
		{
			// §5.4 step 2 exempts RS-clients: a transparent RS (AS6777)
			// sends its client's path [64496] unchanged. No neighbor-AS
			// failure; N=1 → Valid.
			name: "rs-mapped, first AS is RS client",
			peer: "192.0.2.2", peerASN: 6777, path: []uint32{64496},
			want: types.ASPAValid, wantProc: types.ASPAUpstream, wantSource: types.ASPASourceConfigAddress,
		},
		{
			// §5.4 step 2: most recently added AS (64496) is not the
			// neighbor AS (64497) → Invalid.
			name: "peer-mapped, first AS differs from PeerASN",
			peer: "192.0.2.3", peerASN: 64497, path: []uint32{64496},
			want: types.ASPAInvalid, wantProc: types.ASPAUpstream, wantSource: types.ASPASourceConfigAddress,
			wantReason: true,
		},
		{
			// §5.1: prepends do not change the most recently added AS.
			name: "peer-mapped, prepended first AS matches",
			peer: "192.0.2.3", peerASN: 64497, path: []uint32{64497, 64497, 64496},
			want: types.ASPAUnknown, wantProc: types.ASPAUpstream, wantSource: types.ASPASourceConfigAddress,
		},
		{
			// Unknown role (default path): no neighbor-AS check.
			name: "unmapped, first AS differs from PeerASN",
			peer: "198.51.100.9", peerASN: 64497, path: []uint32{64496},
			want: types.ASPAValid, wantProc: types.ASPAUpstream, wantSource: types.ASPASourceDefault,
		},
	}
	a := NewAnnotator(store.NewASPAStore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &types.Route{
				PeerAddr: netip.MustParseAddr(tt.peer),
				PeerASN:  tt.peerASN,
				ASPath:   tt.path,
			}
			got := a.ValidateSelection(route, sels.Select(route.PeerAddr, route.PeerASN))
			if got.State != tt.want || got.Procedure != tt.wantProc || got.ProcedureSource != tt.wantSource {
				t.Fatalf("got %s/%s/%s, want %s/%s/%s", got.State, got.Procedure, got.ProcedureSource,
					tt.want, tt.wantProc, tt.wantSource)
			}
			if hasReason := strings.Contains(got.Reason, "neighbor-AS check failed"); hasReason != tt.wantReason {
				t.Fatalf("reason = %q, want neighbor-AS failure %v", got.Reason, tt.wantReason)
			}
		})
	}
}
