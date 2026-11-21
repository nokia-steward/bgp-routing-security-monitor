package routetable

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// ListRoutes lists the default view (Adj-RIB-In pre-policy and Loc-RIB)
// unless RIBs says otherwise, whatever the filter: a route a router reports
// in several RIBs used to be listed, and counted, once per RIB.
func TestListRoutesByRIB(t *testing.T) {
	tbl := New()
	peer := netip.MustParseAddr("192.0.2.9")
	p := netip.MustParsePrefix("1.1.1.0/24")
	for _, rib := range types.AllRIBTypes {
		tbl.Insert(&types.Route{PeerAddr: peer, Prefix: p, ASPath: []uint32{64501, 13335}, RIBType: rib,
			SecurityPosture: types.PostureSecured})
	}
	ribsOf := func(rs []types.Route) (out []types.RIBType) {
		for _, r := range rs {
			out = append(out, r.RIBType)
		}
		slices.Sort(out)
		return out
	}
	for _, f := range []Filter{{}, {PeerAddr: peer.String()}, {Prefix: p.String()}, {OriginASN: 13335}, {Posture: "secured"}} {
		rs, err := tbl.ListRoutes(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		if got := ribsOf(rs); !slices.Equal(got, []types.RIBType{types.AdjRIBInPre, types.LocRIB}) {
			t.Errorf("%+v: RIBs %v, want the default view", f, got)
		}
		f.RIBs = types.RIBSetOf(types.AdjRIBInPost)
		rs, _ = tbl.ListRoutes(context.Background(), f)
		if got := ribsOf(rs); !slices.Equal(got, []types.RIBType{types.AdjRIBInPost}) {
			t.Errorf("%+v: RIBs %v, want adj-rib-in-post only", f, got)
		}
	}
}
