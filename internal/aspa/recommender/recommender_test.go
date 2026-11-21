package recommender

import (
	"context"
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Relationships come from paths as neighbors sent them (Adj-RIB-In
// pre-policy). The same prefix in the router's Loc-RIB, with the router's
// own AS first as FRR 10.2 sends it, must not suggest that AS as a
// provider, nor count the pre-policy path's hops a second time.
func TestRecommendIgnoresLocRIB(t *testing.T) {
	const localAS, neighborAS, originAS = 65000, 64501, 13335
	router := netip.MustParseAddr("192.0.2.1")
	p := netip.MustParsePrefix("1.1.1.0/24")
	table := routetable.New()
	table.Insert(&types.Route{Router: router, PeerAddr: netip.MustParseAddr("192.0.2.9"), PeerASN: neighborAS,
		Prefix: p, ASPath: []uint32{neighborAS, originAS}, RIBType: types.AdjRIBInPre})
	table.Insert(&types.Route{Router: router, PeerType: types.PeerTypeLocRIB, PeerAddr: netip.IPv4Unspecified(),
		PeerASN: localAS, LocalASN: localAS, Prefix: p, ASPath: []uint32{localAS, neighborAS, originAS},
		RIBType: types.LocRIB})

	got, err := NewRecommender(table, store.NewASPAStore()).Recommend(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CustomerASN != originAS {
		t.Fatalf("suggestions %+v, want one, for AS%d", got, originAS)
	}
	ps := got[0].SuggestedProviders
	if len(ps) != 1 || ps[0].ProviderASN != neighborAS || ps[0].ObservedCount != 1 {
		t.Errorf("AS%d providers %+v, want AS%d observed once", originAS, ps, neighborAS)
	}
}
