package server

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/bmp/bmptest"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
)

// AS38016: br1.nyc reports its own address, 135.92.55.33, as a
// local-instance peer whose routes come post-policy only. raven peers shows
// it with 0 routes (its default view holds none), what-if counted its
// routes, and raven routes --peer 135.92.55.33 found none. For every RIB
// selection what-if takes, raven routes --peer with the same RIBs must list
// exactly the routes what-if counts for that peer.
func TestWhatIfPeerMatchesRoutesPeer(t *testing.T) {
	invalid := []rtrtest.VRP{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), MaxLen: 24, ASN: 64999}}
	h := startE2E(t, e2eConfig{vrps: invalid})
	h.ready()
	local := netip.MustParseAddr("135.92.55.33")
	lp := bmptest.Peer{Addr: local, ASN: 38016, BGPID: local, Type: 2, Distinguisher: 1, PostPolicy: true}
	h.feed.PeerUp(lp)
	h.feed.Announce(lp,
		bmptest.Route{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{38016, 64500}},
		bmptest.Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASPath: []uint32{38016, 64500}},
		bmptest.Route{Prefix: netip.MustParsePrefix("192.0.2.0/24"), ASPath: []uint32{38016, 64500}})
	h.feed.Announce(h.peer, bmptest.Route{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{64501, 64500}})
	h.waitTable(4, "the local peer's post-policy routes and the BGP peer's route")

	get := func(path string, q url.Values, v any) {
		t.Helper()
		resp, err := http.Get(h.api + path + "?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s?%s: status %d", path, q.Encode(), resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatal(err)
		}
	}

	var peers []api.PeerResponse
	get("/api/v1/peers", nil, &peers)
	for _, p := range peers {
		if p.Addr == local.String() && (p.PeerType != "local" || p.RouteCount != 0 || p.RoutesByRIB["adj-rib-in-post"] != 3) {
			t.Errorf("peer %s: type %s, %d routes, by RIB %v; want local, 0 in the default view, 3 post-policy",
				p.Addr, p.PeerType, p.RouteCount, p.RoutesByRIB)
		}
	}

	for _, rib := range []string{"", "adj-rib-in-post", "loc-rib", "all"} {
		q := url.Values{}
		if rib != "" {
			q.Set("rib", rib)
		}
		// reject-invalid has the by-peer breakdown (aspa-enforce has none).
		var res whatif.RejectInvalidResult
		get("/api/v1/whatif/reject-invalid", q, &res)
		if rib == "adj-rib-in-post" || rib == "all" {
			found := false
			for _, p := range res.ByPeer {
				found = found || p.PeerAddr == local.String()
			}
			if !found {
				t.Errorf("--rib %q: what-if by peer %+v lacks %s", rib, res.ByPeer, local)
			}
		}
		for _, p := range res.ByPeer {
			rq := url.Values{"peer": {p.PeerAddr}, "rib": res.RIBs}
			var routes []api.RouteResponse
			get("/api/v1/routes", rq, &routes)
			if len(routes) != p.Total {
				t.Errorf("--rib %q: what-if counts %d routes for peer %s, routes?%s lists %d",
					rib, p.Total, p.PeerAddr, rq.Encode(), len(routes))
			}
		}
	}

	// The default: what-if (adj-rib-in-pre) counts nothing for the local
	// peer, and raven routes --peer (the default view) lists nothing.
	var res whatif.RejectInvalidResult
	get("/api/v1/whatif/reject-invalid", nil, &res)
	for _, p := range res.ByPeer {
		if p.PeerAddr == local.String() {
			t.Errorf("default what-if counts %d routes for %s, whose routes are all post-policy", p.Total, local)
		}
	}
}
