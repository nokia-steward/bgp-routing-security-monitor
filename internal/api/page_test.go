package api

import (
	"cmp"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// getPage is one /api/v1/routes request for target, and its next page's
// target from the Link header ("" on the last page).
func getPage(t *testing.T, s *Server, target string) ([]RouteResponse, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleRoutes(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", target, rec.Code, rec.Body)
	}
	var routes []RouteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &routes); err != nil {
		t.Fatalf("%s: decode: %v", target, err)
	}
	link := rec.Header().Get("Link")
	if link == "" {
		return routes, ""
	}
	next, ok := strings.CutSuffix(link, `>; rel="next"`)
	if !ok || !strings.HasPrefix(next, "<") {
		t.Fatalf("%s: Link %q", target, link)
	}
	return routes, next[1:]
}

func routeID(r RouteResponse) string {
	return r.Prefix + " " + netip.MustParseAddr(r.PeerAddr).Unmap().String()
}

// compareByPrefixAndPeer orders the fixture's routes, which differ only
// in prefix and peer, as the route key does.
func compareByPrefixAndPeer(a, b RouteResponse) int {
	pa, pb := netip.MustParsePrefix(a.Prefix), netip.MustParsePrefix(b.Prefix)
	return cmp.Or(
		pa.Addr().Compare(pb.Addr()),
		cmp.Compare(pa.Bits(), pb.Bits()),
		netip.MustParseAddr(a.PeerAddr).Unmap().Compare(netip.MustParseAddr(b.PeerAddr).Unmap()),
	)
}

// Following the Link header from the first page lists every route once, in
// prefix order, limit routes a page, with the filter kept on every page.
func TestRoutesPagesFollowLink(t *testing.T) {
	s := filterFixture(t)
	for _, tc := range []struct {
		name  string
		q     url.Values
		sizes []int
	}{
		{"whole table", url.Values{"limit": {"3"}}, []int{3, 3, 1}},
		{"limit equal to the routes", url.Values{"limit": {"7"}}, []int{7}},
		{"filtered", url.Values{"limit": {"3"}, "prefix": {"1.1.1.0/24"}}, []int{3, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unpaged := url.Values{}
			for k, v := range tc.q {
				if k != "limit" {
					unpaged[k] = v
				}
			}
			_, all := getRoutes(t, s, unpaged)
			var want []string
			for _, r := range all {
				want = append(want, routeID(r))
			}
			slices.Sort(want)

			var sizes []int
			var pages []RouteResponse
			target := "/api/v1/routes?" + tc.q.Encode()
			for target != "" {
				var page []RouteResponse
				page, target = getPage(t, s, target)
				sizes = append(sizes, len(page))
				pages = append(pages, page...)
				if len(sizes) > len(tc.sizes) {
					t.Fatalf("more than %d pages", len(tc.sizes))
				}
			}
			if !slices.Equal(sizes, tc.sizes) {
				t.Errorf("page sizes %v, want %v", sizes, tc.sizes)
			}
			var got []string
			for _, r := range pages {
				got = append(got, routeID(r))
			}
			if !slices.IsSortedFunc(pages, compareByPrefixAndPeer) {
				t.Errorf("not in prefix and peer order: %v", got)
			}
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

// A route withdrawn between two pages does not shift the next page: it
// starts after the last route sent, wherever that route is now.
func TestRoutesPageAfterWithdrawnRoute(t *testing.T) {
	s := filterFixture(t)
	first, next := getPage(t, s, "/api/v1/routes?limit=2")
	if len(first) != 2 || next == "" {
		t.Fatalf("first page %d routes, next %q", len(first), next)
	}
	last := first[len(first)-1]
	if !s.table.Withdraw(types.RouteKey{
		Peer:    types.NewPeerRef(netip.Addr{}, 0, netip.MustParseAddr(last.PeerAddr)),
		Prefix:  netip.MustParsePrefix(last.Prefix),
		RIBType: types.AdjRIBInPre,
	}) {
		t.Fatalf("withdraw %s: not in the table", routeID(last))
	}

	var rest []string
	for next != "" {
		var page []RouteResponse
		page, next = getPage(t, s, next)
		for _, r := range page {
			rest = append(rest, routeID(r))
		}
	}
	if len(rest) != 5 {
		t.Errorf("after the first page: %v, want the 5 routes not yet sent", rest)
	}
	for _, r := range first {
		if slices.Contains(rest, routeID(r)) {
			t.Errorf("%s sent twice", routeID(r))
		}
	}
}

// Without limit or after, the answer is every route and has no Link.
func TestRoutesNoLimitNoLink(t *testing.T) {
	s := filterFixture(t)
	routes, next := getPage(t, s, "/api/v1/routes")
	if len(routes) != 7 || next != "" {
		t.Errorf("%d routes, next %q; want 7 and no Link", len(routes), next)
	}
}

func TestRoutesBadPageParameters(t *testing.T) {
	s := filterFixture(t)
	for _, q := range []string{"limit=0", "limit=-1", "limit=x", "after=not-a-cursor", "after="} {
		rec := httptest.NewRecorder()
		s.handleRoutes(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routes?"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, rec.Code)
		}
	}
}

// A cursor names the same route key once decoded, every field set or not.
func TestCursorRoundTrip(t *testing.T) {
	for _, k := range []types.RouteKey{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), RIBType: types.AdjRIBInPre},
		{
			Peer: types.PeerRef{
				Router:        netip.MustParseAddr("192.0.2.1"),
				Distinguisher: 64499<<32 | 100,
				Addr:          netip.MustParseAddr("2001:db8::1"),
			},
			Prefix:  netip.MustParsePrefix("2001:db8:1::/48"),
			PathID:  7,
			RIBType: types.LocRIB,
		},
	} {
		got, err := decodeCursor(encodeCursor(k))
		if err != nil || got != k {
			t.Errorf("%+v: decoded %+v, %v", k, got, err)
		}
	}
}

// Pages of a table larger than a page list every route once, in strictly
// increasing key order across page boundaries.
func TestRoutesPagesCoverLargeTable(t *testing.T) {
	s := largeRoutesServer(t, 1000)
	var pages []RouteResponse
	sizes := 0
	for target := "/api/v1/routes?limit=64"; target != ""; sizes++ {
		var page []RouteResponse
		page, target = getPage(t, s, target)
		pages = append(pages, page...)
	}
	if len(pages) != 1000 || sizes != 16 {
		t.Fatalf("%d routes in %d pages, want 1000 in 16", len(pages), sizes)
	}
	for i := 1; i < len(pages); i++ {
		if compareByPrefixAndPeer(pages[i-1], pages[i]) >= 0 {
			t.Fatalf("route %d (%s) not after route %d (%s)", i, pages[i].Prefix, i-1, pages[i-1].Prefix)
		}
	}
}
