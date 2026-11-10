package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation"
)

// traceServer is an API server over routes validated against vrps by the
// engine, as ingest leaves them.
func traceServer(t *testing.T, vrps []types.VRP, routes ...*types.Route) *Server {
	t.Helper()
	vs := store.NewVRPStore()
	vs.ReplaceAll(vrps, 1, 1)
	table := routetable.New()
	e := validation.NewEngine(vs, store.NewASPAStore(), nil, table, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, r := range routes {
		if r.PeerAddr == (netip.Addr{}) {
			r.PeerAddr = netip.MustParseAddr("192.0.2.1")
		}
		e.ValidateRoute(r)
		table.Insert(r)
	}
	return NewServer(table, nil, vs, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
}

// productionRoute is the route from the production report:
// 94.177.129.126/32 from AS202744, under VRP 94.177.129.0/24-24 AS202744,
// carrying BLACKHOLE and a large community.
func productionRoute() *types.Route {
	return &types.Route{
		Router:           netip.MustParseAddr("192.0.2.3"),
		PeerAddr:         netip.MustParseAddr("80.81.194.180"),
		PeerASN:          6695,
		Prefix:           netip.MustParsePrefix("94.177.129.126/32"),
		ASPath:           []uint32{6695, 202744},
		NextHop:          netip.MustParseAddr("80.81.194.180"),
		Communities:      []types.Community{{High: 6695, Low: 1911}, types.CommunityBlackhole},
		LargeCommunities: []types.LargeCommunity{{GlobalAdmin: 6695, LocalData1: 1911, LocalData2: 172}},
	}
}

var productionVRPs = []types.VRP{
	{Prefix: netip.MustParsePrefix("94.177.129.0/24"), ASN: 202744, MaxLength: 24},
	{Prefix: netip.MustParsePrefix("94.176.0.0/14"), ASN: 64511, MaxLength: 24},
}

// rawRoutes is /api/v1/routes for q, undecoded, and the body.
func rawRoutes(t *testing.T, s *Server, q url.Values) ([]map[string]json.RawMessage, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleRoutes(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routes?"+q.Encode(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("routes %s: %d %s", q.Encode(), rec.Code, rec.Body)
	}
	var out []map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out, rec.Body.String()
}

// The production route lists as invalid_length, its reason naming the
// VRP, with the covering VRPs split as Routinator splits them, the
// deciding VRP, and its communities as strings.
func TestRouteJSONROVTraceAndCommunities(t *testing.T) {
	s := traceServer(t, productionVRPs, productionRoute())
	_, routes := getRoutes(t, s, url.Values{"prefix": {"94.177.129.126/32"}})
	if len(routes) != 1 {
		t.Fatalf("%d routes, want 1", len(routes))
	}
	r := routes[0]
	if r.ROV != "Invalid" || r.ROVReasonCode != "invalid_length" ||
		r.ROVReason != "prefix length /32 exceeds maxLength /24 of VRP 94.177.129.0/24 AS202744" {
		t.Errorf("rov %s, code %q, reason %q", r.ROV, r.ROVReasonCode, r.ROVReason)
	}
	want := ROVVRPsResponse{
		Matched:         []VRPResponse{},
		UnmatchedAS:     []VRPResponse{{Prefix: "94.176.0.0/14", ASN: 64511, MaxLength: 24}},
		UnmatchedLength: []VRPResponse{{Prefix: "94.177.129.0/24", ASN: 202744, MaxLength: 24}},
	}
	if r.ROVVRPs == nil || !slices.Equal(r.ROVVRPs.Matched, want.Matched) || !slices.Equal(r.ROVVRPs.UnmatchedAS, want.UnmatchedAS) ||
		!slices.Equal(r.ROVVRPs.UnmatchedLength, want.UnmatchedLength) ||
		r.ROVVRPs.MatchedCount+r.ROVVRPs.UnmatchedASCount+r.ROVVRPs.UnmatchedLengthCount != 0 {
		t.Errorf("rov_vrps %+v, want %+v", r.ROVVRPs, want)
	}
	if d := r.ROVDecidingVRP; d == nil || *d != (VRPResponse{Prefix: "94.177.129.0/24", ASN: 202744, MaxLength: 24}) {
		t.Errorf("rov_deciding_vrp %+v, want 94.177.129.0/24 AS202744 /24", d)
	}
	if !slices.Equal(r.Communities, []string{"6695:1911", "65535:666"}) || !slices.Equal(r.LargeCommunities, []string{"6695:1911:172"}) {
		t.Errorf("communities %q, large %q", r.Communities, r.LargeCommunities)
	}

	// On the wire: empty lists are [], not null, and counts are absent
	// when nothing was cut.
	raw, body := rawRoutes(t, s, url.Values{"prefix": {"94.177.129.126/32"}})
	var trace map[string]json.RawMessage
	if err := json.Unmarshal(raw[0]["rov_vrps"], &trace); err != nil {
		t.Fatal(err)
	}
	if string(trace["matched"]) != "[]" {
		t.Errorf("matched = %s, want []", trace["matched"])
	}
	for _, k := range []string{"matched_count", "unmatched_as_count", "unmatched_length_count"} {
		if _, ok := trace[k]; ok {
			t.Errorf("%s present on an untruncated trace", k)
		}
	}
	t.Logf("production route JSON:\n%s", body)
}

// A route with no covering VRP has an empty trace and no deciding VRP; one
// with no communities has neither field.
func TestRouteJSONNotFoundTrace(t *testing.T) {
	s := traceServer(t, productionVRPs, &types.Route{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{64500}})
	raw, _ := rawRoutes(t, s, url.Values{"prefix": {"203.0.113.0/24"}})
	r := raw[0]
	if string(r["rov_reason_code"]) != `"not_found"` {
		t.Errorf("rov_reason_code %s", r["rov_reason_code"])
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, r["rov_vrps"]); err != nil || compact.String() != `{"matched":[],"unmatched_as":[],"unmatched_length":[]}` {
		t.Errorf("rov_vrps %s", r["rov_vrps"])
	}
	for _, k := range []string{"rov_deciding_vrp", "communities", "large_communities"} {
		if _, ok := r[k]; ok {
			t.Errorf("%s = %s, want it omitted", k, r[k])
		}
	}
}

// Each rov_vrps list shows at most MaxVRPTrace VRPs; a list cut short gives
// its full length in its _count field, the others none.
func TestRouteJSONTraceTruncated(t *testing.T) {
	var vrps []types.VRP
	for i := 0; i < 20; i++ { // 20 VRPs for other ASes, /8 to /27
		vrps = append(vrps, types.VRP{Prefix: netip.PrefixFrom(netip.MustParseAddr("10.0.0.0"), 8+i).Masked(), ASN: uint32(64600 + i), MaxLength: 32})
	}
	vrps = append(vrps, types.VRP{Prefix: netip.MustParsePrefix("10.0.0.0/8"), ASN: 64500, MaxLength: 32})
	s := traceServer(t, vrps, &types.Route{Prefix: netip.MustParsePrefix("10.0.0.0/28"), ASPath: []uint32{64500}})
	_, routes := getRoutes(t, s, url.Values{"prefix": {"10.0.0.0/28"}})
	tr := routes[0].ROVVRPs
	if routes[0].ROVReasonCode != "valid" || tr == nil {
		t.Fatalf("route %+v", routes[0])
	}
	if len(tr.UnmatchedAS) != MaxVRPTrace || tr.UnmatchedASCount != 20 {
		t.Errorf("unmatched_as: %d shown, count %d; want %d and 20", len(tr.UnmatchedAS), tr.UnmatchedASCount, MaxVRPTrace)
	}
	if tr.UnmatchedAS[0].Prefix != "10.0.0.0/8" || tr.UnmatchedAS[MaxVRPTrace-1].Prefix != fmt.Sprintf("10.0.0.0/%d", 8+MaxVRPTrace-1) {
		t.Errorf("unmatched_as kept %s … %s, want the first %d, shortest first", tr.UnmatchedAS[0].Prefix, tr.UnmatchedAS[MaxVRPTrace-1].Prefix, MaxVRPTrace)
	}
	if len(tr.Matched) != 1 || tr.MatchedCount != 0 || len(tr.UnmatchedLength) != 0 || tr.UnmatchedLengthCount != 0 {
		t.Errorf("matched %v (count %d), unmatched_length %v (count %d); want one matched, no counts",
			tr.Matched, tr.MatchedCount, tr.UnmatchedLength, tr.UnmatchedLengthCount)
	}
}

// A watcher gets the same trace a listing does.
func TestWatchEventHasTrace(t *testing.T) {
	s := traceServer(t, productionVRPs)
	ch := make(chan RouteResponse, 1)
	s.watchSubs[ch] = &routeFilter{}
	r := productionRoute()
	r.ROV = rovOf(t, s, r)
	s.NotifyRoute(r)
	got := <-ch
	if got.ROVReasonCode != "invalid_length" || got.ROVDecidingVRP == nil || got.ROVVRPs == nil || len(got.ROVVRPs.UnmatchedLength) != 1 {
		t.Errorf("watch event %+v", got)
	}
}

func rovOf(t *testing.T, s *Server, r *types.Route) types.ROVResult {
	t.Helper()
	e := validation.NewEngine(s.vrpStore, store.NewASPAStore(), nil, routetable.New(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.ValidateRoute(r)
	return r.ROV
}

// matchFixture holds nested and sibling prefixes, IPv4 and IPv6, on two
// peers, and one Loc-RIB route outside the queried RIB.
func matchFixture(t *testing.T) *Server {
	t.Helper()
	var routes []*types.Route
	for _, p := range []string{
		"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25", "10.2.0.0/16", "11.0.0.0/8",
		"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1:2::/64", "2001:db8:2::/48", "2001:db9::/32",
	} {
		for _, peer := range []string{"192.0.2.1", "192.0.2.2"} {
			routes = append(routes, &types.Route{PeerAddr: netip.MustParseAddr(peer), Prefix: netip.MustParsePrefix(p),
				ASPath: []uint32{64500}, RIBType: types.AdjRIBInPre})
		}
	}
	routes = append(routes, &types.Route{PeerType: types.PeerTypeLocRIB, PeerAddr: netip.IPv4Unspecified(),
		Prefix: netip.MustParsePrefix("10.0.0.0/8"), ASPath: []uint32{64500}, RIBType: types.LocRIB})
	return traceServer(t, nil, routes...)
}

func prefixesOf(routes []RouteResponse) []string {
	var out []string
	for _, r := range routes {
		out = append(out, r.Prefix)
	}
	return out
}

// --match exact is the prefix alone (the default, as before); covering adds
// every less specific route covering it, least specific first; longer adds
// every more specific route within it. Each applies the other filters and
// the RIB, and a prefix not in the table is covered all the same.
func TestRoutesMatch(t *testing.T) {
	s := matchFixture(t)
	for _, tc := range []struct {
		prefix, match, peer, rib string
		want                     []string
	}{
		{"10.1.0.0/16", "", "192.0.2.1", "", []string{"10.1.0.0/16"}},
		{"10.1.0.0/16", "exact", "192.0.2.1", "", []string{"10.1.0.0/16"}},
		{"10.1.0.0/16", "covering", "192.0.2.1", "", []string{"10.0.0.0/8", "10.1.0.0/16"}},
		{"10.1.0.0/16", "longer", "192.0.2.1", "", []string{"10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25"}},
		{"10.1.3.0/24", "exact", "192.0.2.1", "", nil},
		{"10.1.3.0/24", "covering", "192.0.2.1", "", []string{"10.0.0.0/8", "10.1.0.0/16"}},
		{"10.1.2.200/25", "covering", "192.0.2.1", "", []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25"}},
		{"10.0.0.0/7", "longer", "192.0.2.1", "", []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25", "10.2.0.0/16", "11.0.0.0/8"}},
		{"10.1.0.0/16", "covering", "", "", []string{"10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/16"}},
		{"10.1.0.0/16", "covering", "", "adj-rib-in-pre", []string{"10.0.0.0/8", "10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/16"}},
		{"2001:db8:1::/48", "exact", "192.0.2.2", "", []string{"2001:db8:1::/48"}},
		{"2001:db8:1::/48", "covering", "192.0.2.2", "", []string{"2001:db8::/32", "2001:db8:1::/48"}},
		{"2001:db8:1::/48", "longer", "192.0.2.2", "", []string{"2001:db8:1::/48", "2001:db8:1:2::/64"}},
		{"2001:db8:1:2:3::/80", "covering", "192.0.2.2", "", []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1:2::/64"}},
		{"2001:db8::/32", "longer", "192.0.2.2", "", []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1:2::/64", "2001:db8:2::/48"}},
	} {
		q := url.Values{"prefix": {tc.prefix}}
		for k, v := range map[string]string{"match": tc.match, "peer": tc.peer, "rib": tc.rib} {
			if v != "" {
				q.Set(k, v)
			}
		}
		code, routes := getRoutes(t, s, q)
		got := prefixesOf(routes) // covering: least specific first; longer: CIDR order
		if code != http.StatusOK || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %d %v, want %v", q.Encode(), code, got, tc.want)
		}
	}
	for _, q := range []url.Values{
		{"prefix": {"10.0.0.0/8"}, "match": {"supernets"}},
		{"match": {"covering"}},
		{"match": {"longer"}, "origin-asn": {"64500"}},
	} {
		if code, _ := getRoutes(t, s, q); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", q.Encode(), code)
		}
	}
}

// A watch filter matches a route's prefix as a listing does.
func TestWatchMatch(t *testing.T) {
	f, err := parseRouteFilter(url.Values{"prefix": {"10.1.0.0/16"}, "match": {"covering"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := parseRouteFilter(url.Values{"prefix": {"10.1.0.0/16"}, "match": {"longer"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		prefix           string
		covering, longer bool
	}{
		{"10.0.0.0/8", true, false},
		{"10.1.0.0/16", true, true},
		{"10.1.2.0/24", false, true},
		{"10.2.0.0/16", false, false},
		{"::ffff:10.0.0.0/104", false, false}, // another family
	} {
		r := &types.Route{Prefix: netip.MustParsePrefix(tc.prefix)}
		if f.match(r) != tc.covering || g.match(r) != tc.longer {
			t.Errorf("%s: covering %v longer %v, want %v %v", tc.prefix, f.match(r), g.match(r), tc.covering, tc.longer)
		}
	}
}
