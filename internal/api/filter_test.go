package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation"
)

// filterFixture is the production report's shape: 1.1.1.0/24 held by four
// peers, plus other prefixes, origins and postures on the same peers. Peer
// 80.81.194.180's routes are stored under its IPv4-mapped form, which must
// match the plain form and the reverse.
func filterFixture(t *testing.T) *Server {
	t.Helper()
	table := routetable.New()
	add := func(peer, prefix string, origin uint32, posture types.SecurityPosture) {
		table.Insert(&types.Route{
			PeerAddr:        netip.MustParseAddr(peer),
			Prefix:          netip.MustParsePrefix(prefix),
			ASPath:          []uint32{64500, origin},
			RIBType:         types.AdjRIBInPre,
			SecurityPosture: posture,
		})
	}
	for _, peer := range []string{"::ffff:80.81.194.180", "80.81.194.181", "206.82.106.254", "46.18.174.241"} {
		add(peer, "1.1.1.0/24", 13335, types.PostureSecured)
	}
	add("::ffff:80.81.194.180", "8.8.8.0/24", 15169, types.PostureOriginOnly)
	add("::ffff:80.81.194.180", "9.9.9.0/24", 13335, types.PosturePathSuspect)
	add("206.82.106.254", "8.8.8.0/24", 15169, types.PostureOriginOnly)
	return NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
}

func getRoutes(t *testing.T, s *Server, q url.Values) (int, []RouteResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleRoutes(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routes?"+q.Encode(), nil))
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var out []RouteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rec.Code, out
}

// Every filter given applies, alone and in any combination; an IPv4 peer
// matches in either form.
func TestRoutesFiltersCombine(t *testing.T) {
	s := filterFixture(t)
	key := func(r RouteResponse) string {
		return netip.MustParseAddr(r.PeerAddr).Unmap().String() + " " + r.Prefix
	}
	for _, tc := range []struct {
		name string
		q    url.Values
		want []string
	}{
		{"prefix and peer (the report)", url.Values{"prefix": {"1.1.1.0/24"}, "peer": {"80.81.194.180"}},
			[]string{"80.81.194.180 1.1.1.0/24"}},
		{"prefix and peer, mapped form", url.Values{"prefix": {"1.1.1.0/24"}, "peer": {"::ffff:80.81.194.180"}},
			[]string{"80.81.194.180 1.1.1.0/24"}},
		{"prefix and plain-stored peer, mapped form", url.Values{"prefix": {"1.1.1.0/24"}, "peer": {"::ffff:206.82.106.254"}},
			[]string{"206.82.106.254 1.1.1.0/24"}},
		{"prefix alone", url.Values{"prefix": {"1.1.1.0/24"}},
			[]string{"206.82.106.254 1.1.1.0/24", "46.18.174.241 1.1.1.0/24", "80.81.194.180 1.1.1.0/24", "80.81.194.181 1.1.1.0/24"}},
		{"peer alone", url.Values{"peer": {"80.81.194.180"}},
			[]string{"80.81.194.180 1.1.1.0/24", "80.81.194.180 8.8.8.0/24", "80.81.194.180 9.9.9.0/24"}},
		{"origin and peer", url.Values{"origin-asn": {"13335"}, "peer": {"80.81.194.180"}},
			[]string{"80.81.194.180 1.1.1.0/24", "80.81.194.180 9.9.9.0/24"}},
		{"posture and peer", url.Values{"posture": {"origin-only"}, "peer": {"206.82.106.254"}},
			[]string{"206.82.106.254 8.8.8.0/24"}},
		{"prefix and posture", url.Values{"prefix": {"8.8.8.0/24"}, "posture": {"secured"}}, nil},
		{"prefix and origin", url.Values{"prefix": {"1.1.1.0/24"}, "origin-asn": {"15169"}}, nil},
		{"all four", url.Values{"prefix": {"9.9.9.0/24"}, "origin-asn": {"13335"}, "peer": {"80.81.194.180"}, "posture": {"path-suspect"}},
			[]string{"80.81.194.180 9.9.9.0/24"}},
		{"peer with no routes", url.Values{"peer": {"192.0.2.99"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, routes := getRoutes(t, s, tc.q)
			if code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			var got []string
			for _, r := range routes {
				got = append(got, key(r))
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	for _, bad := range []url.Values{{"peer": {"not-an-ip"}}, {"prefix": {"1.1.1.0/24"}, "peer": {"x"}}, {"origin-asn": {"AS1"}}} {
		if code, _ := getRoutes(t, s, bad); code != http.StatusBadRequest {
			t.Errorf("%v: status %d, want 400", bad, code)
		}
	}
}

// raven watch applies the same filters to the stream.
func TestWatchFilters(t *testing.T) {
	s := filterFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(s.handleWatch))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		srv.URL+"?"+url.Values{"prefix": {"1.1.1.0/24"}, "peer": {"::ffff:80.81.194.180"}}.Encode(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for {
		s.watchMu.RLock()
		n := len(s.watchSubs)
		s.watchMu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	route := func(peer, prefix string) *types.Route {
		return &types.Route{PeerAddr: netip.MustParseAddr(peer), Prefix: netip.MustParsePrefix(prefix), ASPath: []uint32{64500, 13335}}
	}
	s.NotifyRoute(route("80.81.194.181", "1.1.1.0/24")) // other peer
	s.NotifyRoute(route("80.81.194.180", "8.8.8.0/24")) // other prefix
	s.NotifyRoute(route("80.81.194.180", "1.1.1.0/24")) // match, plain form
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var rr RouteResponse
		if err := json.Unmarshal([]byte(line), &rr); err != nil {
			t.Fatal(err)
		}
		if rr.PeerAddr != "80.81.194.180" || rr.Prefix != "1.1.1.0/24" {
			t.Fatalf("watch delivered %s via %s, which the filter excludes", rr.Prefix, rr.PeerAddr)
		}
		return
	}
	t.Fatalf("no event: %v", sc.Err())
}

// The failing ASPA hop is in the route JSON, and absent when there is none.
func TestRouteJSONFailingHop(t *testing.T) {
	r := &types.Route{Prefix: netip.MustParsePrefix("145.102.136.0/22"), ASPath: []uint32{65000, 1199}}
	b, _ := json.Marshal(routeToResponse(r, ""))
	if strings.Contains(string(b), "aspa_failing_hop") {
		t.Errorf("JSON %s has aspa_failing_hop with no failing hop", b)
	}
	r.ASPA.FailingHop = &types.ASPAHop{CustomerASN: 1199, ProviderASN: 65000, Authorization: types.HopNotAuthorized}
	b, _ = json.Marshal(routeToResponse(r, ""))
	if !strings.Contains(string(b), `"aspa_failing_hop":{"customer_asn":1199,"provider_asn":65000}`) {
		t.Errorf("JSON %s lacks the failing hop", b)
	}
}

// A route the engine finds ASPA Invalid carries its failing hop to the watch
// stream's JSON; once it is no longer Invalid the hop is gone.
func TestWatchJSONFailingHopFromEngine(t *testing.T) {
	aspas := store.NewASPAStore()
	for _, p := range []uint32{16735, 23106, 270735} {
		aspas.AddProvider(53072, p)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := validation.NewEngine(store.NewVRPStore(), aspas, nil, routetable.New(), log)
	r := &types.Route{
		PeerAddr: netip.MustParseAddr("192.0.2.1"),
		PeerASN:  1031,
		Prefix:   netip.MustParsePrefix("104.16.0.0/13"),
		NextHop:  netip.MustParseAddr("192.0.2.1"),
		ASPath:   []uint32{1031, 262504, 53072, 7738, 13335},
	}
	e.ValidateRoute(r)
	if r.ASPA.State != types.ASPAInvalid || r.SecurityPosture != types.PosturePathSuspect {
		t.Fatalf("ASPA %s posture %s, want Invalid path-suspect", r.ASPA.State, r.SecurityPosture)
	}
	if h := r.ASPA.FailingHop; h == nil || h.CustomerASN != 53072 || h.ProviderASN != 262504 {
		t.Fatalf("failing hop = %+v, want 53072→262504", h)
	}

	s := NewServer(routetable.New(), nil, store.NewVRPStore(), log, "test")
	ch := make(chan RouteResponse, 1)
	s.watchMu.Lock()
	s.watchSubs[ch] = &watcher{}
	s.watchMu.Unlock()
	s.NotifyRoute(r)
	b, _ := json.Marshal(<-ch)
	for _, want := range []string{`"aspa":"Invalid"`,
		`"aspa_failing_hop":{"customer_asn":53072,"provider_asn":262504}`, `"posture":"path-suspect"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("watch JSON %s lacks %s", b, want)
		}
	}

	aspas.AddProvider(53072, 262504) // the leak is now an authorized provider
	e.ValidateRoute(r)
	if r.ASPA.State == types.ASPAInvalid {
		t.Fatalf("ASPA still Invalid with 262504 authorized")
	}
	s.NotifyRoute(r)
	if b, _ := json.Marshal(<-ch); strings.Contains(string(b), "aspa_failing_hop") {
		t.Errorf("watch JSON %s has aspa_failing_hop when ASPA is %s", b, r.ASPA.State)
	}
}

// origin_asn is the origin ROV validated (RFC 6811 §2): for an empty
// AS_PATH, or one ending in a confederation segment, the router's own AS,
// not 0.
func TestRouteJSONLocalOrigin(t *testing.T) {
	confed := []types.ASSegment{{Type: types.ASSegmentConfedSequence, ASNs: []uint32{65002}}}
	for _, tc := range []struct {
		name  string
		route types.Route
		want  uint32
	}{
		{"empty AS_PATH", types.Route{LocalASN: 64500}, 64500},
		{"empty AS_PATH inside a confederation", types.Route{LocalASN: 65001, ConfedID: 64500}, 64500},
		{"confederation, identifier known", types.Route{ASPath: []uint32{65002}, ASPathRaw: confed, LocalASN: 65001, ConfedID: 64500}, 64500},
		{"confederation, member AS", types.Route{ASPath: []uint32{65002}, ASPathRaw: confed, LocalASN: 65001}, 65001},
		{"local AS not known", types.Route{}, 0},
	} {
		tc.route.Prefix = netip.MustParsePrefix("198.51.100.0/24")
		if got := routeToResponse(&tc.route, "").OriginASN; got != tc.want {
			t.Errorf("%s: origin_asn %d, want %d", tc.name, got, tc.want)
		}
	}
}

// The routes listing shows one RIB, Adj-RIB-In pre-policy unless rib names
// another, with or without other filters. Outbound routes could not be
// listed at all before.
func TestRoutesRIB(t *testing.T) {
	table := routetable.New()
	peer := netip.MustParseAddr("80.81.194.180")
	for _, rib := range types.AllRIBTypes {
		for _, prefix := range []string{"1.1.1.0/24", "8.8.8.0/24"} {
			table.Insert(&types.Route{PeerAddr: peer, Prefix: netip.MustParsePrefix(prefix),
				ASPath: []uint32{64501, 13335}, RIBType: rib, SecurityPosture: types.PostureSecured})
		}
	}
	s := NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	for _, filter := range []url.Values{{}, {"prefix": {"1.1.1.0/24"}}, {"origin-asn": {"13335"}},
		{"peer": {"80.81.194.180"}}, {"posture": {"secured"}}} {
		for _, rib := range append([]string{""}, func() (names []string) {
			for _, r := range types.AllRIBTypes {
				names = append(names, r.String())
			}
			return
		}()...) {
			q := url.Values{}
			for k, v := range filter {
				q[k] = v
			}
			// Without rib, the default view: Adj-RIB-In pre-policy and
			// Loc-RIB, both of them.
			want := []string{"adj-rib-in-pre", "loc-rib"}
			if rib != "" {
				q.Set("rib", rib)
				want = []string{rib}
			}
			code, routes := getRoutes(t, s, q)
			if code != http.StatusOK || len(routes) == 0 {
				t.Fatalf("%v: status %d, %d routes", q, code, len(routes))
			}
			seen := map[string]bool{}
			for _, r := range routes {
				seen[r.RIB] = true
				if !slices.Contains(want, r.RIB) {
					t.Errorf("%v: got a %s route, want only %v", q, r.RIB, want)
				}
			}
			if len(seen) != len(want) {
				t.Errorf("%v: routes of %v, want of each of %v", q, seen, want)
			}
		}
	}
	if code, _ := getRoutes(t, s, url.Values{"rib": {"adj-rib-in"}}); code != http.StatusBadRequest {
		t.Errorf("unknown rib: status %d, want 400", code)
	}
	// pre-policy and post-policy are aliases; several RIBs can be named.
	for rib, want := range map[string][]string{
		"pre-policy":                  {"adj-rib-in-pre"},
		"post-policy":                 {"adj-rib-in-post"},
		"post-policy,loc-rib":         {"adj-rib-in-post", "loc-rib"},
		"adj-rib-out-pre, pre-policy": {"adj-rib-in-pre", "adj-rib-out-pre"},
	} {
		code, routes := getRoutes(t, s, url.Values{"rib": {rib}, "prefix": {"1.1.1.0/24"}})
		var got []string
		for _, r := range routes {
			got = append(got, r.RIB)
		}
		slices.Sort(got)
		if code != http.StatusOK || !slices.Equal(got, want) {
			t.Errorf("rib=%s: status %d, RIBs %v, want %v", rib, code, got, want)
		}
	}

	// A watch without rib streams the default view, as routes lists it.
	def, err := parseRouteFilter(url.Values{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := parseRouteFilter(url.Values{"rib": {"adj-rib-out-pre"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pre := &types.Route{RIBType: types.AdjRIBInPre}
	loc := &types.Route{RIBType: types.LocRIB}
	post := &types.Route{RIBType: types.AdjRIBInPost}
	outbound := &types.Route{RIBType: types.AdjRIBOutPre}
	if !def.match(pre) || !def.match(loc) || def.match(post) || def.match(outbound) {
		t.Error("watch without rib: want the default view, adj-rib-in-pre and loc-rib only")
	}
	if out.match(post) || !out.match(outbound) {
		t.Error("watch rib=adj-rib-out-pre: RIB filtering wrong")
	}
}

// --prefix and --origin-asn look up indexes that hold every RIB: an
// Adj-RIB-Out and a post-policy route for the prefix must stay out of the
// default (Adj-RIB-In pre-policy) answer and be the answer with their --rib.
func TestRoutesPrefixAndOriginApplyRIB(t *testing.T) {
	table := routetable.New()
	peer := netip.MustParseAddr("80.81.194.180")
	for _, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost, types.AdjRIBOutPre} {
		table.Insert(&types.Route{PeerAddr: peer, Prefix: netip.MustParsePrefix("1.1.1.0/24"),
			ASPath: []uint32{64501, 13335}, RIBType: rib, SecurityPosture: types.PostureSecured})
	}
	s := NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	for _, q := range []url.Values{{"prefix": {"1.1.1.0/24"}}, {"origin-asn": {"13335"}}} {
		for rib, want := range map[string]string{
			"":                 "adj-rib-in-pre",
			"adj-rib-in-pre":   "adj-rib-in-pre",
			"adj-rib-in-post":  "adj-rib-in-post",
			"adj-rib-out-pre":  "adj-rib-out-pre",
			"adj-rib-out-post": "",
		} {
			qq := url.Values{}
			for k, v := range q {
				qq[k] = v
			}
			if rib != "" {
				qq.Set("rib", rib)
			}
			code, routes := getRoutes(t, s, qq)
			var got []string
			for _, r := range routes {
				got = append(got, r.RIB)
			}
			if code != http.StatusOK || (want == "" && len(got) != 0) || (want != "" && !slices.Equal(got, []string{want})) {
				t.Errorf("%v: status %d, RIBs %v, want [%s]", qq, code, got, want)
			}
		}
	}
}

// Routes and watch output carry the route's receive time, RFC 3339 in UTC;
// it was always "". A route with no time gives "".
func TestRouteTimestamp(t *testing.T) {
	table := routetable.New()
	received := time.Date(2026, 10, 18, 14, 30, 5, 123000000, time.FixedZone("CEST", 2*3600))
	table.Insert(&types.Route{PeerAddr: netip.MustParseAddr("80.81.194.180"), Prefix: netip.MustParsePrefix("1.1.1.0/24"),
		ASPath: []uint32{64501, 13335}, Timestamp: received})
	table.Insert(&types.Route{PeerAddr: netip.MustParseAddr("80.81.194.180"), Prefix: netip.MustParsePrefix("8.8.8.0/24"),
		ASPath: []uint32{64501, 15169}})
	s := NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	const want = "2026-10-18T12:30:05Z"

	_, routes := getRoutes(t, s, url.Values{})
	got := map[string]string{}
	for _, r := range routes {
		got[r.Prefix] = r.Timestamp
	}
	if got["1.1.1.0/24"] != want || got["8.8.8.0/24"] != "" {
		t.Errorf("routes timestamps %v, want 1.1.1.0/24 %s and 8.8.8.0/24 empty", got, want)
	}

	srv := httptest.NewServer(http.HandlerFunc(s.handleWatch))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for {
		s.watchMu.RLock()
		n := len(s.watchSubs)
		s.watchMu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	s.NotifyRoute(table.GetByPrefix(netip.MustParsePrefix("1.1.1.0/24"))[0])
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var rr RouteResponse
		if err := json.Unmarshal([]byte(line), &rr); err != nil {
			t.Fatal(err)
		}
		if rr.Timestamp != want {
			t.Errorf("watch timestamp %q, want %s", rr.Timestamp, want)
		}
		return
	}
	t.Fatalf("no event: %v", sc.Err())
}
