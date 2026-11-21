package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/api"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/events"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// locRIBRoute is a route of routerA's Loc-RIB: the zero peer address, the
// router's own AS as peer AS (RFC 9069).
func locRIBRoute(prefix string) types.Route {
	return types.Route{
		Router: routerA, PeerType: types.PeerTypeLocRIB, PeerAddr: netip.IPv4Unspecified(), PeerASN: 65000,
		LocalASN: 65000, Prefix: netip.MustParsePrefix(prefix), ASPath: []uint32{6695, 13335}, RIBType: types.LocRIB,
	}
}

// A Loc-RIB instance's Peer Down clears the Loc-RIB only, and a BGP peer's
// Peer Down its Adj-RIBs only, even for one peer reference holding both.
func TestPeerDownScopeByRIB(t *testing.T) {
	s := newTestServer(t)
	shared := netip.MustParseAddr("10.0.12.1")
	mk := func(rib types.RIBType) types.Route {
		r := routerRoute(routerA, "1.1.1.0/24")
		r.PeerAddr, r.RIBType = shared, rib
		return r
	}
	for i, rib := range types.AllRIBTypes {
		s.ingestRoute(mk(rib), 1, uint64(i+1))
	}
	loc := locRIBRoute("8.8.8.0/24")
	s.ingestRoute(loc, 1, 9)

	ribsLeft := func() (out []types.RIBType) {
		for _, rib := range types.AllRIBTypes {
			r := mk(rib)
			if s.table.Get(r.Key()) != nil {
				out = append(out, rib)
			}
		}
		return out
	}

	// Loc-RIB Peer Down for the shared reference: its Loc-RIB route only.
	s.ingestWithdrawal(types.Withdrawal{Router: routerA, PeerAddr: shared, RIBType: types.LocRIB, WithdrawAll: true}, 1)
	applyRemovals(s)
	if got, want := ribsLeft(), []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost, types.AdjRIBOutPre, types.AdjRIBOutPost}; !slices.Equal(got, want) {
		t.Errorf("after a Loc-RIB Peer Down: RIBs left %v, want %v", got, want)
	}
	if s.table.Get(loc.Key()) == nil {
		t.Error("another Loc-RIB (the zero address) was removed")
	}

	// BGP Peer Down: the Adj-RIBs.
	s.ingestWithdrawal(types.Withdrawal{Router: routerA, PeerAddr: shared, WithdrawAll: true}, 1)
	applyRemovals(s)
	if got := ribsLeft(); len(got) != 0 {
		t.Errorf("after a BGP Peer Down: RIBs left %v, want none", got)
	}

	// The real Loc-RIB, at the zero address: a BGP Peer Down there would
	// leave it; its own Peer Down removes it.
	s.ingestWithdrawal(types.Withdrawal{Router: routerA, PeerAddr: loc.PeerAddr, WithdrawAll: true}, 1)
	applyRemovals(s)
	if s.table.Get(loc.Key()) == nil {
		t.Error("a BGP-scoped withdraw-all removed a Loc-RIB route")
	}
	s.ingestWithdrawal(types.Withdrawal{Router: routerA, PeerAddr: loc.PeerAddr, RIBType: types.LocRIB, WithdrawAll: true}, 1)
	applyRemovals(s)
	if s.table.Get(loc.Key()) != nil || s.table.Count() != 0 {
		t.Errorf("after the Loc-RIB Peer Down: %d routes left, want none", s.table.Count())
	}
}

// A router that sends only its Loc-RIB shows its routes: route queries and
// the status totals default to the default view, Adj-RIB-In pre-policy plus
// Loc-RIB; post-policy and Adj-RIB-Out stay out unless asked for.
func TestDefaultViewIncludesLocRIB(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Validation.ROV = true // every route gets a posture: unverified, with no VRP
	s.ingestRoute(locRIBRoute("1.1.1.0/24"), 1, 1)
	s.ingestRoute(locRIBRoute("8.8.8.0/24"), 1, 2)
	pre := routerRoute(routerB, "1.1.1.0/24")
	post := routerRoute(routerB, "1.1.1.0/24")
	post.RIBType = types.AdjRIBInPost
	s.ingestRoute(pre, 2, 3)
	s.ingestRoute(post, 2, 4)

	ribs := func(rs []api.RouteResponse) (out []string) {
		for _, r := range rs {
			out = append(out, r.RIB)
		}
		slices.Sort(out)
		return out
	}
	for q, want := range map[string][]string{
		"":                                       {"adj-rib-in-pre", "loc-rib", "loc-rib"},
		"router=" + routerA.String():             {"loc-rib", "loc-rib"},
		"prefix=1.1.1.0/24":                      {"adj-rib-in-pre", "loc-rib"},
		"origin-asn=13335":                       {"adj-rib-in-pre", "loc-rib", "loc-rib"},
		"posture=unverified":                     {"adj-rib-in-pre", "loc-rib", "loc-rib"},
		"rib=post-policy":                        {"adj-rib-in-post"},
		"rib=adj-rib-in-post,pre-policy":         {"adj-rib-in-post", "adj-rib-in-pre"},
		"rib=loc-rib&posture=unverified":         {"loc-rib", "loc-rib"},
		"rib=adj-rib-in-post&posture=unverified": {"adj-rib-in-post"},
	} {
		if got := ribs(routesVia(t, s, q)); !slices.Equal(got, want) {
			t.Errorf("routes?%s: RIBs %v, want %v", q, got, want)
		}
	}
	if r := routesVia(t, s, "router="+routerA.String()); len(r) == 0 || r[0].PeerType != "loc-rib" || r[0].PeerAddr != "0.0.0.0" {
		t.Errorf("Loc-RIB route JSON %+v, want peer_type loc-rib, peer 0.0.0.0", r)
	}

	rec := httptest.NewRecorder()
	s.apiSrv.Mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	var st api.StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	rt := st.RouteTable
	if rt.TotalRoutes != 3 || !slices.Equal(rt.DefaultView, []string{"adj-rib-in-pre", "loc-rib"}) {
		t.Errorf("status total %d over %v, want 3 over [adj-rib-in-pre loc-rib]", rt.TotalRoutes, rt.DefaultView)
	}
	if rt.ByPosture["unverified"] != 3 {
		t.Errorf("status by_posture %v, want unverified 3 (the default view)", rt.ByPosture)
	}
	if rt.ByRIB["loc-rib"] != 2 || rt.ByRIB["adj-rib-in-pre"] != 1 || rt.ByRIB["adj-rib-in-post"] != 1 {
		t.Errorf("status by_rib %v, want loc-rib 2, adj-rib-in-pre 1, adj-rib-in-post 1", rt.ByRIB)
	}
}

// gaugeExists reports whether a gauge series with exactly these labels
// exists.
func gaugeExists(t *testing.T, name string, labels map[string]string) bool {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	metric:
		for _, m := range mf.GetMetric() {
			if len(m.GetLabel()) != len(labels) {
				continue
			}
			for _, lp := range m.GetLabel() {
				if labels[lp.GetName()] != lp.GetValue() {
					continue metric
				}
			}
			return true
		}
	}
	return false
}

// raven_routes_total and raven_route_table_size count adj-rib-in-pre,
// adj-rib-in-post and loc-rib apart under a rib label, every label set
// existing at 0; Adj-RIB-Out routes stay in their own gauge.
func TestRoutesTotalRIBLabel(t *testing.T) {
	for _, rib := range metrics.RouteRIBs {
		for _, posture := range metrics.Postures {
			for _, afi := range metrics.AFIs {
				if !gaugeExists(t, "raven_routes_total", map[string]string{"posture": posture, "afi": afi, "rib": rib}) {
					t.Errorf("raven_routes_total{posture=%q,afi=%q,rib=%q} not created at 0", posture, afi, rib)
				}
			}
		}
		if !gaugeExists(t, "raven_route_table_size", map[string]string{"rib": rib}) {
			t.Errorf("raven_route_table_size{rib=%q} not created at 0", rib)
		}
	}
	var names []string
	for _, r := range metricRIBs {
		names = append(names, r.String())
	}
	if !slices.Equal(names, metrics.RouteRIBs) {
		t.Errorf("server counts RIBs %v, metrics labels %v: they must agree", names, metrics.RouteRIBs)
	}

	s := newTestServer(t)
	s.ingestRoute(locRIBRoute("1.1.1.0/24"), 1, 1)
	s.ingestRoute(locRIBRoute("8.8.8.0/24"), 1, 2)
	for i, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost, types.AdjRIBOutPre} {
		r := routerRoute(routerB, "1.1.1.0/24")
		r.RIBType = rib
		s.ingestRoute(r, 2, uint64(10+i))
	}
	s.updateRouteMetrics()
	label := func(rib string) map[string]string {
		return map[string]string{"posture": "unverified", "afi": "ipv4", "rib": rib}
	}
	for rib, want := range map[string]float64{"loc-rib": 2, "adj-rib-in-pre": 1, "adj-rib-in-post": 1} {
		if got := gaugeValue(t, "raven_routes_total", label(rib)); got != want {
			t.Errorf("raven_routes_total{rib=%q} = %v, want %v", rib, got, want)
		}
	}
	if gaugeExists(t, "raven_routes_total", label("adj-rib-out-pre")) {
		t.Error("raven_routes_total has an adj-rib-out-pre series; Adj-RIB-Out has its own gauge")
	}
	if got := gaugeValue(t, "raven_adj_rib_out_routes_total", map[string]string{"posture": "unverified", "afi": "ipv4"}); got != 1 {
		t.Errorf("raven_adj_rib_out_routes_total = %v, want 1", got)
	}
	for rib, want := range map[string]float64{"loc-rib": 2, "adj-rib-in-pre": 1, "adj-rib-in-post": 1} {
		if got := gaugeValue(t, "raven_route_table_size", map[string]string{"rib": rib}); got != want {
			t.Errorf("raven_route_table_size{rib=%q} = %v, want %v", rib, got, want)
		}
	}
	if gaugeExists(t, "raven_route_table_size", map[string]string{"rib": "adj-rib-out-pre"}) {
		t.Error("raven_route_table_size has an adj-rib-out-pre series")
	}
	if gaugeExists(t, "raven_route_table_size", nil) {
		t.Error("raven_route_table_size has an unlabelled series")
	}

	// The OTel view of the same counts.
	got := map[string]int64{}
	for _, c := range s.RouteCounts() {
		got[c.RIB+"/"+c.Posture+"/"+c.AFI] += c.Count
	}
	want := map[string]int64{"loc-rib/unverified/ipv4": 2, "adj-rib-in-pre/unverified/ipv4": 1, "adj-rib-in-post/unverified/ipv4": 1}
	if len(got) != len(want) {
		t.Errorf("RouteCounts %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("RouteCounts[%s] = %d, want %d", k, got[k], n)
		}
	}
}

// A Loc-RIB withdrawal raises its route_withdraw event, with the Loc-RIB
// route: the withdrawn route is looked up in the withdrawal's own RIB.
func TestLocRIBWithdrawEvent(t *testing.T) {
	s := newTestServer(t)
	s.eventEngine = events.NewEngine(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var emitted []events.Event
	s.testEmitted = func(ev events.Event) { emitted = append(emitted, ev) }
	loc := locRIBRoute("1.1.1.0/24")
	s.ingestRoute(loc, 1, 1)
	s.ingestWithdrawal(types.Withdrawal{Router: routerA, PeerAddr: loc.PeerAddr, Prefix: loc.Prefix, RIBType: types.LocRIB}, 1)
	if len(emitted) != 2 || emitted[1].Type != events.EventTypeRouteWithdraw || emitted[1].Route.RIBType != types.LocRIB {
		t.Fatalf("events %+v, want a new-route and a route_withdraw event for the Loc-RIB route", emitted)
	}
}
