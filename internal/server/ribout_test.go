package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/api"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/buildinfo"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/events"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Adj-RIB-Out routes (RFC 8671) are stored apart from Adj-RIB-In: the same
// peer and prefix in both RIBs are two routes. They never enter what is
// counted as received (per-peer ROUTES, posture totals, raven_routes_total),
// get ROV but not inbound ASPA verification, and raise no events.
func TestAdjRIBOutKeptApart(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Validation.ROV = true
	s.eventEngine = events.NewEngine(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var emitted []events.Event
	s.testEmitted = func(ev events.Event) { emitted = append(emitted, ev) }
	s.vrpStore.ReplaceAll([]types.VRP{{Prefix: netip.MustParsePrefix("1.1.1.0/24"), ASN: 13335, MaxLength: 24}}, 1, 1)

	in := routerRoute(routerA, "1.1.1.0/24")
	out := routerRoute(routerA, "1.1.1.0/24")
	out.RIBType = types.AdjRIBOutPre
	s.ingestRoute(in, 1, 1)
	s.ingestRoute(out, 1, 2)

	gotIn, gotOut := s.table.Get(in.Key()), s.table.Get(out.Key())
	if gotIn == nil || gotOut == nil || s.table.Count() != 2 {
		t.Fatalf("table holds %d routes; in %v out %v", s.table.Count(), gotIn != nil, gotOut != nil)
	}
	if gotOut.ROV.State != types.ROVValid {
		t.Errorf("Adj-RIB-Out ROV = %s, want Valid (ROV applies)", gotOut.ROV.State)
	}
	if gotOut.ASPA.State != types.ASPAUnverifiable || !strings.Contains(gotOut.ASPA.Reason, "Adj-RIB-Out") {
		t.Errorf("Adj-RIB-Out ASPA = %s %q, want Unverifiable with an Adj-RIB-Out reason", gotOut.ASPA.State, gotOut.ASPA.Reason)
	}
	if gotIn.ASPA.State == types.ASPAUnverifiable {
		t.Errorf("Adj-RIB-In route was not ASPA-verified")
	}

	c := s.table.PeerRouteCounts()[in.Peer()]
	if c[types.AdjRIBInPre] != 1 || c[types.AdjRIBOutPre] != 1 {
		t.Errorf("per-peer counts %v, want 1 in and 1 out, apart", c)
	}
	var postures uint64
	for _, n := range s.table.CountByPosture() {
		postures += n
	}
	if postures != 1 {
		t.Errorf("posture totals count %d routes, want 1 (Adj-RIB-In pre-policy only)", postures)
	}

	s.updateRouteMetrics()
	if got := gaugeValue(t, "raven_routes_total", map[string]string{"posture": "origin-only", "afi": "ipv4", "rib": "adj-rib-in-pre"}); got != 1 {
		t.Errorf("raven_routes_total{origin-only,ipv4} = %v, want 1 (inbound only)", got)
	}
	if got := gaugeValue(t, "raven_adj_rib_out_routes_total", map[string]string{"posture": "origin-only", "afi": "ipv4"}); got != 1 {
		t.Errorf("raven_adj_rib_out_routes_total{origin-only,ipv4} = %v, want 1", got)
	}

	rec := httptest.NewRecorder()
	s.apiSrv.Mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	var st api.StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.RouteTable.TotalRoutes != 1 || st.RouteTable.ByRIB["adj-rib-in-pre"] != 1 || st.RouteTable.ByRIB["adj-rib-out-pre"] != 1 {
		t.Errorf("status route table %+v, want 1 received and by_rib in 1 / out 1", st.RouteTable)
	}

	if len(emitted) != 1 || emitted[0].Route.RIBType != types.AdjRIBInPre {
		t.Errorf("%d events emitted, want 1, for the Adj-RIB-In route only", len(emitted))
	}

	// Withdrawing the Adj-RIB-Out route leaves the Adj-RIB-In one.
	s.ingestWithdrawal(types.Withdrawal{Router: routerA, PeerAddr: rsPeer, Prefix: out.Prefix, RIBType: types.AdjRIBOutPre}, 1)
	if s.table.Get(out.Key()) != nil || s.table.Get(in.Key()) == nil {
		t.Error("withdrawing the Adj-RIB-Out route did not leave exactly the Adj-RIB-In one")
	}
}

// Route and withdrawal events name the monitored router in RouterID; they
// had the peer's BGP ID and the peer's address.
func TestEventRouterID(t *testing.T) {
	s := newTestServer(t)
	s.eventEngine = events.NewEngine(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var emitted []events.Event
	s.testEmitted = func(ev events.Event) { emitted = append(emitted, ev) }
	r := routerRoute(routerA, "1.1.1.0/24")
	r.RouterID = netip.MustParseAddr("10.9.9.9") // the peer's BGP identifier
	s.ingestRoute(r, 1, 1)
	s.ingestWithdrawal(types.Withdrawal{Router: routerA, PeerAddr: rsPeer, Prefix: r.Prefix}, 1)
	if len(emitted) != 2 {
		t.Fatalf("%d events, want a route and a withdrawal event", len(emitted))
	}
	for _, ev := range emitted {
		if ev.RouterID != routerA.String() {
			t.Errorf("%s event RouterID = %q, want the router %s", ev.Type, ev.RouterID, routerA)
		}
	}
}

// The daemon reports the build's version (the Makefile's -ldflags set
// buildinfo), the same raven version prints; it said "dev" whatever the build.
func TestStatusReportsBuildVersion(t *testing.T) {
	prev := buildinfo.Version
	buildinfo.Version = "v1.2.3-test"
	t.Cleanup(func() { buildinfo.Version = prev })
	s, err := New(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.apiSrv.Mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	var st api.StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Version != "v1.2.3-test" {
		t.Errorf("status version %q, want v1.2.3-test", st.Version)
	}
}
