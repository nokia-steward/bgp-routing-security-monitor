package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/api"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/snapshot"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

var (
	routerA = netip.MustParseAddr("192.0.2.1")
	routerB = netip.MustParseAddr("192.0.2.2")
	rsPeer  = netip.MustParseAddr("80.81.194.180") // a route server both routers peer with
)

func routerRoute(router netip.Addr, prefix string) types.Route {
	return types.Route{
		Router: router, PeerAddr: rsPeer, PeerASN: 6695, Prefix: netip.MustParsePrefix(prefix),
		ASPath: []uint32{6695, 13335}, RIBType: types.AdjRIBInPre,
	}
}

// applyRemovals finishes the withdraw-alls ingest has queued, as ingestLoop
// does between events.
func applyRemovals(s *Server) {
	for len(s.removals) > 0 {
		s.stepRemovals()
	}
}

func routesVia(t *testing.T, s *Server, q string) []api.RouteResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	s.apiSrv.Mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routes?"+q, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET routes?%s: %d %s", q, rec.Code, rec.Body)
	}
	var out []api.RouteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Two routers at one IXP both learn 1.1.1.0/24 from the same route server:
// both routes are kept, counted per router, and --router picks each.
func TestTwoRoutersSamePeerAndPrefix(t *testing.T) {
	s := newTestServer(t)
	s.ingestRoute(routerRoute(routerA, "1.1.1.0/24"), 1, 1)
	s.ingestRoute(routerRoute(routerB, "1.1.1.0/24"), 2, 2)
	s.ingestRoute(routerRoute(routerB, "8.8.8.0/24"), 2, 3)

	if n := s.table.Count(); n != 3 {
		t.Fatalf("table holds %d routes, want 3: routers overwrote each other", n)
	}
	counts := s.table.PeerRouteCounts()
	a, b := types.NewPeerRef(routerA, 0, rsPeer), types.NewPeerRef(routerB, 0, rsPeer)
	if counts[a][types.AdjRIBInPre] != 1 || counts[b][types.AdjRIBInPre] != 2 {
		t.Errorf("counts router A %d, router B %d; want 1 and 2", counts[a][types.AdjRIBInPre], counts[b][types.AdjRIBInPre])
	}
	for router, want := range map[netip.Addr]int{routerA: 1, routerB: 2} {
		got := routesVia(t, s, "router="+router.String())
		if len(got) != want {
			t.Errorf("router=%s: %d routes, want %d", router, len(got), want)
		}
		for _, r := range got {
			if r.Router != router.String() {
				t.Errorf("router=%s returned a route from %s", router, r.Router)
			}
		}
	}
	if got := routesVia(t, s, "router="+routerB.String()+"&prefix=1.1.1.0/24&peer="+rsPeer.String()); len(got) != 1 {
		t.Errorf("router, prefix and peer combined: %d routes, want 1", len(got))
	}
}

// A peer-down, or the end of the BMP session, on router A leaves router B's
// routes from the same peer address, and their count, intact.
func TestPeerDownAndSessionEndStayOnTheirRouter(t *testing.T) {
	s := newTestServer(t)
	const sessA, sessB = 1, 2
	for i, p := range []string{"1.1.1.0/24", "8.8.8.0/24"} {
		s.ingestRoute(routerRoute(routerA, p), sessA, uint64(i))
		s.ingestRoute(routerRoute(routerB, p), sessB, uint64(i))
	}
	bRef := types.NewPeerRef(routerB, 0, rsPeer)
	check := func(step string, wantA uint64) {
		t.Helper()
		counts := s.table.PeerRouteCounts()
		if counts[bRef][types.AdjRIBInPre] != 2 || counts[types.NewPeerRef(routerA, 0, rsPeer)][types.AdjRIBInPre] != wantA {
			t.Errorf("%s: counts A %d B %d, want %d and 2", step, counts[types.NewPeerRef(routerA, 0, rsPeer)][types.AdjRIBInPre], counts[bRef][types.AdjRIBInPre], wantA)
		}
		for _, p := range []string{"1.1.1.0/24", "8.8.8.0/24"} {
			r := routerRoute(routerB, p)
			if s.table.Get(r.Key()) == nil {
				t.Errorf("%s: router B's %s is gone", step, p)
			}
		}
	}

	s.ingestWithdrawal(types.Withdrawal{Router: routerA, PeerAddr: rsPeer, WithdrawAll: true}, sessA)
	applyRemovals(s)
	check("peer down on router A", 0)

	s.ingestRoute(routerRoute(routerA, "1.1.1.0/24"), sessA, 9)
	s.ingestWithdrawal(types.Withdrawal{SessionEnd: true}, sessA)
	applyRemovals(s)
	check("session end on router A", 0)

	r := routerRoute(routerB, "8.8.8.0/24")
	w := types.Withdrawal{Router: routerB, PeerAddr: rsPeer, Prefix: r.Prefix, RIBType: types.AdjRIBInPre}
	s.ingestWithdrawal(w, sessB)
	if s.table.Get(r.Key()) != nil || s.table.PeerRouteCounts()[bRef][types.AdjRIBInPre] != 1 {
		t.Error("a withdrawal on router B did not remove router B's route")
	}
}

// A route snapshot in the old format (no format_version: peer, prefix and
// RIB type only) is not migrated: RAVEN warns and starts the route table
// cold, and still restores the RPKI snapshot. A current snapshot restores
// routes from two routers apart.
func TestOldFormatRouteSnapshotColdStarts(t *testing.T) {
	dir := t.TempDir()
	w, err := snapshot.NewWriter(dir, Version)
	if err != nil {
		t.Fatal(err)
	}
	vrp := types.VRP{Prefix: netip.MustParsePrefix("1.1.1.0/24"), ASN: 13335, MaxLength: 24}
	if err := w.WriteRPKI([]types.VRP{vrp}, nil, 7); err != nil {
		t.Fatal(err)
	}
	old := `{"snapshot_time_unix":1,"raven_version":"` + Version + `","routes":[` +
		`{"prefix":"1.1.1.0/24","peer_addr":"80.81.194.180","peer_asn":6695,"rib_type":"adj-rib-in-pre"}]}`
	if err := os.WriteFile(filepath.Join(dir, "routes.snap"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}

	restore := func() (*Server, string) {
		var logs bytes.Buffer
		s, err := New(&config.Config{Persistence: config.PersistenceConfig{Enabled: true, SnapshotDir: dir}},
			slog.New(slog.NewTextHandler(&logs, nil)))
		if err != nil {
			t.Fatal(err)
		}
		s.restoreSnapshots()
		return s, logs.String()
	}
	s, logs := restore()
	if s.table.Count() != 0 {
		t.Errorf("old-format snapshot restored %d routes, want a cold start", s.table.Count())
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "older format") {
		t.Errorf("no WARN about the old format:\n%s", logs)
	}
	if s.vrpStore.Count() != 1 {
		t.Errorf("RPKI snapshot not restored alongside: %d VRPs", s.vrpStore.Count())
	}

	a, b := routerRoute(routerA, "1.1.1.0/24"), routerRoute(routerB, "1.1.1.0/24")
	b.PeerDistinguisher, b.PathID = 0x0000fde8_00000064, 3
	if err := w.WriteRoutes([]*types.Route{&a, &b}); err != nil {
		t.Fatal(err)
	}
	s, _ = restore()
	if s.table.Count() != 2 || s.table.Get(a.Key()) == nil || s.table.Get(b.Key()) == nil {
		t.Errorf("current-format snapshot restored %d routes; A %v B %v", s.table.Count(),
			s.table.Get(a.Key()) != nil, s.table.Get(b.Key()) != nil)
	}
}
