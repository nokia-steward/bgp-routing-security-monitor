package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/snapshot"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// restoreVRPs and restoreRoutes are a warm start's data: one route of each
// ROV reason the VRPs give, stored as a snapshot stores them (state only).
var restoreVRPs = []types.VRP{
	{Prefix: netip.MustParsePrefix("1.1.1.0/24"), ASN: 13335, MaxLength: 24},
	{Prefix: netip.MustParsePrefix("8.8.8.0/24"), ASN: 15169, MaxLength: 24},
}

var restoreWant = map[string]types.ROVReasonCode{
	"1.1.1.0/24":     types.ROVReasonValid,
	"1.1.1.0/25":     types.ROVReasonInvalidLength,
	"8.8.8.0/24":     types.ROVReasonInvalidOrigin,
	"203.0.113.0/24": types.ROVReasonNotFound,
}

func restoreRoutes() []*types.Route {
	states := map[types.ROVReasonCode]types.ROVState{
		types.ROVReasonValid: types.ROVValid, types.ROVReasonInvalidLength: types.ROVInvalid,
		types.ROVReasonInvalidOrigin: types.ROVInvalid, types.ROVReasonNotFound: types.ROVNotFound,
	}
	origins := map[string]uint32{"1.1.1.0/24": 13335, "1.1.1.0/25": 13335, "8.8.8.0/24": 64666, "203.0.113.0/24": 64666}
	var out []*types.Route
	for p, code := range restoreWant {
		out = append(out, &types.Route{
			Router: routerA, PeerAddr: rsPeer, PeerASN: 6695, Prefix: netip.MustParsePrefix(p),
			ASPath: []uint32{6695, origins[p]}, RIBType: types.AdjRIBInPre,
			ROV: types.ROVResult{State: states[code]},
		})
	}
	return out
}

func writeSnapshots(t *testing.T, dir string, withRPKI bool) {
	t.Helper()
	w, err := snapshot.NewWriter(dir, Version)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRoutes(restoreRoutes()); err != nil {
		t.Fatal(err)
	}
	if withRPKI {
		if err := w.WriteRPKI(restoreVRPs, nil, 7); err != nil {
			t.Fatal(err)
		}
	}
}

// checkCodes checks that the routes have the reason codes their VRPs give.
func checkCodes(t *testing.T, routes []api.RouteResponse) {
	t.Helper()
	if len(routes) != len(restoreWant) {
		t.Fatalf("%d routes, want %d", len(routes), len(restoreWant))
	}
	for _, r := range routes {
		if want := restoreWant[r.Prefix].String(); r.ROVReasonCode != want {
			t.Errorf("restored %s: rov_reason_code %q, want %q", r.Prefix, r.ROVReasonCode, want)
		}
	}
}

func apiRoutes(t *testing.T, s *Server) []api.RouteResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	s.apiSrv.Mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil))
	var out []api.RouteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// #61: routes restored from a warm-start snapshot carry their ROV reason
// code at once, computed from the restored VRPs: no RTR sync, no
// revalidation. They used to have none until a revalidation reached them.
func TestRestoredRoutesHaveReasonCodes(t *testing.T) {
	dir := t.TempDir()
	writeSnapshots(t, dir, true)
	s, err := New(&config.Config{Persistence: config.PersistenceConfig{Enabled: true, SnapshotDir: dir}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.restoreSnapshots()
	checkCodes(t, apiRoutes(t, s))
	for _, r := range s.table.All() {
		if !r.Stale {
			t.Errorf("restored %s is not marked stale", r.Prefix)
		}
	}
}

// Without an RPKI snapshot there are no VRPs to compute the codes from at
// restore time: the routes wait, out of the table, until the first RTR sync
// has filled the VRP store, so no query sees them without a code; then they
// come in with it, before any BMP event.
func TestRestoredRoutesWaitForVRPs(t *testing.T) {
	dir := t.TempDir()
	writeSnapshots(t, dir, false)
	s, err := New(&config.Config{Persistence: config.PersistenceConfig{Enabled: true, SnapshotDir: dir}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.restoreSnapshots()
	if n := len(apiRoutes(t, s)); n != 0 || s.table.Count() != 0 {
		t.Fatalf("before any VRPs: the API lists %d routes, the table holds %d; want none", n, s.table.Count())
	}

	// Through serve: the first sync's VRPs give the codes.
	var vrps []rtrtest.VRP
	for _, v := range restoreVRPs {
		vrps = append(vrps, rtrtest.VRP{Prefix: v.Prefix, MaxLen: v.MaxLength, ASN: v.ASN})
	}
	h := startE2E(t, e2eConfig{vrps: vrps, snapshotDir: dir})
	h.ready()
	h.waitTable(len(restoreWant), "the held restored routes")
	resp, err := http.Get(h.api + "/api/v1/routes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var routes []api.RouteResponse
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		t.Fatal(err)
	}
	checkCodes(t, routes)
}

// A serve stopped before its first RTR sync writes the held routes back to
// the snapshot rather than an empty table.
func TestHeldRestoredRoutesSurviveShutdown(t *testing.T) {
	dir := t.TempDir()
	writeSnapshots(t, dir, false)
	h := startE2E(t, e2eConfig{snapshotDir: dir, cache: func(c *rtrtest.ServerConfig) {
		c.Unsupported = rtrtest.Stall // and MaxVersion 0 below: the cache never answers
		c.MaxVersion = 0
	}})
	h.stop()
	routes, err := snapshot.NewReader(dir, Version).ReadRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != len(restoreWant) {
		t.Errorf("snapshot after a stop before any RTR sync holds %d routes, want %d", len(routes), len(restoreWant))
	}
}
