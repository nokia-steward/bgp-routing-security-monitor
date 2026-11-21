package server

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// gaugeValue reads a gauge from the default Prometheus registry. labels must
// match the series' labels exactly; nil selects an unlabelled gauge.
func gaugeValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
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
			return m.GetGauge().GetValue()
		}
	}
	return 0
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func testRoute(peer netip.Addr, i int, posture types.SecurityPosture) *types.Route {
	return &types.Route{
		PeerAddr:        peer,
		Prefix:          netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 2, byte(i), 0}), 24),
		ASPath:          []uint32{64501, 65000 + uint32(i%3)},
		RIBType:         types.AdjRIBInPre,
		SecurityPosture: posture,
	}
}

// testWaitBound caps how long a test waits for a condition. It is not a
// timing assertion: it only stops a broken test from hanging, so it is far
// above anything a loaded machine under -race needs.
const testWaitBound = 60 * time.Second

// drain blocks until every event queued so far has been applied, including
// the withdraw-alls and revalidation passes ingestLoop applies a chunk at a
// time. The ingest stream
// is ordered, so once a marker route queued last is in the table, everything
// before it has been processed or queued for removal.
func drain(t *testing.T, s *Server) {
	t.Helper()
	marker := &types.Route{
		PeerAddr: netip.MustParseAddr("203.0.113.254"),
		Prefix:   netip.MustParsePrefix("203.0.113.0/24"),
		RIBType:  types.AdjRIBInPre,
	}
	s.table.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: marker.PeerAddr}, Prefix: marker.Prefix})
	s.ingestCh <- types.IngestEvent{Route: marker}
	key := types.RouteKey{Peer: types.PeerRef{Addr: marker.PeerAddr}, Prefix: marker.Prefix, RIBType: marker.RIBType}
	deadline := time.Now().Add(testWaitBound)
	for s.table.Get(key) == nil || s.removalsPending.Load() != 0 || s.revalidating.Load() {
		if time.Now().After(deadline) {
			t.Fatalf("ingest loop did not drain within %v", testWaitBound)
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.table.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: marker.PeerAddr}, Prefix: marker.Prefix})
}

// End to end through the ingest loop: a peer's routes are counted in the
// route table and raven_routes_total, and a peer-down removes all of them,
// from the table, the metrics and every index, leaving other peers intact.
func TestPeerDownRemovesPeerRoutes(t *testing.T) {
	s := newTestServer(t)
	close(s.rtrReady)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.ingestLoop(ctx)

	down := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")

	const n = 40
	for i := 0; i < n; i++ {
		posture := types.PostureOriginOnly
		if i%4 == 0 {
			posture = types.PostureOriginInvalid
		}
		s.ingestCh <- types.IngestEvent{Route: testRoute(down, i, posture)}
	}
	s.ingestCh <- types.IngestEvent{Route: testRoute(other, 0, types.PostureOriginInvalid)} // shares 10.2.0.0/24
	drain(t, s)

	s.updateRouteMetrics()
	if got := gaugeValue(t, "raven_route_table_size", map[string]string{"rib": "adj-rib-in-pre"}); got != n+1 {
		t.Fatalf("raven_route_table_size{rib=adj-rib-in-pre} = %v before peer down, want %d", got, n+1)
	}
	originOnly := map[string]string{"posture": "origin-only", "afi": "ipv4", "rib": "adj-rib-in-pre"}
	originInvalid := map[string]string{"posture": "origin-invalid", "afi": "ipv4", "rib": "adj-rib-in-pre"}
	if got := gaugeValue(t, "raven_routes_total", originOnly); got != 30 {
		t.Fatalf("raven_routes_total{origin-only} = %v before peer down, want 30", got)
	}
	if got := gaugeValue(t, "raven_routes_total", originInvalid); got != 11 {
		t.Fatalf("raven_routes_total{origin-invalid} = %v before peer down, want 11", got)
	}

	s.ingestCh <- types.IngestEvent{Withdrawal: &types.Withdrawal{PeerAddr: down, WithdrawAll: true}}
	drain(t, s)

	if got := s.table.Count(); got != 1 {
		t.Errorf("table count after peer down = %d, want 1 (the other peer's route)", got)
	}
	s.updateRouteMetrics()
	if got := gaugeValue(t, "raven_route_table_size", map[string]string{"rib": "adj-rib-in-pre"}); got != 1 {
		t.Errorf("raven_route_table_size{rib=adj-rib-in-pre} = %v after peer down, want 1", got)
	}
	if got := gaugeValue(t, "raven_routes_total", originOnly); got != 0 {
		t.Errorf("raven_routes_total{origin-only} = %v after peer down, want 0", got)
	}
	if got := gaugeValue(t, "raven_routes_total", originInvalid); got != 1 {
		t.Errorf("raven_routes_total{origin-invalid} = %v after peer down, want 1", got)
	}

	// Index-level checks, through the public queries: nothing of the downed
	// peer's is reachable by prefix, origin ASN or posture. (The routetable
	// package's own test inspects the raw indexes.)
	for i := 0; i < n; i++ {
		for _, r := range s.table.GetByPrefix(testRoute(down, i, "").Prefix) {
			if r.PeerAddr == down {
				t.Errorf("GetByPrefix still returns the downed peer's route for %s", r.Prefix)
			}
		}
	}
	for asn := uint32(65000); asn < 65003; asn++ {
		for _, r := range s.table.GetByOriginASN(asn) {
			if r.PeerAddr == down {
				t.Errorf("GetByOriginASN(%d) still returns the downed peer's route %s", asn, r.Prefix)
			}
		}
	}
	for _, p := range []types.SecurityPosture{types.PostureOriginOnly, types.PostureOriginInvalid} {
		for _, r := range s.table.GetByPosture(p) {
			if r.PeerAddr == down {
				t.Errorf("GetByPosture(%s) still returns the downed peer's route %s", p, r.Prefix)
			}
		}
	}
}

// The startup case that made the old split pipeline lose peer-downs every
// time: routes were held back until the first RTR sync while withdrawals were
// applied immediately, so a peer-down queued behind its own routes wiped an
// empty table and the routes were inserted afterwards. On one ordered stream
// the peer-down is applied after them.
func TestPeerDownQueuedBeforeRTRReadyIsAppliedAfterItsRoutes(t *testing.T) {
	s := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.ingestLoop(ctx) // blocked until rtrReady

	peer := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < 20; i++ {
		s.ingestCh <- types.IngestEvent{Route: testRoute(peer, i, types.PostureOriginOnly)}
	}
	s.ingestCh <- types.IngestEvent{Withdrawal: &types.Withdrawal{PeerAddr: peer, WithdrawAll: true}}

	// Give a loop that applies withdrawals early the chance to do so, then
	// confirm nothing at all was consumed before the first RTR sync.
	time.Sleep(50 * time.Millisecond)
	if queued := len(s.ingestCh); queued != 21 {
		t.Fatalf("%d of 21 events still queued before RTR ready, want all 21: nothing may be applied early", queued)
	}

	close(s.rtrReady)
	drain(t, s)

	if got := s.table.Count(); got != 0 {
		t.Errorf("table count = %d, want 0: the peer-down was queued after all its routes", got)
	}
}
