package server

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

func counterValue(t testing.TB, name string, labels map[string]string) float64 {
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
			for _, lp := range m.GetLabel() {
				if labels[lp.GetName()] != lp.GetValue() {
					continue metric
				}
			}
			if h := m.GetHistogram(); h != nil {
				return float64(h.GetSampleCount())
			}
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

// RTR deltas requested before ingestLoop takes them make one incremental
// pass over their union; an empty delta requests nothing. The pass is logged
// and counted with its mode.
func TestDeltaRequestsMakeOneIncrementalPass(t *testing.T) {
	s := newTestServer(t)
	s.engine.SetASPAUnavailable("") // as after an RTR version 2 sync: ASPA data to verify against
	var logs syncBuffer
	s.log = slog.New(slog.NewTextHandler(&logs, nil))
	peer := netip.MustParseAddr("192.0.2.1")
	fillValidated(s, peer, sessA, 1000) // benchRoute i: 1.0.i.0/24, path [64501 1+i]

	s.RequestRevalidationDelta(&store.Delta{})
	if n := len(s.revalidateCh); n != 0 {
		t.Fatalf("an empty delta queued %d requests, want 0", n)
	}

	v1 := types.VRP{Prefix: netip.MustParsePrefix("1.0.3.0/24"), ASN: 4, MaxLength: 24}
	v2 := types.VRP{Prefix: netip.MustParsePrefix("1.0.7.0/24"), ASN: 8, MaxLength: 24}
	s.vrpStore.AddVRP(v1)
	s.vrpStore.AddVRP(v2)
	s.vrpStore.RebuildIndex()
	s.aspaStore.AddProvider(11, 64501)
	checked0 := counterValue(t, "raven_revalidation_routes_total", map[string]string{"mode": "incremental", "result": "checked"})
	passes0 := counterValue(t, "raven_revalidation_duration_seconds", map[string]string{"mode": "incremental"})
	s.RequestRevalidationDelta(&store.Delta{VRPAnnounced: []types.VRP{v1}})
	s.RequestRevalidationDelta(&store.Delta{VRPAnnounced: []types.VRP{v2}, ASPACustomers: []uint32{11}})

	<-s.revalidateCh
	s.startRevalidation()
	if s.revalidation == nil || s.revalidation.Full {
		t.Fatal("no incremental pass started")
	}
	for s.revalidating.Load() {
		s.stepBackground()
	}
	if got := s.revalidationPasses.Load(); got != 1 {
		t.Errorf("%d passes, want 1", got)
	}
	for i, want := range map[int]types.ROVState{3: types.ROVValid, 7: types.ROVValid, 5: types.ROVNotFound} {
		if got := lookup2(s, peer, i).ROV.State; got != want {
			t.Errorf("route %d ROV = %s, want %s", i, got, want)
		}
	}
	if got := lookup2(s, peer, 10).ASPA.State; got != types.ASPAValid {
		t.Errorf("route 10 (path [64501 11]) ASPA = %s, want Valid", got)
	}
	if got := counterValue(t, "raven_revalidation_routes_total", map[string]string{"mode": "incremental", "result": "checked"}) - checked0; got != 3 {
		t.Errorf("checked counter rose by %v, want 3", got)
	}
	if got := counterValue(t, "raven_revalidation_duration_seconds", map[string]string{"mode": "incremental"}) - passes0; got != 1 {
		t.Errorf("duration histogram observed %v passes, want 1", got)
	}
	line := logs.String()
	for _, want := range []string{"re-validation complete", "mode=incremental", "candidates=3", "checked=3", "changed=3", "aspa_scanned=1000", "took="} {
		if !strings.Contains(line, want) {
			t.Errorf("log %q lacks %q", line, want)
		}
	}
}

var (
	incBenchOnce   sync.Once
	incBenchServer *Server
)

// BenchmarkRevalidationModes compares a full pass with incremental passes
// for a typical RTR delta on a table of 1M routes (benchRoute: 1.x.y.0/24,
// path [64501 X] with X one of 70k ASes; every route ROV-invalid under
// vrpsCovering). The delta announces, then on the next iteration withdraws,
// 45 /24 and 5 /20 VRPs that make their routes valid, plus aspa ASPA
// customers: a typical AS (in ~14 paths), or "hot", AS64501, in every path.
// pass-ms is the pass's own time (no ingest competing), max-step-ms the
// longest any ingest event could wait on it, candidates the routes selected.
//
//	go test -run '^$' -bench RevalidationModes -benchtime 10x ./internal/server/
func BenchmarkRevalidationModes(b *testing.B) {
	const n = 1_000_000
	incBenchOnce.Do(func() { incBenchServer = newBenchServer(b, n) })
	s := incBenchServer

	var vrps []types.VRP
	for i := 0; i < 45; i++ {
		j := 997 + i*20_011
		vrps = append(vrps, types.VRP{Prefix: benchRoute(netip.Addr{}, j, 0).Prefix, ASN: 1 + uint32(j%70_000), MaxLength: 24})
	}
	for i := 0; i < 5; i++ {
		j := 4096 + i*160_000 // a /20: 16 routes, all with different origins
		p, _ := benchRoute(netip.Addr{}, j, 0).Prefix.Addr().Prefix(20)
		vrps = append(vrps, types.VRP{Prefix: p, ASN: 1 + uint32(j%70_000), MaxLength: 24})
	}

	for _, tc := range []struct {
		name string
		full bool
		aspa []uint32
	}{
		{"mode=full", true, []uint32{12_345}},
		{"mode=incremental/aspa=0", false, nil},
		{"mode=incremental/aspa=1", false, []uint32{12_345}},
		{"mode=incremental/aspa=2", false, []uint32{12_345, 54_321}},
		{"mode=incremental/aspa=hot", false, []uint32{64501}},
	} {
		b.Run(fmt.Sprintf("routes=%d/%s", n, tc.name), func(b *testing.B) {
			var pass, maxStep, scan time.Duration
			var candidates, changed int
			announce := true
			b.ReportAllocs()
			b.ResetTimer()
			for it := 0; it < b.N; it++ {
				b.StopTimer()
				d := &store.Delta{ASPACustomers: tc.aspa}
				for _, v := range vrps {
					if announce {
						s.vrpStore.AddVRP(v)
					} else {
						s.vrpStore.RemoveVRP(v)
					}
				}
				for _, c := range tc.aspa {
					if announce {
						s.aspaStore.AddProvider(c, 64501)
					} else {
						s.aspaStore.RemoveProvider(c, 64501)
					}
				}
				s.vrpStore.RebuildIndex()
				if announce {
					d.VRPAnnounced = vrps
				} else {
					d.VRPWithdrawn = vrps
				}
				if tc.full {
					d = store.FullDelta()
				}
				announce = !announce
				b.StartTimer()

				start := time.Now()
				rv := s.engine.NewDeltaRevalidation(d)
				for {
					c := time.Now()
					done := rv.Step(revalidateChunk)
					maxStep = max(maxStep, time.Since(c))
					if done {
						break
					}
				}
				pass += time.Since(start)
				scan += rv.ASPAScanTime
				candidates += rv.Candidates
				changed += rv.Changed
			}
			b.StopTimer()
			b.ReportMetric(float64(pass.Microseconds())/1000/float64(b.N), "pass-ms")
			b.ReportMetric(float64(maxStep.Microseconds())/1000, "max-step-ms")
			b.ReportMetric(float64(scan.Microseconds())/1000/float64(b.N), "aspa-scan-ms")
			b.ReportMetric(float64(candidates)/float64(b.N), "candidates")
			b.ReportMetric(float64(changed)/float64(b.N), "changed")
		})
	}
}
