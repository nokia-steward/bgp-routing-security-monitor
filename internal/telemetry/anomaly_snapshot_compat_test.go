package telemetry

import (
	"encoding/json"
	"math"
	"os"
	"sort"
	"testing"
	"time"
)

// testdata/anomaly_snapshot_v0.4.0.json was written by v0.4.0's own
// Detector.Save, before the scale floors and ObserveSyncTotals: a
// timer-driven cache (fort, 300 syncs, windows partly filled, ASPA windows
// constant 0) and a notify-driven one (routinator, 620 syncs, windows
// wrapped). The on-disk format is unchanged (schema_version 1): totals are
// not persisted, each sync brings its own.
const v040Snapshot = "testdata/anomaly_snapshot_v0.4.0.json"

const (
	v040Timer  = "fort.example.net:323"
	v040Notify = "routinator.example.net:3323"
)

// A snapshot from the previous release loads, and every window comes back
// as saved: same position, fullness and contents (so the same median and
// MAD).
func TestLoadV040SnapshotKeepsWindows(t *testing.T) {
	raw, err := os.ReadFile(v040Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var file anomalySnapshotFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.SchemaVersion != 1 || len(file.Caches) != 2 {
		t.Fatalf("fixture: schema %d, %d caches; want schema 1, 2 caches", file.SchemaVersion, len(file.Caches))
	}

	d := NewDetector(DefaultAnomalyConfig())
	if err := d.Load(v040Snapshot); err != nil {
		t.Fatalf("Load of a v0.4.0 snapshot: %v", err)
	}
	for cache, metrics := range file.Caches {
		if len(metrics) != len(trackedMetrics) {
			t.Errorf("%s: fixture has %d windows, want %d", cache, len(metrics), len(trackedMetrics))
		}
		for metric, snap := range metrics {
			w := d.window(cache, metric)
			if w == nil {
				t.Errorf("%s/%s: window not restored", cache, metric)
				continue
			}
			n := snap.Pos
			if snap.Filled {
				n = len(snap.Values)
			}
			wantMed, wantMAD := medianMADOf(snap.Values[:n])
			med, mad, ok := w.medianMAD()
			if !ok || w.count() != n || w.pos != snap.Pos || w.filled != snap.Filled || med != wantMed || mad != wantMAD {
				t.Errorf("%s/%s: restored count %d pos %d filled %t median %v MAD %v; saved count %d pos %d filled %t median %v MAD %v",
					cache, metric, w.count(), w.pos, w.filled, med, mad, n, snap.Pos, snap.Filled, wantMed, wantMAD)
			}
		}
	}
	// The fixture covers both shapes of window.
	if w := d.window(v040Timer, MetricVRPAnnounced); w.filled || w.count() != 300 {
		t.Errorf("%s: count %d filled %t, want a partly filled window of 300", v040Timer, w.count(), w.filled)
	}
	if w := d.window(v040Notify, MetricVRPAnnounced); !w.filled || w.pos != 620-DefaultAnomalyConfig().WindowSize {
		t.Errorf("%s: pos %d filled %t, want a wrapped window at pos %d", v040Notify, w.pos, w.filled, 620-DefaultAnomalyConfig().WindowSize)
	}
}

// medianMADOf computes median and MAD independently of metricWindow.
func medianMADOf(vals []float64) (median, mad float64) {
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	median = medianOfSorted(s)
	devs := make([]float64, len(s))
	for i, v := range s {
		devs[i] = math.Abs(v - median)
	}
	sort.Float64s(devs)
	return median, medianOfSorted(devs)
}

// After loading a v0.4.0 snapshot, with no totals known yet (Totals{}), the
// VRP and ASPA floors are their absolute minimum of 1 and every scale is
// positive, so z is finite, also for the windows whose MAD is exactly 0 (the
// timer-driven cache's ASPA windows, constant 0). An ordinary first sync
// does not trip and is taken into the windows; once a sync supplies totals,
// the floors follow them.
func TestV040SnapshotFirstSyncWithoutTotals(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	if err := d.Load(v040Snapshot); err != nil {
		t.Fatal(err)
	}

	sawMADZero := false
	for _, cache := range []string{v040Timer, v040Notify} {
		for _, metric := range trackedMetrics {
			med, mad, _ := d.window(cache, metric).medianMAD()
			sawMADZero = sawMADZero || mad == 0
			s := scale(metric, med, mad, Totals{})
			if s <= 0 || math.IsInf(s, 0) || math.IsNaN(s) {
				t.Errorf("%s/%s: scale %v with no totals, want positive and finite", cache, metric, s)
			}
			if z := modifiedZ(med+1, med, s); math.IsInf(z, 0) || math.IsNaN(z) {
				t.Errorf("%s/%s: z %v, want finite", cache, metric, z)
			}
			switch metric {
			case MetricVRPAnnounced, MetricVRPWithdrawn, MetricASPAAnnounced, MetricASPAWithdrawn:
				if got := minScale(metric, med, Totals{}); got != 1 {
					t.Errorf("%s/%s: floor %v with no totals, want the absolute minimum 1", cache, metric, got)
				}
			}
		}
	}
	if !sawMADZero {
		t.Fatal("fixture has no MAD 0 window: it does not exercise the floor at its minimum")
	}

	// The first sync after a restart, without totals: ordinary values for
	// each cache. No trip, and each value enters its window.
	first := map[string]map[string]float64{
		v040Timer: {
			MetricIntervalSince: float64(600*time.Second + 2*time.Millisecond),
			MetricSyncDuration:  float64(740 * time.Millisecond), // the Fort notify-driven sync
			MetricVRPAnnounced:  2, MetricVRPWithdrawn: 1,
			MetricASPAAnnounced: 1, MetricASPAWithdrawn: 0,
		},
		v040Notify: {
			MetricIntervalSince: float64(900 * time.Second),
			MetricSyncDuration:  float64(12 * time.Second),
			MetricVRPAnnounced:  1100, MetricVRPWithdrawn: 880,
			MetricASPAAnnounced: 1, MetricASPAWithdrawn: 0,
		},
	}
	ts := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for cache, m := range first {
		before := map[string]int{}
		for _, metric := range trackedMetrics {
			before[metric] = d.window(cache, metric).count()
		}
		if ev := d.ObserveSync(cache, ts, m); ev != nil {
			t.Errorf("%s: first sync after loading the v0.4.0 snapshot tripped: %+v", cache, ev)
		}
		for _, metric := range trackedMetrics {
			w := d.window(cache, metric)
			want := min(before[metric]+1, w.cap)
			if got := w.count(); got != want {
				t.Errorf("%s/%s: count %d -> %d, want the value taken in", cache, metric, before[metric], got)
			}
		}
	}

	// A sync that supplies totals: the VRP floor is now relative (100 on 1M
	// VRPs). Ordinary churn stays quiet, a 1,200-VRP burst trips.
	totals := Totals{VRPs: 1_000_000, ASPAs: 1_000}
	med, _, _ := d.window(v040Timer, MetricVRPAnnounced).medianMAD()
	if got := minScale(MetricVRPAnnounced, med, totals); got != 100 {
		t.Fatalf("VRP floor with 1M VRPs = %v, want 100", got)
	}
	quiet := map[string]float64{MetricVRPAnnounced: 23, MetricVRPWithdrawn: 23}
	if ev := d.ObserveSyncTotals(v040Timer, ts.Add(10*time.Minute), quiet, totals); ev != nil {
		t.Errorf("23/23 churn on 1M VRPs tripped: %+v", ev)
	}
	burst := map[string]float64{MetricVRPAnnounced: 1200}
	if ev := d.ObserveSyncTotals(v040Timer, ts.Add(20*time.Minute), burst, totals); ev == nil || ev.Trigger != MetricVRPAnnounced {
		t.Errorf("1,200-VRP burst after loading: %+v, want a trip on %s", ev, MetricVRPAnnounced)
	}
}
