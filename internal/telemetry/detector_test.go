package telemetry

import (
	"math"
	"testing"
	"time"
)

const testCache = "localhost:3323"

// warmUp feeds n syncs, each carrying the given metric set produced by gen(i),
// through the detector and fails if any of them (unexpectedly) trips. It is
// used to bring windows past WarmupMinimum with in-baseline values.
func warmUp(t *testing.T, d *Detector, n int, gen func(i int) map[string]float64) {
	t.Helper()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < n; i++ {
		ev := d.ObserveSync(testCache, base.Add(time.Duration(i)*time.Second), gen(i))
		if ev != nil {
			t.Fatalf("warm-up sync %d unexpectedly tripped: %+v", i, ev)
		}
	}
}

// window reaches into the detector's internal state for assertions. Same
// package, so unexported fields are accessible.
func (d *Detector) window(cache, metric string) *metricWindow {
	d.mu.Lock()
	defer d.mu.Unlock()
	if cw := d.windows[cache]; cw != nil {
		return cw[metric]
	}
	return nil
}

func TestMetricWindowFillAndWrap(t *testing.T) {
	w := newMetricWindow(3)

	if got := w.count(); got != 0 {
		t.Fatalf("empty window count = %d, want 0", got)
	}
	if _, _, ok := w.medianMAD(); ok {
		t.Fatal("medianMAD on empty window should report ok == false")
	}

	w.add(1)
	w.add(2)
	if got := w.count(); got != 2 {
		t.Fatalf("count after 2 adds = %d, want 2", got)
	}
	if w.filled {
		t.Fatal("window should not be filled after 2 of 3 adds")
	}

	w.add(3)
	if got := w.count(); got != 3 {
		t.Fatalf("count after 3 adds = %d, want 3", got)
	}
	if !w.filled {
		t.Fatal("window should be filled after 3 of 3 adds")
	}
	if w.pos != 0 {
		t.Fatalf("pos after wrap boundary = %d, want 0", w.pos)
	}

	// Wrap: overwrite the oldest value (1) with 4. Contents become {4,2,3}.
	w.add(4)
	if got := w.count(); got != 3 {
		t.Fatalf("count stays capped = %d, want 3", got)
	}
	median, _, ok := w.medianMAD()
	if !ok {
		t.Fatal("medianMAD ok == false after wrap")
	}
	if median != 3 { // median of {2,3,4}; the evicted 1 must not appear
		t.Fatalf("median after wrap = %v, want 3 (evicted value 1 leaked)", median)
	}
}

func TestModifiedZ(t *testing.T) {
	z := modifiedZ(10, 4, 2)
	want := 0.6745 * (10 - 4) / 2
	if math.Abs(z-want) > 1e-9 {
		t.Fatalf("modifiedZ = %v, want %v", z, want)
	}
}

// The scale is max(MAD, floor), the floor per statistic: max(1% of the
// median, 1 s) for timings, max(1, 0.01% of VRPs held) for VRP counts,
// max(1, 0.1% of ASPAs held) for ASPA counts. MAD 0 takes the floor.
func TestScaleFloors(t *testing.T) {
	sec := float64(time.Second)
	for _, tc := range []struct {
		metric      string
		median, mad float64
		totals      Totals
		want        float64
	}{
		{MetricSyncDuration, 0.106 * sec, 0.0013 * sec, Totals{}, sec},             // Fort: 1 s floor
		{MetricIntervalSince, 600.106 * sec, 0.005 * sec, Totals{}, 6.00106 * sec}, // Fort: 1% of 600 s
		{MetricIntervalSince, 900 * sec, 30 * sec, Totals{}, 30 * sec},             // MAD above the floor
		{MetricIntervalSince, 600 * sec, 0, Totals{}, 6 * sec},                     // MAD 0
		{MetricVRPWithdrawn, 2, 2, Totals{VRPs: 1_000_000}, 100},                   // DaKnObNET
		{MetricVRPAnnounced, 0, 0, Totals{}, 1},                                    // empty cache
		{MetricVRPAnnounced, 20, 300, Totals{VRPs: 1_000_000}, 300},                // MAD above
		{MetricASPAAnnounced, 0, 0, Totals{ASPAs: 5000}, 5},                        // 0.1% of ASPAs
		{MetricASPAWithdrawn, 0, 0, Totals{ASPAs: 300, VRPs: 1_000_000}, 1},        // floor of 1
	} {
		if got := scale(tc.metric, tc.median, tc.mad, tc.totals); math.Abs(got-tc.want) > 1e-6*tc.want {
			t.Errorf("scale(%s, median %v, mad %v, %+v) = %v, want %v", tc.metric, tc.median, tc.mad, tc.totals, got, tc.want)
		}
	}
}

func TestNoAnomalyBeforeWarmup(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	base := time.Unix(1_700_000_000, 0)

	// Feed one fewer than WarmupMinimum, including a wildly out-of-range value.
	for i := 0; i < DefaultAnomalyConfig().WarmupMinimum-1; i++ {
		v := float64(20 + i%7)
		if i == 50 {
			v = 100000 // extreme, but must not trip: still in warm-up
		}
		ev := d.ObserveSync(testCache, base.Add(time.Duration(i)*time.Second),
			map[string]float64{MetricVRPWithdrawn: v})
		if ev != nil {
			t.Fatalf("sync %d tripped during warm-up: %+v", i, ev)
		}
	}
	if got := d.window(testCache, MetricVRPWithdrawn).count(); got != DefaultAnomalyConfig().WarmupMinimum-1 {
		t.Fatalf("window count = %d, want %d", got, DefaultAnomalyConfig().WarmupMinimum-1)
	}
}

func TestInBaselineValueNoTrip(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	warmUp(t, d, 150, func(i int) map[string]float64 {
		return map[string]float64{MetricVRPWithdrawn: float64(20 + i%9)}
	})

	// A value squarely inside the baseline range must not trip once warm.
	ev := d.ObserveSync(testCache, time.Unix(1_700_100_000, 0),
		map[string]float64{MetricVRPWithdrawn: 24})
	if ev != nil {
		t.Fatalf("in-baseline value tripped: %+v", ev)
	}
}

func TestHardTripExcludedFromWindow(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	warmUp(t, d, 150, func(i int) map[string]float64 {
		return map[string]float64{MetricVRPWithdrawn: float64(20 + i%9)}
	})

	w := d.window(testCache, MetricVRPWithdrawn)
	countBefore := w.count()
	medBefore, madBefore, _ := w.medianMAD()

	ev := d.ObserveSync(testCache, time.Unix(1_700_100_000, 0),
		map[string]float64{MetricVRPWithdrawn: 5000})
	if ev == nil {
		t.Fatal("wildly out-of-range value did not trip")
	}
	if ev.Category != "statistical" || ev.Severity != "high" {
		t.Fatalf("got category=%q severity=%q, want statistical/high", ev.Category, ev.Severity)
	}
	if ev.Trigger != MetricVRPWithdrawn {
		t.Fatalf("trigger = %q, want %q", ev.Trigger, MetricVRPWithdrawn)
	}
	if _, ok := ev.ZScores[MetricVRPWithdrawn]; !ok {
		t.Fatal("hard-trip event should carry the tripping metric's z-score")
	}
	if ev.Raw[MetricVRPWithdrawn] != 5000 {
		t.Fatalf("raw value = %v, want 5000", ev.Raw[MetricVRPWithdrawn])
	}

	// The anomalous value must not have entered the window.
	if got := w.count(); got != countBefore {
		t.Fatalf("window count changed after hard trip: %d -> %d", countBefore, got)
	}
	medAfter, madAfter, _ := w.medianMAD()
	if medAfter != medBefore || madAfter != madBefore {
		t.Fatalf("window stats changed after hard trip: median %v->%v, mad %v->%v",
			medBefore, medAfter, madBefore, madAfter)
	}
}

func TestCorrelatedTrip(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	// Warm two metrics with a symmetric spread so MAD is above the floor:
	// 90..110 s.
	warmUp(t, d, 150, func(i int) map[string]float64 {
		v := float64(time.Duration(90+i%21) * time.Second)
		return map[string]float64{
			MetricSyncDuration:  v,
			MetricIntervalSince: v,
		}
	})

	// Derive an exact value giving |z| == 4.0 (soft, below hard 6.0) for each.
	const targetZ = 4.0
	sdVal := valueAtZ(t, d, MetricSyncDuration, targetZ)
	isVal := valueAtZ(t, d, MetricIntervalSince, targetZ)

	// One metric elevated alone: only one soft crosser (< CorrelatedCount) -> no trip.
	if ev := d.ObserveSync(testCache, time.Unix(1_700_100_000, 0),
		map[string]float64{MetricSyncDuration: sdVal, MetricIntervalSince: float64(100 * time.Second)}); ev != nil {
		t.Fatalf("single elevated metric tripped: %+v", ev)
	}

	// Both elevated together: correlated medium trip.
	ev := d.ObserveSync(testCache, time.Unix(1_700_100_100, 0),
		map[string]float64{MetricSyncDuration: sdVal, MetricIntervalSince: isVal})
	if ev == nil {
		t.Fatal("two elevated metrics did not produce a correlated trip")
	}
	if ev.Category != "statistical" || ev.Severity != "medium" {
		t.Fatalf("got category=%q severity=%q, want statistical/medium", ev.Category, ev.Severity)
	}
	if ev.Trigger != "correlated" {
		t.Fatalf("trigger = %q, want %q", ev.Trigger, "correlated")
	}
	if len(ev.ZScores) != 2 {
		t.Fatalf("z-scores = %v, want both crossing metrics", ev.ZScores)
	}
}

func TestObserveStructuralAlwaysHigh(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	ts := time.Unix(1_700_000_000, 0)

	// Cold detector.
	ev := d.ObserveStructural(testCache, "cache_reset", ts)
	if ev == nil || ev.Category != "structural" || ev.Severity != "high" || ev.Trigger != "cache_reset" {
		t.Fatalf("cold structural event = %+v, want structural/high/cache_reset", ev)
	}

	// After warm-up, still unconditionally high, and no window is created for it.
	warmUp(t, d, 150, func(i int) map[string]float64 {
		return map[string]float64{MetricVRPAnnounced: float64(5 + i%15)}
	})
	ev = d.ObserveStructural(testCache, "error_report", ts)
	if ev == nil || ev.Category != "structural" || ev.Severity != "high" || ev.Trigger != "error_report" {
		t.Fatalf("warm structural event = %+v, want structural/high/error_report", ev)
	}
}

// A window constant at 0 has MAD 0. It used to be skipped, so the metric
// could never trip; now the floor gives it a scale, a small value stays
// quiet and a large one trips.
func TestMADZeroWindowStillTrips(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	warmUp(t, d, 150, func(i int) map[string]float64 {
		return map[string]float64{MetricASPAWithdrawn: 0}
	})
	totals := Totals{ASPAs: 1000} // floor 1
	if ev := d.ObserveSyncTotals(testCache, time.Unix(1_700_100_000, 0),
		map[string]float64{MetricASPAWithdrawn: 2}, totals); ev != nil {
		t.Fatalf("2 ASPAs withdrawn against a constant-0 window tripped: %+v", ev)
	}
	ev := d.ObserveSyncTotals(testCache, time.Unix(1_700_100_100, 0),
		map[string]float64{MetricASPAWithdrawn: 99999}, totals)
	if ev == nil || ev.Severity != "high" || ev.Trigger != MetricASPAWithdrawn {
		t.Fatalf("99999 ASPAs withdrawn against a constant-0 window: %+v, want a high trip on %s", ev, MetricASPAWithdrawn)
	}
}
