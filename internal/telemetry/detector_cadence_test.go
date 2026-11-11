package telemetry

import (
	"math/rand/v2"
	"testing"
	"time"
)

// A timer-driven cache, as ASPA Explorer polls Fort 1.7.0 (#59): a sync
// every 600 s with a few milliseconds of jitter, ~106 ms syncs, and small
// counts on a ~1M-VRP, ~1,000-ASPA cache. Its windows have a MAD of
// milliseconds, so without a minimum spread any ordinary variation scored
// hundreds of "deviations".
type cadence struct {
	rng    *rand.Rand
	totals Totals
}

func newCadence() *cadence {
	return &cadence{rng: rand.New(rand.NewPCG(59, 600)), totals: Totals{VRPs: 1_000_000, ASPAs: 1_000}}
}

// next returns sync i of the cadence. The jitter is within ±5 ms on the
// interval and ±2 ms on the duration; now and then the cache has more to
// say: a notify-driven 0.74 s sync announcing 783 VRPs (the Fort case), a
// DaKnObNET-style 23/23 churn, a single ASPA change.
func (c *cadence) next(i int) map[string]float64 {
	jitter := func(d time.Duration) float64 { return float64(time.Duration(c.rng.Int64N(int64(2*d+1))) - d) }
	m := map[string]float64{
		MetricIntervalSince: float64(600*time.Second) + jitter(5*time.Millisecond),
		MetricSyncDuration:  float64(106*time.Millisecond) + jitter(2*time.Millisecond),
		MetricVRPAnnounced:  float64(c.rng.IntN(4)),
		MetricVRPWithdrawn:  float64(c.rng.IntN(4)),
		MetricASPAAnnounced: 0,
		MetricASPAWithdrawn: 0,
	}
	switch {
	case i%97 == 50:
		m[MetricSyncDuration] = float64(740 * time.Millisecond)
		// z ~= 5.3 on vrp_announced (soft, not hard, on 1M VRPs) and
		// ~0.4 on the duration: one soft crosser, no correlated trip.
		m[MetricVRPAnnounced] = 783
	case i%53 == 20:
		m[MetricVRPAnnounced], m[MetricVRPWithdrawn] = 23, 23
	case i%71 == 30:
		m[MetricASPAAnnounced] = 1
	}
	return m
}

// warm runs n cadence syncs through d and fails on any trip.
func (c *cadence) warm(t *testing.T, d *Detector, n int) {
	t.Helper()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < n; i++ {
		m := c.next(i)
		if ev := d.ObserveSyncTotals(testCache, base.Add(time.Duration(i)*10*time.Minute), m, c.totals); ev != nil {
			t.Fatalf("sync %d of a normal timer-driven cadence tripped: %+v (values %v)", i, ev, m)
		}
	}
}

// Over a long run (four full windows) a timer-driven cache with ordinary
// jitter and ordinary churn never trips.
func TestTimerCadenceNoTripsOverLongRun(t *testing.T) {
	c := newCadence()
	d := NewDetector(DefaultAnomalyConfig())
	c.warm(t, d, 2000)
	// The windows really are degenerate: the floor, not the MAD, sets the
	// scale. Otherwise this test would not cover #59.
	for _, metric := range []string{MetricIntervalSince, MetricSyncDuration} {
		med, mad, _ := d.window(testCache, metric).medianMAD()
		if floor := minScale(metric, med, c.totals); mad >= floor/100 {
			t.Fatalf("%s MAD %v is not near 0 (floor %v): the fixture does not exercise the floor", metric, mad, floor)
		}
	}
}

// After warm-up, a burst of 1,200 VRPs in one sync on a ~1M-VRP cache is a
// high-severity trip on vrp_announced.
func TestTimerCadenceVRPBurstTrips(t *testing.T) {
	c := newCadence()
	d := NewDetector(DefaultAnomalyConfig())
	c.warm(t, d, 150)
	m := c.next(150)
	m[MetricVRPAnnounced] = 1200
	ev := d.ObserveSyncTotals(testCache, time.Unix(1_800_000_000, 0), m, c.totals)
	if ev == nil || ev.Severity != "high" || ev.Trigger != MetricVRPAnnounced {
		t.Fatalf("1,200-VRP burst: %+v, want a high trip on %s", ev, MetricVRPAnnounced)
	}
}

// A real change of cadence (the cache now polled every 20 minutes, or a
// stalled validator) is a high-severity trip on interval_since_ns; so is a
// sync that takes many seconds instead of ~100 ms.
func TestTimerCadenceRealChangesTrip(t *testing.T) {
	for _, tc := range []struct {
		metric string
		value  time.Duration
	}{
		{MetricIntervalSince, 1200 * time.Second},
		{MetricIntervalSince, 660 * time.Second}, // 10% late: ~6.7 scales
		{MetricSyncDuration, 15 * time.Second},
	} {
		c := newCadence()
		d := NewDetector(DefaultAnomalyConfig())
		c.warm(t, d, 150)
		m := c.next(150)
		m[tc.metric] = float64(tc.value)
		ev := d.ObserveSyncTotals(testCache, time.Unix(1_800_000_000, 0), m, c.totals)
		if ev == nil || ev.Severity != "high" || ev.Trigger != tc.metric {
			t.Errorf("%s = %v: %+v, want a high trip on it", tc.metric, tc.value, ev)
		}
	}
}

// A window that has been exactly constant (MAD 0: a perfect timer, a count
// that never moved) was skipped and could never trip. It now trips on a
// large deviation and stays quiet on a small one.
func TestConstantWindowTripsOnLargeDeviation(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	totals := Totals{VRPs: 1_000_000, ASPAs: 1_000}
	base := time.Unix(1_700_000_000, 0)
	constant := map[string]float64{
		MetricIntervalSince: float64(600 * time.Second),
		MetricSyncDuration:  float64(100 * time.Millisecond),
		MetricVRPAnnounced:  0,
	}
	for i := 0; i < 150; i++ {
		if ev := d.ObserveSyncTotals(testCache, base.Add(time.Duration(i)*time.Minute), constant, totals); ev != nil {
			t.Fatalf("constant sync %d tripped: %+v", i, ev)
		}
	}
	small := map[string]float64{
		MetricIntervalSince: float64(603 * time.Second),
		MetricSyncDuration:  float64(900 * time.Millisecond),
		MetricVRPAnnounced:  40,
	}
	if ev := d.ObserveSyncTotals(testCache, base.Add(time.Hour), small, totals); ev != nil {
		t.Fatalf("small deviation from a constant window tripped: %+v", ev)
	}
	for metric, v := range map[string]float64{
		MetricIntervalSince: float64(900 * time.Second),
		MetricSyncDuration:  float64(20 * time.Second),
		MetricVRPAnnounced:  5000,
	} {
		m := map[string]float64{}
		for k, cv := range constant {
			m[k] = cv
		}
		m[metric] = v
		ev := d.ObserveSyncTotals(testCache, base.Add(2*time.Hour), m, totals)
		if ev == nil || ev.Severity != "high" || ev.Trigger != metric {
			t.Errorf("%s = %v against a constant window: %+v, want a high trip on it", metric, v, ev)
		}
	}
}
