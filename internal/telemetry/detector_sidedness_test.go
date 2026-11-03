package telemetry

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// longBaseline is one in-baseline sync for a cache polled every ~15 minutes:
// intervals of 840-960s, syncs of 10-14s, and counts that all have spread, so
// every window has a nonzero MAD and every metric is evaluated.
func longBaseline(i int) map[string]float64 {
	return map[string]float64{
		MetricIntervalSince: float64(840*time.Second + time.Duration(i%121)*time.Second),
		MetricSyncDuration:  float64(10*time.Second + time.Duration(i%41)*100*time.Millisecond),
		MetricVRPAnnounced:  float64(1000 + i%201),
		MetricVRPWithdrawn:  float64(800 + i%161),
		MetricASPAAnnounced: float64(100 + i%41),
		MetricASPAWithdrawn: float64(50 + i%21),
	}
}

// valueAtZ returns the value whose modified z against metric's current window
// is z.
func valueAtZ(t *testing.T, d *Detector, metric string, z float64) float64 {
	t.Helper()
	med, mad, ok := d.window(testCache, metric).medianMAD()
	if !ok || mad == 0 {
		t.Fatalf("metric %q not ready: mad=%v ok=%v", metric, mad, ok)
	}
	return med + z*mad/0.6745
}

// The lab case: a baseline seeded at a 15-minute cadence, then syncs every
// 5-15s that also finish faster. Their z is hugely negative (≈ -42 for the
// interval), which used to be a high-severity trip. Shorter and faster is
// never a fault, so nothing trips, and the values join the windows rather
// than being held out as confirmed anomalies.
func TestShortIntervalAndFastSyncDoNotTrip(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	warmUp(t, d, 150, longBaseline)

	for i, interval := range []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second} {
		m := longBaseline(i)
		m[MetricIntervalSince] = float64(interval)
		m[MetricSyncDuration] = float64(200 * time.Millisecond)

		before := map[string]int{}
		for _, name := range []string{MetricIntervalSince, MetricSyncDuration} {
			before[name] = d.window(testCache, name).count()
		}
		if ev := d.ObserveSync(testCache, time.Unix(1_700_100_000+int64(i), 0), m); ev != nil {
			t.Fatalf("interval %v with a 200ms sync tripped: %+v", interval, ev)
		}
		for _, name := range []string{MetricIntervalSince, MetricSyncDuration} {
			if got := d.window(testCache, name).count(); got != before[name]+1 {
				t.Fatalf("%s window count %d -> %d: a short value was held out of the window", name, before[name], got)
			}
		}
	}
}

// A long interval or a slow sync is what a stalled validator or a slow
// repository looks like; those still trip at both thresholds.
func TestLongIntervalAndSlowSyncStillTrip(t *testing.T) {
	cfg := DefaultAnomalyConfig()

	for _, metric := range []string{MetricIntervalSince, MetricSyncDuration} {
		t.Run(metric+"/hard", func(t *testing.T) {
			d := NewDetector(cfg)
			warmUp(t, d, 150, longBaseline)
			m := longBaseline(0)
			m[metric] = valueAtZ(t, d, metric, cfg.HardZThreshold+0.5)
			ev := d.ObserveSync(testCache, time.Unix(1_700_100_000, 0), m)
			if ev == nil || ev.Severity != "high" || ev.Trigger != metric {
				t.Fatalf("z=%.1f on %s = %+v, want a high trip on %s", cfg.HardZThreshold+0.5, metric, ev, metric)
			}
			if z := ev.ZScores[metric]; z < cfg.HardZThreshold {
				t.Fatalf("reported z = %v, want >= %v", z, cfg.HardZThreshold)
			}
		})
	}

	t.Run("soft", func(t *testing.T) {
		d := NewDetector(cfg)
		warmUp(t, d, 150, longBaseline)
		const z = 4.0 // above soft 3.5, below hard 6.0
		m := longBaseline(0)
		m[MetricIntervalSince] = valueAtZ(t, d, MetricIntervalSince, z)
		if ev := d.ObserveSync(testCache, time.Unix(1_700_100_000, 0), m); ev != nil {
			t.Fatalf("one soft crosser tripped: %+v", ev)
		}

		m = longBaseline(1)
		m[MetricIntervalSince] = valueAtZ(t, d, MetricIntervalSince, z)
		m[MetricSyncDuration] = valueAtZ(t, d, MetricSyncDuration, z)
		ev := d.ObserveSync(testCache, time.Unix(1_700_100_100, 0), m)
		if ev == nil || ev.Severity != "medium" || ev.Trigger != "correlated" {
			t.Fatalf("long interval + slow sync at z=%v = %+v, want a medium correlated trip", z, ev)
		}
		if len(ev.ZScores) != 2 {
			t.Fatalf("z-scores = %v, want interval and duration", ev.ZScores)
		}
	})

	// The mirror image of the correlated case: both at z = -4, as far below
	// the median as the soft case is above it, must not trip.
	t.Run("soft-below", func(t *testing.T) {
		d := NewDetector(cfg)
		warmUp(t, d, 150, longBaseline)
		m := longBaseline(0)
		m[MetricIntervalSince] = valueAtZ(t, d, MetricIntervalSince, -4)
		m[MetricSyncDuration] = valueAtZ(t, d, MetricSyncDuration, -4)
		if ev := d.ObserveSync(testCache, time.Unix(1_700_100_000, 0), m); ev != nil {
			t.Fatalf("short interval + fast sync at z=-4 tripped: %+v", ev)
		}
	})
}

// The count statistics are upper-tail too: a burst of announcements or
// withdrawals is worth flagging, a quiet sync is not.
func TestCountStatisticsAreUpperTail(t *testing.T) {
	cfg := DefaultAnomalyConfig()
	for _, metric := range []string{MetricVRPAnnounced, MetricVRPWithdrawn, MetricASPAAnnounced, MetricASPAWithdrawn} {
		t.Run(metric, func(t *testing.T) {
			_, hard := cfg.thresholdsFor(metric)
			d := NewDetector(cfg)
			warmUp(t, d, 150, longBaseline)

			m := longBaseline(0)
			m[metric] = valueAtZ(t, d, metric, -(hard + 2))
			if ev := d.ObserveSync(testCache, time.Unix(1_700_100_000, 0), m); ev != nil {
				t.Fatalf("%s far below its baseline tripped: %+v", metric, ev)
			}

			m = longBaseline(1)
			m[metric] = valueAtZ(t, d, metric, hard+0.5)
			ev := d.ObserveSync(testCache, time.Unix(1_700_100_100, 0), m)
			if ev == nil || ev.Severity != "high" || ev.Trigger != metric {
				t.Fatalf("%s above its hard threshold = %+v, want a high trip", metric, ev)
			}
		})
	}
}

// SeedBaseline replays through ObserveSync, where a hard trip holds a value
// out of its window. A recording that moves from a 15-minute cadence to
// syncs every few seconds must keep those short intervals in the seeded
// windows, as the live path now does.
func TestSeedBaselineKeepsShortIntervals(t *testing.T) {
	var b strings.Builder
	ts := time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)
	line := func(interval, duration time.Duration) {
		ts = ts.Add(interval)
		fmt.Fprintf(&b, `{"timestamp":%q,"cache":%q,"event_type":"sync","vrp_announced":%d,"vrp_withdrawn":%d,"sync_duration_ns":%d,"interval_since_ns":%d,"sync_type":"incremental"}`+"\n",
			ts.Format(time.RFC3339Nano), testCache, 10+b.Len()%17, 5+b.Len()%13, duration, interval)
	}
	const long, short = 150, 20
	for i := 0; i < long; i++ {
		line(840*time.Second+time.Duration(i%121)*time.Second, 10*time.Second+time.Duration(i%41)*100*time.Millisecond)
	}
	for i := 0; i < short; i++ {
		line(5*time.Second+time.Duration(i%11)*time.Second, 300*time.Millisecond)
	}

	d, _, err := SeedBaseline(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("SeedBaseline: %v", err)
	}
	for _, metric := range []string{MetricIntervalSince, MetricSyncDuration} {
		if got := d.window(testCache, metric).count(); got != long+short {
			t.Fatalf("seeded %s window holds %d values, want %d: short values were dropped as anomalies", metric, got, long+short)
		}
	}
}
