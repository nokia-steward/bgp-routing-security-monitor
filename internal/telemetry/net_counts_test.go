package telemetry

import (
	"encoding/json"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The detector's count statistics are the sync's net change, under their
// old names: Fort 1.7.0's 220 -> 221 delta (2276 announcement PDUs, 2263
// withdrawals; 21 VRPs added, 8 removed) scores as 21 and 8.
func TestSyncMetricsUseNetCounts(t *testing.T) {
	ev := SessionEvent{
		EventType: EventSync, SyncType: SyncTypeIncremental,
		VRPAnnounced: 2276, VRPWithdrawn: 2263, VRPAdded: 21, VRPRemoved: 8,
		ASPAAnnounced: 3, ASPAWithdrawn: 1, ASPAAdded: 1, ASPARemoved: 1,
		IntervalSince: time.Minute, SyncDuration: time.Second,
	}
	want := map[string]float64{
		MetricIntervalSince: float64(time.Minute), MetricSyncDuration: float64(time.Second),
		MetricVRPAnnounced: 21, MetricVRPWithdrawn: 8, MetricASPAAnnounced: 1, MetricASPAWithdrawn: 1,
	}
	if got := SyncMetrics(ev); !reflect.DeepEqual(got, want) {
		t.Errorf("SyncMetrics = %v, want %v", got, want)
	}
}

// pduMetrics is the metric map RAVEN built before the net counts: the PDU
// counts.
func pduMetrics(ev SessionEvent) map[string]float64 {
	return map[string]float64{
		MetricIntervalSince: float64(ev.IntervalSince),
		MetricSyncDuration:  float64(ev.SyncDuration),
		MetricVRPAnnounced:  float64(ev.VRPAnnounced),
		MetricVRPWithdrawn:  float64(ev.VRPWithdrawn),
		MetricASPAAnnounced: float64(ev.ASPAAnnounced),
		MetricASPAWithdrawn: float64(ev.ASPAWithdrawn),
	}
}

// cleanSyncs returns n incremental syncs of cache with no protocol errors
// (net change equal to the PDU counts) around the given churn, with every
// tenth a burst large enough to trip.
func cleanSyncs(cache string, n int, start time.Time, interval time.Duration, vrps, aspas int) []SessionEvent {
	r := rand.New(rand.NewPCG(uint64(len(cache)), uint64(n)))
	out := make([]SessionEvent, n)
	for i := range out {
		ann, wd := vrps+r.IntN(vrps/2+1), vrps/2+r.IntN(vrps/2+1)
		aann, awd := r.IntN(aspas+1), r.IntN(aspas+1)
		if i%10 == 9 {
			ann *= 50
		}
		out[i] = SessionEvent{
			Timestamp: start.Add(time.Duration(i) * interval), Cache: cache,
			EventType: EventSync, SyncType: SyncTypeIncremental,
			VRPTotal: 500_000, ASPATotal: 800,
			VRPAnnounced: ann, VRPWithdrawn: wd, VRPAdded: ann, VRPRemoved: wd,
			ASPAAnnounced: aann, ASPAWithdrawn: awd, ASPAAdded: aann, ASPARemoved: awd,
			IntervalSince: interval + time.Duration(r.IntN(2000))*time.Millisecond,
			SyncDuration:  time.Duration(500+r.IntN(500)) * time.Millisecond,
		}
	}
	return out
}

// A v0.4.0 snapshot, its windows built from PDU counts, still loads and, on
// syncs without protocol errors, scores exactly as before: the same
// anomalies, z-scores and raw values, sync for sync, bursts included, and
// the same windows after.
func TestV040SnapshotScoresNetCountsAsBefore(t *testing.T) {
	before, after := NewDetector(DefaultAnomalyConfig()), NewDetector(DefaultAnomalyConfig())
	for _, d := range []*Detector{before, after} {
		if err := d.Load(v040Snapshot); err != nil {
			t.Fatalf("Load of a v0.4.0 snapshot: %v", err)
		}
	}
	start := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	trips := 0
	for _, c := range []struct {
		cache       string
		interval    time.Duration
		vrps, aspas int
	}{
		{v040Timer, 600 * time.Second, 20, 1},
		{v040Notify, 900 * time.Second, 1000, 2},
	} {
		for _, ev := range cleanSyncs(c.cache, 120, start, c.interval, c.vrps, c.aspas) {
			old := before.ObserveSyncTotals(ev.Cache, ev.Timestamp, pduMetrics(ev), TotalsOf(ev))
			got := after.ObserveSyncTotals(ev.Cache, ev.Timestamp, SyncMetrics(ev), TotalsOf(ev))
			if !reflect.DeepEqual(old, got) {
				t.Fatalf("%s at %s: scored %+v with net counts, %+v with PDU counts", ev.Cache, ev.Timestamp, got, old)
			}
			if got != nil {
				trips++
			}
		}
		for _, metric := range trackedMetrics {
			bm, bmad, _ := before.window(c.cache, metric).medianMAD()
			am, amad, _ := after.window(c.cache, metric).medianMAD()
			if bm != am || bmad != amad {
				t.Errorf("%s/%s: window median/MAD %v/%v with net counts, %v/%v before", c.cache, metric, am, amad, bm, bmad)
			}
		}
	}
	if trips == 0 {
		t.Fatal("no sync tripped: the comparison does not exercise an anomaly")
	}
}

// seed-baseline reads NDJSON from a RAVEN before the net counts, which has
// none of them, by its PDU counts: an old file seeds the same baseline as
// the same syncs written today.
func TestSeedBaselineOldRecordsUsePDUCounts(t *testing.T) {
	var old, current strings.Builder
	for _, ev := range cleanSyncs("rtr.example.net:3323", 150, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), 600*time.Second, 30, 1) {
		line, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		current.Write(append(line, '\n'))
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"vrp_added", "vrp_removed", "aspa_added", "aspa_removed"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("a sync record has no %s: %s", k, line)
			}
			delete(m, k)
		}
		line, _ = json.Marshal(m)
		old.Write(append(line, '\n'))
	}
	dOld, _, err := SeedBaseline(strings.NewReader(old.String()))
	if err != nil {
		t.Fatal(err)
	}
	dNew, _, err := SeedBaseline(strings.NewReader(current.String()))
	if err != nil {
		t.Fatal(err)
	}
	for _, metric := range trackedMetrics {
		om, omad, _ := dOld.window("rtr.example.net:3323", metric).medianMAD()
		nm, nmad, _ := dNew.window("rtr.example.net:3323", metric).medianMAD()
		if om != nm || omad != nmad || om == 0 && metric == MetricVRPAnnounced {
			t.Errorf("%s: old file seeds median/MAD %v/%v, current %v/%v", metric, om, omad, nm, nmad)
		}
	}
}
