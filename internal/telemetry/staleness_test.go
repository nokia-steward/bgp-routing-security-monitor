package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// syncAt is a sync record of cache at t holding the set named set (a
// fingerprint stand-in for a real one).
func syncAt(cache string, t time.Time, serial uint32, set string) SessionEvent {
	return SessionEvent{Timestamp: t, Cache: cache, EventType: EventSync, Serial: serial,
		SyncType: SyncTypeIncremental, DataFingerprint: set}
}

// observeAll feeds evs to tr and returns every DataEvent.
func observeAll(tr *DataTracker, evs ...SessionEvent) []DataEvent {
	var out []DataEvent
	for _, ev := range evs {
		out = append(out, tr.Observe(ev)...)
	}
	return out
}

func kinds(des []DataEvent) []DataEventKind {
	var out []DataEventKind
	for _, d := range des {
		out = append(out, d.Kind)
	}
	return out
}

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

// learn feeds tr n data changes of cache, gaps cycling through gaps, from
// t0. It returns the time and serial of the last.
func learn(tr *DataTracker, cache string, n int, gaps ...time.Duration) (time.Time, uint32) {
	at := t0
	for i := range n + 1 {
		if i > 0 {
			at = at.Add(gaps[(i-1)%len(gaps)])
		}
		tr.Observe(syncAt(cache, at, uint32(i), fmt.Sprintf("set-%d", i)))
	}
	return at, uint32(n)
}

// The threshold is max(4 x median, 3 x p90, 30m) of the gaps, once 20 are
// known.
func TestStaleThresholdLearned(t *testing.T) {
	for _, tc := range []struct {
		name string
		gaps []time.Duration
		want time.Duration
	}{
		// median 15m, p90 20m: 4 x 15 = 60 = 3 x 20.
		{"10-20 min", []time.Duration{10 * time.Minute, 12 * time.Minute, 14 * time.Minute, 16 * time.Minute, 18 * time.Minute, 20 * time.Minute}, time.Hour},
		// median 5m: 20m, under the 30m floor.
		{"every 5 min", []time.Duration{5 * time.Minute}, 30 * time.Minute},
		// a heavy tail: median 10m (40m), p90 60m (180m).
		{"tail", []time.Duration{10 * time.Minute, 10 * time.Minute, 10 * time.Minute, 10 * time.Minute, 10 * time.Minute,
			10 * time.Minute, 10 * time.Minute, 10 * time.Minute, 60 * time.Minute, 60 * time.Minute}, 3 * time.Hour},
		// daily: median 24h.
		{"daily", []time.Duration{24 * time.Hour}, 96 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewDataTracker()
			learn(tr, "c", 60, tc.gaps...)
			got, src, n := tr.Threshold("c")
			if got != tc.want || src != ThresholdLearned || n != 60 {
				t.Errorf("threshold %v (%s, %d gaps), want %v (learned, 60 gaps)", got, src, n, tc.want)
			}
		})
	}
}

// Cold start: the 4-hour default until 20 gaps are known; --stale-threshold
// overrides either.
func TestStaleThresholdColdStart(t *testing.T) {
	tr := NewDataTracker()
	at, serial := learn(tr, "c", 19, 10*time.Minute)
	if thr, src, n := tr.Threshold("c"); thr != DefaultStaleThreshold || src != ThresholdDefault || n != 19 {
		t.Fatalf("19 gaps: threshold %v (%s, %d), want 4h (default)", thr, src, n)
	}
	// 3 hours without a change: under the default, though far above what
	// the 19 gaps would give (40m).
	for i := 1; i <= 18; i++ {
		if des := tr.Observe(syncAt("c", at.Add(time.Duration(i)*10*time.Minute), serial, "set-19")); len(des) != 0 {
			t.Fatalf("cold start, %v without a change: %v", time.Duration(i)*10*time.Minute, kinds(des))
		}
	}
	des := tr.Observe(syncAt("c", at.Add(4*time.Hour+time.Minute), serial, "set-19"))
	if len(des) != 1 || des[0].Kind != DataStale || des[0].ThresholdSource != ThresholdDefault || des[0].ExpectedGap != 4*time.Hour {
		t.Fatalf("cold start, 4h01m without a change: %+v, want one stale (default, 4h)", des)
	}
	// The 20th gap: now learned.
	tr.Observe(syncAt("c", at.Add(4*time.Hour+2*time.Minute), serial+1, "set-20"))
	if _, src, n := tr.Threshold("c"); src != ThresholdLearned || n != 20 {
		t.Errorf("20 gaps: %s, %d gaps, want learned", src, n)
	}
	tr.SetThreshold(5 * time.Minute)
	if thr, src, _ := tr.Threshold("c"); thr != 5*time.Minute || src != ThresholdConfigured {
		t.Errorf("--stale-threshold 5m: %v (%s)", thr, src)
	}
}

// A cache whose data changes once a day is not stale at 6 hours.
func TestDailyCacheNotStaleAtSixHours(t *testing.T) {
	tr := NewDataTracker()
	at, serial := learn(tr, "c", 30, 24*time.Hour)
	for h := 1; h <= 6; h++ {
		if des := tr.Observe(syncAt("c", at.Add(time.Duration(h)*time.Hour), serial, "set-30")); len(des) != 0 {
			t.Fatalf("daily cache, %dh without a change: %v", h, kinds(des))
		}
	}
	if st, _ := tr.Status("c", at.Add(6*time.Hour)); st.Stale || st.Age != 6*time.Hour {
		t.Errorf("status %+v, want 6h old, not stale", st)
	}
}

// One stale record per episode, never one per sync; resolved by a change,
// not by a return to earlier data.
func TestStaleOncePerEpisode(t *testing.T) {
	tr := NewDataTracker()
	at, serial := learn(tr, "c", 30, 15*time.Minute) // threshold 1h
	var des []DataEvent
	for i := 1; i <= 20; i++ {
		des = append(des, tr.Observe(syncAt("c", at.Add(time.Duration(i)*10*time.Minute), serial+uint32(i), "set-30"))...)
	}
	if len(des) != 1 || des[0].Kind != DataStale || des[0].Timestamp != at.Add(70*time.Minute) || des[0].SyncsWithoutChange != 7 {
		t.Fatalf("20 syncs without a change: %+v, want one stale at 70m after 7 syncs", des)
	}
	// Back to an earlier set: data_regressed, still stale, no new record.
	at = at.Add(210 * time.Minute)
	des = tr.Observe(syncAt("c", at, 99, "set-29"))
	if len(des) != 1 || des[0].Kind != DataRegressed {
		t.Fatalf("return to set-29: %v, want data_regressed alone", kinds(des))
	}
	des = tr.Observe(syncAt("c", at.Add(10*time.Minute), 100, "set-new"))
	if len(des) != 1 || des[0].Kind != DataStaleResolved || des[0].SerialBefore != 99 || des[0].SerialAfter != 100 {
		t.Fatalf("a new set: %+v, want stale_resolved 99 -> 100", des)
	}
}

// Old snapshots (no data_gaps) load with no gap history; a snapshot saved
// now carries it.
func TestSnapshotGapHistory(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	if err := d.Load(v040Snapshot); err != nil {
		t.Fatalf("v0.4.0 snapshot: %v", err)
	}
	if _, src, n := d.Data().Threshold("fort.example.net:323"); n != 0 || src != ThresholdDefault {
		t.Errorf("after an old snapshot: %d gaps (%s), want none", n, src)
	}

	learn(d.Data(), "c", 25, 15*time.Minute)
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := d.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"data_gaps"`) {
		t.Error("saved snapshot has no data_gaps")
	}
	d2 := NewDetector(DefaultAnomalyConfig())
	if err := d2.Load(path); err != nil {
		t.Fatal(err)
	}
	if thr, src, n := d2.Data().Threshold("c"); n != 25 || src != ThresholdLearned || thr != time.Hour {
		t.Errorf("reloaded: %v (%s, %d gaps), want 1h learned from 25", thr, src, n)
	}
}

// With several caches compared, a stale record is held until its scope is
// known: upstream when every compared cache went stale within the settle
// window, local once the window has passed without that.
func TestStaleScope(t *testing.T) {
	members := []string{"a", "b", "c"}
	setup := func() *DataTracker {
		tr := NewDataTracker()
		tr.SetThreshold(time.Hour)
		tr.SetGroup(func() ([]string, time.Duration) { return members, 10 * time.Minute })
		for _, m := range members {
			tr.Observe(syncAt(m, t0, 1, "x"))
		}
		return tr
	}
	t.Run("upstream", func(t *testing.T) {
		tr := setup()
		at := t0.Add(61 * time.Minute)
		if des := observeAll(tr, syncAt("a", at, 2, "x"), syncAt("b", at.Add(time.Minute), 2, "x")); len(des) != 0 {
			t.Fatalf("two of three stale: %v, want them held", kinds(des))
		}
		des := tr.Observe(syncAt("c", at.Add(2*time.Minute), 2, "x"))
		if len(des) != 3 {
			t.Fatalf("all three stale: %+v, want three stale records", des)
		}
		for i, d := range des {
			if d.Kind != DataStale || d.Cache != members[i] || d.Scope != ScopeUpstream {
				t.Errorf("record %d: %+v, want stale for %s, scope upstream", i, d, members[i])
			}
		}
	})
	t.Run("local", func(t *testing.T) {
		tr := setup()
		at := t0.Add(61 * time.Minute)
		observeAll(tr, syncAt("b", at, 2, "y"), syncAt("c", at, 2, "y"))
		if des := tr.Observe(syncAt("a", at, 2, "x")); len(des) != 0 {
			t.Fatalf("a stale alone: %v, held for the settle window", kinds(des))
		}
		des := tr.Observe(syncAt("b", at.Add(11*time.Minute), 3, "z"))
		if len(des) != 1 || des[0].Cache != "a" || des[0].Scope != ScopeLocal {
			t.Fatalf("after the settle window: %+v, want a's stale, scope local", des)
		}
	})
}

// replayFixture replays the anycast fixture's sync records through a fresh
// tracker as a monitor would: each sync, and a Tick every 15 seconds of the
// fixture's time in between. It
// returns every DataEvent and the threshold in force at the stall's start.
func replayFixture(t *testing.T) (des []DataEvent, thr time.Duration, src ThresholdSource, gaps int) {
	t.Helper()
	f, err := os.Open("testdata/anycast-node-stall-2026-11-12.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stallStart := time.Date(2026, 11, 12, 4, 49, 43, 0, time.UTC)
	tr := NewDataTracker()
	sc := bufio.NewScanner(f)
	lines := 0
	var tick time.Time // the monitor's ticks, every 15 s of the fixture's time
	for sc.Scan() {
		lines++
		var ev SessionEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d: %v", lines, err)
		}
		switch ev.EventType {
		case EventSync, EventConnected, EventDisconnected:
		default:
			continue
		}
		if tick.IsZero() {
			tick = ev.Timestamp
		}
		for ; tick.Before(ev.Timestamp); tick = tick.Add(15 * time.Second) {
			des = append(des, tr.Tick(tick)...)
		}
		if ev.EventType != EventSync { // the cache's connection state
			tr.Observe(ev)
			continue
		}
		normalizeLegacySync(&ev, sc.Bytes())
		if ev.Timestamp.Truncate(time.Second).Equal(stallStart) {
			thr, src, gaps = tr.Threshold(ev.Cache)
		}
		des = append(des, tr.Observe(ev)...)
	}
	if lines != 459 {
		t.Fatalf("fixture has %d records, want 459", lines)
	}
	return des, thr, src, gaps
}

// The anycast-node stall seen by ASPA Explorer: one node behind
// rtr.rpki.cloudflare.com:8282 served the same 1,033,733 VRPs from 04:49 on
// 12 Nov to 19:49 on 13 Nov, syncing hourly; a reconnect at 20:12 reached
// fresh data, and one at 21:12 landed on the stale node again.
//
// These records predate data_fingerprint and the net counts. A data change
// is a change in vrp_total or aspa_total, or non-zero announced/withdrawn
// on an incremental sync (a full sync's announced is its whole data set).
// They carry totals, not sets, so for the regression check equal totals at
// the same serial after different data stand in for "same set", and only
// against a set at least two syncs saw (see cacheData.find: serial and
// totals alone collide by chance five times before the stall). So 04:49 on
// 12 Nov (serial 3, 1,033,733), a return within the session to the total of
// 04:34 (serial 6), is not recognised: the serials differ. 21:12 on 13 Nov
// is: serial 3 and 1,033,733 again, a set 39 syncs saw.
//
// The fixture holds a second stall too, on 9-10 Nov: 1,032,530 VRPs at
// serial 5 from 17:41 to 03:41, hourly, caught with the 4-hour default as
// only 8 gaps were known by then.
func TestFixtureAnycastNodeStall(t *testing.T) {
	des, thr, src, gaps := replayFixture(t)

	// Warm before the stall: learned from the 10-20 minute changes.
	t.Logf("threshold at the stall's start: %v, %s from %d gaps", thr, src, gaps)
	if src != ThresholdLearned || gaps < StaleMinGaps || thr < 55*time.Minute || thr > 65*time.Minute {
		t.Errorf("threshold at the stall's start: %v (%s, %d gaps), want learned, about 1h", thr, src, gaps)
	}

	utc := func(day, h, m int) time.Time { return time.Date(2026, 11, day, h, m, 0, 0, time.UTC) }
	type want struct {
		kind DataEventKind
		at   time.Time
	}
	// The 05:49 sync is 60m00s into the stall, under the 1h00m46s
	// threshold; the first tick past it, at 05:50:37, makes it stale, not
	// the 06:49 sync.
	wants := []want{
		{DataStale, utc(9, 21, 41)}, {DataStaleResolved, utc(10, 3, 42)},
		{DataStale, utc(12, 5, 50)}, {DataStaleResolved, utc(13, 20, 12)},
		{DataRegressed, utc(13, 21, 12)}, {DataStale, utc(13, 21, 12)},
	}
	var got []string
	for _, d := range des {
		got = append(got, fmt.Sprintf("%s %s", d.Kind, d.Timestamp.UTC().Format("01-02T15:04")))
	}
	if len(des) != len(wants) {
		t.Fatalf("data events:\n%s\nwant %d", strings.Join(got, "\n"), len(wants))
	}
	for i, w := range wants {
		if des[i].Kind != w.kind || des[i].Timestamp.UTC().Truncate(time.Minute) != w.at {
			t.Errorf("event %d: %s, want %s %s", i, got[i], w.kind, w.at.Format("01-02T15:04"))
		}
	}

	// Every stall was a connected cache serving frozen data. The 20:12
	// resolution is a reconnect to a node with fresh data; the one on 10 Nov
	// too (a new session at 03:42).
	for _, d := range des {
		if d.Kind == DataStale && d.CacheState != CacheConnected {
			t.Errorf("stale at %v: cache_state %q, want connected", d.Timestamp.UTC(), d.CacheState)
		}
		if d.Kind == DataStaleResolved && d.Resolution != ResolvedReconnectNewData {
			t.Errorf("stale_resolved at %v: resolution %q, want reconnect_new_data", d.Timestamp.UTC(), d.Resolution)
		}
	}
	stall, resolved, regressed, again := des[2], des[3], des[4], des[5]
	if stall.ThresholdSource != ThresholdLearned || stall.Serial != 3 || stall.SyncsWithoutChange != 1 ||
		stall.Gap <= stall.ExpectedGap || stall.Gap > stall.ExpectedGap+15*time.Second ||
		stall.LastChange.UTC().Truncate(time.Second) != time.Date(2026, 11, 12, 4, 49, 43, 0, time.UTC) {
		t.Errorf("stall: %+v", stall)
	}
	if resolved.SerialBefore != 3 || resolved.SerialAfter != 5 || resolved.SyncType != SyncTypeFull || resolved.Gap < 39*time.Hour {
		t.Errorf("resolved: %+v, want serial 3 -> 5 by a full sync after 39h+", resolved)
	}
	if regressed.SerialBefore != 1 || regressed.SerialAfter != 3 || regressed.SyncType != SyncTypeFull ||
		regressed.FirstCurrent.UTC().Truncate(time.Minute) != utc(12, 4, 49) ||
		regressed.LastCurrent.UTC().Truncate(time.Minute) != utc(13, 20, 12) {
		t.Errorf("regressed: %+v, want back to the set current 12 Nov 04:49 to 13 Nov 20:12, serial 1 -> 3", regressed)
	}
	// The set returned to is 40 hours old: stale at once, from its first
	// current.
	if again.LastChange != regressed.FirstCurrent || again.Gap < 40*time.Hour {
		t.Errorf("stale again: %+v, want measured from %v", again, regressed.FirstCurrent)
	}
}

// A cache whose sync adds records the next one removes again (DaKnObNET's
// 23 announced and 23 withdrawn, the same records each time) toggles between
// two sets every sync. Neither return is significant: each set was current
// for one interval, and stopped being current one interval ago. They are
// data changes, with no data_regressed and no stale.
func TestChurnTogglingIsNotRegression(t *testing.T) {
	tr := NewDataTracker()
	at, _ := learn(tr, "c", 30, 15*time.Minute) // threshold 1h
	for i := range 200 {
		at = at.Add(10 * time.Minute)
		set := "churn-a"
		if i%2 == 1 {
			set = "churn-b"
		}
		ev := syncAt("c", at, uint32(100+i), set)
		ev.VRPAdded, ev.VRPRemoved = 23, 23
		if des := tr.Observe(ev); len(des) != 0 {
			t.Fatalf("sync %d (%s): %v, want nothing", i, set, kinds(des))
		}
		if des := tr.Tick(at.Add(5 * time.Minute)); len(des) != 0 {
			t.Fatalf("tick after sync %d: %v", i, kinds(des))
		}
	}
	if st, _ := tr.Status("c", at); st.Regressions != 0 || st.Age != 0 {
		t.Errorf("status %+v, want no regressions, data current since the last sync", st)
	}
}

// A return is significant if the set was current, in all, longer than the
// threshold, or stopped being current longer ago than that.
func TestRegressionSignificance(t *testing.T) {
	for _, tc := range []struct {
		name       string
		held, away time.Duration
		want       bool
	}{
		{"brief and recent", 20 * time.Minute, 20 * time.Minute, false},
		{"held past the threshold", 70 * time.Minute, 10 * time.Minute, true},
		{"gone past the threshold", 10 * time.Minute, 70 * time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewDataTracker()
			tr.SetThreshold(time.Hour)
			at := t0
			tr.Observe(syncAt("c", at, 1, "old"))
			// Held for tc.held, synced every 10 min (stale while over 1h).
			for d := 10 * time.Minute; d <= tc.held; d += 10 * time.Minute {
				tr.Observe(syncAt("c", at.Add(d), 1, "old"))
			}
			at = at.Add(tc.held)
			tr.Observe(syncAt("c", at, 2, "new"))
			for d := 10 * time.Minute; d < tc.away; d += 10 * time.Minute {
				tr.Observe(syncAt("c", at.Add(d), 2, "new"))
			}
			des := tr.Observe(syncAt("c", at.Add(tc.away), 3, "old"))
			got := slices.Contains(kinds(des), DataRegressed)
			if got != tc.want {
				t.Errorf("held %v, away %v: %v, want data_regressed %v", tc.held, tc.away, kinds(des), tc.want)
			}
		})
	}
}

// A cache that stops syncing altogether goes stale on a Tick, once.
func TestTickStaleWithoutSyncs(t *testing.T) {
	tr := NewDataTracker()
	tr.SetThreshold(time.Hour)
	tr.Observe(syncAt("c", t0, 7, "x"))
	var des []DataEvent
	for d := 15 * time.Second; d <= 3*time.Hour; d += 15 * time.Second {
		des = append(des, tr.Tick(t0.Add(d))...)
	}
	if len(des) != 1 || des[0].Kind != DataStale || des[0].Timestamp != t0.Add(time.Hour+15*time.Second) ||
		des[0].Serial != 7 || des[0].SyncsWithoutChange != 0 {
		t.Fatalf("3h of ticks without a sync: %+v, want one stale at 1h00m15s", des)
	}
}

// cache_state is the connection state as the episode began; a disconnected
// cache that reconnects with the same data stays in the episode, and how it
// ends is recorded.
func TestStaleCacheStateAndResolution(t *testing.T) {
	tr := NewDataTracker()
	tr.SetThreshold(time.Hour)
	tr.Observe(SessionEvent{Timestamp: t0, Cache: "c", EventType: EventConnected})
	tr.Observe(syncAt("c", t0, 1, "x"))
	tr.Observe(SessionEvent{Timestamp: t0.Add(time.Minute), Cache: "c", EventType: EventDisconnected})
	des := tr.Tick(t0.Add(61 * time.Minute))
	if len(des) != 1 || des[0].CacheState != CacheDisconnected {
		t.Fatalf("away 61m: %+v, want stale, disconnected", des)
	}
	if st, _ := tr.Status("c", t0.Add(61*time.Minute)); st.CacheState != CacheDisconnected {
		t.Errorf("status cache_state %q", st.CacheState)
	}
	tr.Observe(SessionEvent{Timestamp: t0.Add(70 * time.Minute), Cache: "c", EventType: EventConnected})
	if des := tr.Observe(syncAt("c", t0.Add(70*time.Minute), 1, "x")); len(des) != 0 {
		t.Fatalf("reconnect with the same data: %v, want the episode to go on", kinds(des))
	}
	if des := tr.Tick(t0.Add(80 * time.Minute)); len(des) != 0 {
		t.Fatalf("still stale: %v, want no second record", kinds(des))
	}
	des = tr.Observe(syncAt("c", t0.Add(90*time.Minute), 2, "y"))
	if len(des) != 1 || des[0].Resolution != ResolvedDataChange {
		t.Fatalf("change in the session: %+v, want resolved by data_change", des)
	}
	// Connected and stale: serving frozen data.
	des = tr.Tick(t0.Add(151 * time.Minute))
	if len(des) != 1 || des[0].CacheState != CacheConnected {
		t.Fatalf("connected, unchanged 61m: %+v, want stale, connected", des)
	}
	tr.Observe(SessionEvent{Timestamp: t0.Add(152 * time.Minute), Cache: "c", EventType: EventDisconnected})
	tr.Observe(SessionEvent{Timestamp: t0.Add(153 * time.Minute), Cache: "c", EventType: EventConnected})
	des = tr.Observe(syncAt("c", t0.Add(153*time.Minute), 1, "z"))
	if len(des) != 1 || des[0].Resolution != ResolvedReconnectNewData {
		t.Fatalf("reconnect with new data: %+v, want resolved by reconnect_new_data", des)
	}
}
