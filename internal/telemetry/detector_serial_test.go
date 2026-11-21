package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"
)

// pollAt is an incremental sync record of cache at ts, at serial, holding
// set; changed is its serial_changed.
func pollAt(cache string, ts time.Time, serial uint32, set string, changed bool) SessionEvent {
	return SessionEvent{Timestamp: ts, Cache: cache, EventType: EventSync, Serial: serial, SerialChanged: &changed,
		SyncType: SyncTypeIncremental, DataFingerprint: set, VRPTotal: 1_000_000, IntervalSince: time.Second}
}

// warmSerial gives d 150 serial changes of cache, 600 s +/- a few seconds
// apart, from t0. It returns the time and serial of the last.
func warmSerial(d *Detector, cache string) (time.Time, uint32) {
	at := t0
	for i := range 151 {
		if i > 0 {
			at = at.Add(600*time.Second + time.Duration(i%7)*time.Second)
		}
		d.ObserveSyncEvent(pollAt(cache, at, uint32(i), "", true))
	}
	return at, 150
}

// #75: polls that find the serial unchanged are not scored, however soon
// they follow each other: a burst of them 1 s apart (Routinator's End of
// Data refresh before a validation run) raises nothing and leaves the
// window as it was. The next serial change is scored against the last one,
// not against the last poll.
func TestSerialChangeIntervalIgnoresUnchangedPolls(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	at, serial := warmSerial(d, testCache)
	before := d.window(testCache, MetricSerialChangeInterval).count()
	for i := 1; i <= 5; i++ {
		if ev := d.ObserveSyncEvent(pollAt(testCache, at.Add(time.Duration(i)*time.Second), serial, "", false)); ev != nil {
			t.Fatalf("poll %d, 1 s apart, serial unchanged: %+v", i, ev)
		}
	}
	if got := d.window(testCache, MetricSerialChangeInterval).count(); got != before {
		t.Fatalf("window %d -> %d values after polls with the serial unchanged", before, got)
	}
	ev := d.ObserveSyncEvent(pollAt(testCache, at.Add(603*time.Second), serial+1, "", true))
	if ev != nil {
		t.Fatalf("serial change 603 s after the last: %+v, want none", ev)
	}
	w := d.window(testCache, MetricSerialChangeInterval)
	if last := w.values[(w.pos+w.cap-1)%w.cap]; last != float64(603*time.Second) {
		t.Errorf("interval taken in %v, want 603 s since the last serial change", time.Duration(last))
	}
}

// A serial change far outside the window (four times the usual interval)
// trips serial_change_interval_ns, high, with the interval in raw; and the
// value is held out of the window.
func TestSerialChangeIntervalFarOutsideTrips(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	at, serial := warmSerial(d, testCache)
	before := d.window(testCache, MetricSerialChangeInterval).count()
	ev := d.ObserveSyncEvent(pollAt(testCache, at.Add(2400*time.Second), serial+1, "", true))
	if ev == nil || ev.Severity != "high" || ev.Trigger != MetricSerialChangeInterval ||
		ev.Raw[MetricSerialChangeInterval] != float64(2400*time.Second) {
		t.Fatalf("serial change 40 min after the last, usually 10: %+v, want a high trip on %s", ev, MetricSerialChangeInterval)
	}
	if _, ok := ev.Raw[MetricIntervalSince]; ok {
		t.Errorf("raw %v carries interval_since_ns, no longer scored", ev.Raw)
	}
	if got := d.window(testCache, MetricSerialChangeInterval).count(); got != before {
		t.Errorf("window %d -> %d: the tripping interval was taken in", before, got)
	}
}

// A new session (a connected or disconnected record, or a full sync) starts
// the serial-change clock afresh: the first serial change after it has no
// interval, so the time the session was down is never scored.
func TestSerialChangeIntervalRestartsWithTheSession(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(d *Detector, at time.Time)
	}{
		{"connected", func(d *Detector, at time.Time) {
			d.ObserveSession(SessionEvent{Timestamp: at, Cache: testCache, EventType: EventConnected})
		}},
		{"disconnected", func(d *Detector, at time.Time) {
			d.ObserveSession(SessionEvent{Timestamp: at, Cache: testCache, EventType: EventDisconnected})
		}},
		{"full sync", func(d *Detector, at time.Time) {
			full := pollAt(testCache, at, 1, "", true)
			full.SyncType = SyncTypeFull
			if ev := d.ObserveSyncEvent(full); ev != nil {
				t.Errorf("full sync evaluated: %+v", ev)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDetector(DefaultAnomalyConfig())
			at, serial := warmSerial(d, testCache)
			before := d.window(testCache, MetricSerialChangeInterval).count()
			tc.start(d, at.Add(time.Hour))
			// Three hours after the last serial change, the first change of
			// the new session: no interval. The next is scored again.
			if ev := d.ObserveSyncEvent(pollAt(testCache, at.Add(3*time.Hour), serial+1, "", true)); ev != nil {
				t.Fatalf("first serial change of a new session: %+v, want none", ev)
			}
			if got := d.window(testCache, MetricSerialChangeInterval).count(); got != before {
				t.Fatalf("window %d -> %d: the first change of a session was scored", before, got)
			}
			d.ObserveSyncEvent(pollAt(testCache, at.Add(3*time.Hour+600*time.Second), serial+2, "", true))
			if got := d.window(testCache, MetricSerialChangeInterval).count(); got != before+1 {
				t.Errorf("window %d -> %d, want the second change of the session scored", before, got)
			}
		})
	}
}

// serialLog is a raven rtr monitor log of cache: a full sync, then a serial
// change every ~12 minutes with a burst of polls 1 s apart (serial
// unchanged) before each, a reconnect halfway, and an occasional validation
// run that changed nothing (24 minutes).
func serialLog(t *testing.T, cache string) []byte {
	t.Helper()
	var buf bytes.Buffer
	write := func(v any) {
		line, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
	}
	at := t0
	serial := uint32(0)
	full := pollAt(cache, at, serial, "", true)
	full.SyncType = SyncTypeFull
	write(full)
	for i := range 300 {
		if i == 150 {
			at = at.Add(30 * time.Minute)
			write(SessionEvent{Timestamp: at, Cache: cache, EventType: EventConnected})
			full := pollAt(cache, at.Add(time.Second), serial, "", true)
			full.SyncType = SyncTypeFull
			write(full)
		}
		step := 714*time.Second + time.Duration(i%9)*time.Second
		if i%60 == 59 {
			step *= 2
		}
		for k := 2; k >= 1; k-- {
			write(pollAt(cache, at.Add(step-time.Duration(k)*time.Second), serial, "", false))
		}
		at = at.Add(step)
		serial++
		write(pollAt(cache, at, serial, "", true))
	}
	return buf.Bytes()
}

// The serial_change_interval_ns window an anomaly snapshot has none of
// (one from v0.4.0: interval_since_ns, now dropped) is seeded from the log,
// and is the window a cold replay of the whole log (raven rtr seed-baseline)
// ends with. The windows the snapshot had are left as they were.
func TestSeedSerialChangeIntervalsMatchesColdReplay(t *testing.T) {
	log := serialLog(t, v040Notify)
	d := NewDetector(DefaultAnomalyConfig())
	if err := d.Load(v040Snapshot); err != nil {
		t.Fatal(err)
	}
	if d.window(v040Notify, MetricSerialChangeInterval) != nil || d.window(v040Notify, MetricIntervalSince) != nil {
		t.Fatal("v0.4.0 snapshot loaded with a serial_change_interval_ns or interval_since_ns window")
	}
	durBefore := slices.Clone(d.window(v040Notify, MetricSyncDuration).values)

	seeded, skipped, err := d.SeedFromLog(bytes.NewReader(log), []string{v040Notify})
	if err != nil || skipped != 0 {
		t.Fatalf("SeedFromLog: %v, %d lines skipped", err, skipped)
	}
	cold, _, err := SeedBaseline(bytes.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	got, want := d.window(v040Notify, MetricSerialChangeInterval), cold.window(v040Notify, MetricSerialChangeInterval)
	if got == nil || want == nil {
		t.Fatalf("seeded window %v, cold replay's %v", got, want)
	}
	// 300 serial changes; the first of each of the two sessions has no
	// interval.
	if ls := seeded[v040Notify]; !ls.Intervals || ls.IntervalCount != 298 || got.count() != 298 {
		t.Errorf("seeded %+v, window %d values, want 298 intervals", ls, got.count())
	}
	if !slices.Equal(got.snapshot().Values, want.snapshot().Values) || got.pos != want.pos || got.filled != want.filled {
		t.Error("seeded serial_change_interval_ns window differs from the cold replay's")
	}
	if !slices.Equal(d.window(v040Notify, MetricSyncDuration).values, durBefore) {
		t.Error("the snapshot's sync_duration_ns window was changed by seeding")
	}
	// No interval under 10 minutes went in: the 1 s polls are not serial
	// changes.
	for _, v := range got.sorted() {
		if v < float64(10*time.Minute) {
			t.Fatalf("seeded interval %v: a poll was taken for a serial change", time.Duration(v))
		}
	}
}

// A cache that keeps answering but whose serial (and data) stops advancing
// raises no serial_change_interval_ns anomaly while it lasts: there is no
// serial change to score. Data staleness reports it, once the data has
// gone unchanged past its learned threshold.
func TestFrozenSerialIsReportedStale(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	at := t0
	serial := uint32(0)
	set := func() string { return fmt.Sprintf("%032x", serial) }
	observe := func(ev SessionEvent) []string {
		var got []string
		if a := d.ObserveSyncEvent(ev); a != nil {
			got = append(got, a.Trigger)
		}
		for _, de := range d.Data().Observe(ev) {
			if a := de.Anomaly(); a != nil {
				got = append(got, a.Trigger)
			}
		}
		return got
	}
	// 150 serial and data changes, 12 minutes apart: a learned threshold.
	for i := range 151 {
		if i > 0 {
			at = at.Add(12 * time.Minute)
			serial++
		}
		if got := observe(pollAt(testCache, at, serial, set(), true)); len(got) != 0 {
			t.Fatalf("change %d: %v", i, got)
		}
	}
	thr, src, _ := d.Data().Threshold(testCache)
	if src != ThresholdLearned || thr != 48*time.Minute {
		t.Fatalf("threshold %v (%s), want 48m learned", thr, src)
	}
	// Then polls every 10 minutes for 3 hours, serial and data unchanged.
	var got []string
	for i := 1; i <= 18; i++ {
		ts := at.Add(time.Duration(i) * 10 * time.Minute)
		got = append(got, observe(pollAt(testCache, ts, serial, set(), false))...)
		for _, de := range d.Data().Tick(ts.Add(time.Minute)) {
			if a := de.Anomaly(); a != nil {
				got = append(got, a.Trigger)
			}
		}
	}
	if !slices.Equal(got, []string{TriggerDataStale}) {
		t.Errorf("3 hours with the serial frozen: anomalies %v, want one data_stale and nothing else", got)
	}
}
