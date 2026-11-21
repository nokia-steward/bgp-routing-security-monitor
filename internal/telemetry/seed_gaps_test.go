package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"
	"time"
)

const (
	anycastFixture = "testdata/anycast-node-stall-2026-11-12.ndjson"
	anycastCache   = "rtr.rpki.cloudflare.com:8282"
)

// upgradeLog is a monitor's NDJSON log across an upgrade: the anycast
// fixture's records, from a RAVEN before data_fingerprint (the totals stand
// in), then 150 syncs with data_fingerprint, every 10 minutes, the data
// changing at every second one.
func upgradeLog(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(anycastFixture)
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(raw)
	at := time.Date(2026, 11, 15, 18, 55, 0, 0, time.UTC)
	for i := range 150 {
		ev := SessionEvent{Timestamp: at.Add(time.Duration(i) * 10 * time.Minute), Cache: anycastCache,
			EventType: EventSync, SyncType: SyncTypeIncremental, Serial: uint32(i),
			DataFingerprint: fmt.Sprintf("%032x", i/2), VRPTotal: 1033733}
		line, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
	}
	return buf.Bytes()
}

// #80: an anomaly snapshot from before data_gaps gives a cache no gap
// history. SeedGaps rebuilds it from the log's sync records, by the live
// tracker's rules (data_fingerprint where present, the totals stand-in
// before it): the threshold the monitor starts with is the one a cold
// replay of the whole log (raven rtr seed-baseline) ends with, from the
// same gaps.
func TestSeedGapsMatchesColdReplay(t *testing.T) {
	log := upgradeLog(t)
	d := NewDetector(DefaultAnomalyConfig())
	if err := d.Load(v040Snapshot); err != nil {
		t.Fatal(err)
	}
	if _, _, n := d.Data().Threshold(anycastCache); n != 0 {
		t.Fatalf("after a snapshot without data_gaps: %d gaps, want none", n)
	}
	seeded, skipped, err := d.SeedFromLog(bytes.NewReader(log), []string{anycastCache, "absent.example.net:323"})
	if err != nil || skipped != 0 {
		t.Fatalf("SeedFromLog: %v, %d lines skipped", err, skipped)
	}

	cold, summary, err := SeedBaseline(bytes.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	standIn, err := os.Open(anycastFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer standIn.Close()
	_, fixtureOnly, err := SeedBaseline(standIn)
	if err != nil {
		t.Fatal(err)
	}
	want := summary.DataGaps[0]
	thr, src, n := d.Data().Threshold(anycastCache)
	if thr != want.Threshold || src != want.Source || n != want.Gaps {
		t.Fatalf("seeded: %v (%s, %d gaps), want the cold replay's %v (%s, %d gaps)", thr, src, n, want.Threshold, want.Source, want.Gaps)
	}
	if seeded[anycastCache].GapCount != n || n <= fixtureOnly.DataGaps[0].Gaps {
		t.Errorf("seeded %d gaps, threshold from %d; the stand-in records alone give %d", seeded[anycastCache].GapCount, n, fixtureOnly.DataGaps[0].Gaps)
	}
	if got, ok := seeded["absent.example.net:323"]; !ok || !got.Gaps || got.GapCount != 0 {
		t.Errorf("a cache with no records in the log: seeded %+v (%v), want 0 gaps reported", got, ok)
	}
	if !slices.Equal(d.Data().gapSnapshots()[anycastCache].Values, cold.Data().gapSnapshots()[anycastCache].Values) {
		t.Error("seeded gaps differ from the cold replay's")
	}
}

// failReader fails the test if it is read.
type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Error("log read although every cache has a gap history and a serial_change_interval_ns window")
	return 0, io.EOF
}

// A cache whose gap history and serial_change_interval_ns window came with
// the snapshot keeps them: the log is not even read. A line cut short (by a
// crash, say) is skipped, not fatal.
func TestSeedGapsKeepsHistoryAndSkipsBadLines(t *testing.T) {
	d := NewDetector(DefaultAnomalyConfig())
	learn(d.Data(), "c", 25, 15*time.Minute)
	serialChanges(d, "c", t0, 5, 10*time.Minute)
	if seeded, _, err := d.SeedFromLog(failReader{t}, []string{"c"}); err != nil || len(seeded) != 0 {
		t.Errorf("SeedFromLog with a history: %v, %v, want nothing seeded", seeded, err)
	}
	if thr, src, n := d.Data().Threshold("c"); thr != time.Hour || src != ThresholdLearned || n != 25 {
		t.Errorf("after SeedFromLog: %v (%s, %d gaps), want the 1h learned from 25", thr, src, n)
	}

	log := upgradeLog(t)
	cut := append(slices.Clone(log), []byte(`{"timestamp":"2026-11-16T`)...)
	fresh := NewDetector(DefaultAnomalyConfig())
	seeded, skipped, err := fresh.SeedFromLog(bytes.NewReader(cut), []string{anycastCache})
	if err != nil || skipped != 1 {
		t.Fatalf("SeedFromLog of a log cut short: %v, %d lines skipped, want 1", err, skipped)
	}
	ref := NewDetector(DefaultAnomalyConfig())
	want, _, _ := ref.SeedFromLog(bytes.NewReader(log), []string{anycastCache})
	if seeded[anycastCache] != want[anycastCache] || seeded[anycastCache].GapCount == 0 {
		t.Errorf("seeded %+v from the log cut short, want %+v", seeded[anycastCache], want[anycastCache])
	}
}

// serialChanges feeds d n+1 incremental syncs of cache, every apart, from
// at, each changing the serial: n serial_change_interval_ns values. It
// returns the time of the last.
func serialChanges(d *Detector, cache string, at time.Time, n int, every time.Duration) time.Time {
	yes := true
	for i := range n + 1 {
		if i > 0 {
			at = at.Add(every)
		}
		d.ObserveSyncEvent(SessionEvent{Timestamp: at, Cache: cache, EventType: EventSync, Serial: uint32(i),
			SerialChanged: &yes, SyncType: SyncTypeIncremental})
	}
	return at
}
