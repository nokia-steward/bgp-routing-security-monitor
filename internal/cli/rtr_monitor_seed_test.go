package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// #80: rtr monitor upgraded with its --anomaly-snapshot from before
// data_gaps, and its --log-file kept. The gap history is seeded from the
// log before the first live sync, and logged: the threshold it starts with
// is the one a cold replay of the whole log ends with.
func TestMonitorSeedsDataGapsFromLogFile(t *testing.T) {
	const cache = "rtr.rpki.cloudflare.com:8282"
	raw, err := os.ReadFile("../telemetry/testdata/anycast-node-stall-2026-11-12.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logFile := filepath.Join(dir, "rtr-telemetry.ndjson")
	snap := filepath.Join(dir, "anomaly-baseline.json")
	if err := os.WriteFile(logFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// As ASPA Explorer's: caches, saved_at and schema_version, no data_gaps.
	if err := os.WriteFile(snap, []byte(`{"schema_version":1,"saved_at":"2026-11-15T18:55:00Z","caches":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	detector := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	if err := detector.Load(snap); err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	configureDataTracker(detector.Data(), 0, nil)
	seedDataGaps(detector.Data(), logFile, []string{cache}, slog.New(slog.NewTextHandler(logs, nil)))

	_, cold, err := telemetry.SeedBaseline(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := cold.DataGaps[0]
	thr, src, n := detector.Data().Threshold(cache)
	if n == 0 || thr != want.Threshold || src != want.Source || n != want.Gaps {
		t.Fatalf("after seeding: %v (%s, %d gaps), want the cold replay's %v (%s, %d gaps)",
			thr, src, n, want.Threshold, want.Source, want.Gaps)
	}
	line := fmt.Sprintf("cache=%s gaps=%d", cache, n)
	if out := logs.String(); !strings.Contains(out, "seeded gaps between data changes from the log file") || !strings.Contains(out, line) {
		t.Errorf("log %q, want the seeded gaps (%s)", out, line)
	}

	// No log file yet (a first start): nothing seeded, nothing logged.
	fresh := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	quiet := &lockedBuffer{}
	seedDataGaps(fresh.Data(), filepath.Join(dir, "none.ndjson"), []string{cache}, slog.New(slog.NewTextHandler(quiet, nil)))
	if _, _, n := fresh.Data().Threshold(cache); n != 0 || quiet.String() != "" {
		t.Errorf("no log file: %d gaps, log %q, want none", n, quiet.String())
	}
}

// stalePassThroughLog is a log whose history learns about 1h: 31 gaps of
// 15m, then a set X current for 2h, a set Y for 15m, a return to X, and a
// new set Z. Whether the return to X is a return to earlier data (no gap)
// or churn (a gap) depends on the threshold in effect: X was current 2h,
// more than the learned 1h, less than 3h. It returns the log and the
// records.
func stalePassThroughLog(t *testing.T, cache string) ([]byte, []telemetry.SessionEvent) {
	t.Helper()
	at := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	var evs []telemetry.SessionEvent
	sync := func(set string) {
		evs = append(evs, telemetry.SessionEvent{Timestamp: at, Cache: cache, EventType: telemetry.EventSync,
			SyncType: telemetry.SyncTypeIncremental, Serial: uint32(len(evs)), DataFingerprint: fmt.Sprintf("%032s", set)})
		at = at.Add(15 * time.Minute)
	}
	for i := range 32 {
		sync(fmt.Sprintf("s%d", i))
	}
	for range 8 { // X, current for 2h
		sync("X")
	}
	sync("Y")
	sync("X")
	sync("Z")
	var buf bytes.Buffer
	for _, ev := range evs {
		line, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
	}
	return buf.Bytes(), evs
}

// --stale-threshold wins over a history seeded from the log: the threshold
// is 3h (configured), not the ~1h the log learns, and the seeding replay
// itself runs at 3h, as the live tracker would have (the return to X is
// churn at 3h, a return to earlier data at 1h).
func TestMonitorStaleThresholdWinsOverSeededHistory(t *testing.T) {
	const cache = "fort.example.net:323"
	raw, evs := stalePassThroughLog(t, cache)
	logFile := filepath.Join(t.TempDir(), "rtr-telemetry.ndjson")
	if err := os.WriteFile(logFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	gapsAt := func(threshold time.Duration) int {
		tr := telemetry.NewDataTracker()
		tr.SetThreshold(threshold)
		for _, ev := range evs {
			tr.Observe(ev)
		}
		_, _, n := tr.Threshold(cache)
		return n
	}
	learned := telemetry.NewDataTracker()
	for _, ev := range evs {
		learned.Observe(ev)
	}
	if thr, src, _ := learned.Threshold(cache); thr != time.Hour || src != telemetry.ThresholdLearned {
		t.Fatalf("the log learns %v (%s), want 1h learned", thr, src)
	}
	want := gapsAt(3 * time.Hour)
	if want == gapsAt(0) {
		t.Fatalf("%d gaps at 3h and learning alike: the log does not tell the thresholds apart", want)
	}

	detector := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	configureDataTracker(detector.Data(), 3*time.Hour, nil)
	seedDataGaps(detector.Data(), logFile, []string{cache}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	thr, src, n := detector.Data().Threshold(cache)
	if thr != 3*time.Hour || src != telemetry.ThresholdConfigured {
		t.Errorf("--stale-threshold 3h over a seeded history: %v (%s), want 3h (configured)", thr, src)
	}
	if n != want {
		t.Errorf("seeded %d gaps, want the %d a tracker at --stale-threshold 3h learns from the log", n, want)
	}
}
