package telemetry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedFixture is a small synthetic NDJSON telemetry stream: a connected record,
// five sync records (one full, four incremental), a reset and an error record
// (both structural), and a blank line. Only the four incremental syncs should
// populate windows; the full sync is counted but excluded.
const seedFixture = `{"timestamp":"2026-07-02T15:03:01Z","cache":"localhost:3323","event_type":"connected","proto_version":2}
{"timestamp":"2026-07-02T15:03:03Z","cache":"localhost:3323","event_type":"sync","vrp_announced":969537,"aspa_announced":2238,"sync_duration_ns":2404044565,"sync_type":"full"}
{"timestamp":"2026-07-02T15:17:10Z","cache":"localhost:3323","event_type":"sync","vrp_announced":30,"vrp_withdrawn":24,"aspa_announced":2,"sync_duration_ns":24842016770,"interval_since_ns":847035230989,"sync_type":"incremental"}
{"timestamp":"2026-07-02T15:31:44Z","cache":"localhost:3323","event_type":"sync","vrp_announced":8,"vrp_withdrawn":5,"sync_duration_ns":11020030120,"interval_since_ns":874120005000,"sync_type":"incremental"}

{"timestamp":"2026-07-02T15:46:02Z","cache":"localhost:3323","event_type":"sync","vrp_announced":12,"vrp_withdrawn":9,"aspa_withdrawn":1,"sync_duration_ns":10450000000,"interval_since_ns":858000000000,"sync_type":"incremental"}
{"timestamp":"2026-07-02T16:00:18Z","cache":"localhost:3323","event_type":"sync","vrp_announced":15,"vrp_withdrawn":7,"sync_duration_ns":12010000000,"interval_since_ns":856000000000,"sync_type":"incremental"}
{"timestamp":"2026-07-02T16:05:00Z","cache":"localhost:3323","event_type":"reset","reset_reason":"cache_reset_pdu"}
{"timestamp":"2026-07-02T16:06:00Z","cache":"localhost:3323","event_type":"error","error_text":"boom"}
`

func TestSeedBaseline(t *testing.T) {
	detector, summary, err := SeedBaseline(strings.NewReader(seedFixture))
	if err != nil {
		t.Fatalf("SeedBaseline: %v", err)
	}

	// 8 non-blank records parsed (1 connected + 5 sync + reset + error); the
	// blank line is skipped and not counted.
	if summary.LinesProcessed != 8 {
		t.Fatalf("LinesProcessed = %d, want 8", summary.LinesProcessed)
	}
	if summary.SyncCount != 5 {
		t.Fatalf("SyncCount = %d, want 5", summary.SyncCount)
	}
	if summary.FullSyncSkip != 1 {
		t.Fatalf("FullSyncSkip = %d, want 1", summary.FullSyncSkip)
	}

	// Every tracked metric but serial_change_interval_ns gets a window (every
	// incremental sync supplies those keys, defaulting to 0), each holding
	// exactly the 4 incremental values; the full sync is excluded. The
	// records are from a RAVEN before serial_changed: no serial change is
	// known, so no interval between them.
	metrics := v040Metrics()
	if len(summary.Fills) != len(metrics) {
		t.Fatalf("fills = %d windows, want %d", len(summary.Fills), len(metrics))
	}
	for i, fill := range summary.Fills {
		if fill.Cache != "localhost:3323" {
			t.Fatalf("fill[%d].Cache = %q, want localhost:3323", i, fill.Cache)
		}
		if fill.Metric != metrics[i] {
			t.Fatalf("fill[%d].Metric = %q, want %q (canonical order)", i, fill.Metric, metrics[i])
		}
		if fill.Count != 4 || fill.Cap != DefaultAnomalyConfig().WindowSize {
			t.Fatalf("fill[%d] (%s) = %d/%d, want 4/%d", i, fill.Metric, fill.Count, fill.Cap, DefaultAnomalyConfig().WindowSize)
		}
	}

	// Persist and confirm the snapshot round-trips: schema version present and
	// the reloaded windows match the seeded ones.
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := detector.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"schema_version": 1`) {
		t.Fatalf("snapshot missing schema_version 1:\n%s", raw)
	}

	reloaded := NewDetector(DefaultAnomalyConfig())
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := reloaded.windowFills()
	if len(got) != len(summary.Fills) {
		t.Fatalf("reloaded fills = %d, want %d", len(got), len(summary.Fills))
	}
	for i := range got {
		if got[i] != summary.Fills[i] {
			t.Fatalf("reloaded fill[%d] = %+v, want %+v", i, got[i], summary.Fills[i])
		}
	}
}

func TestSeedBaselineFailsOnMalformedLine(t *testing.T) {
	input := `{"timestamp":"2026-07-02T15:03:03Z","cache":"c","event_type":"sync","vrp_announced":30}
this is not json
{"timestamp":"2026-07-02T15:17:10Z","cache":"c","event_type":"sync","vrp_announced":8}
`
	_, _, err := SeedBaseline(strings.NewReader(input))
	if err == nil {
		t.Fatal("SeedBaseline accepted a malformed line, want error")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error should identify the offending line 2, got: %v", err)
	}
}

func TestSeedBaselineSkipsNonSyncRecords(t *testing.T) {
	// Only connected/reset/error records: nothing should populate windows.
	input := `{"timestamp":"2026-07-02T15:03:01Z","cache":"c","event_type":"connected"}
{"timestamp":"2026-07-02T15:05:00Z","cache":"c","event_type":"reset","reset_reason":"cache_reset_pdu"}
{"timestamp":"2026-07-02T15:06:00Z","cache":"c","event_type":"error","error_text":"boom"}
`
	_, summary, err := SeedBaseline(strings.NewReader(input))
	if err != nil {
		t.Fatalf("SeedBaseline: %v", err)
	}
	if summary.LinesProcessed != 3 {
		t.Fatalf("LinesProcessed = %d, want 3", summary.LinesProcessed)
	}
	if summary.SyncCount != 0 {
		t.Fatalf("SyncCount = %d, want 0", summary.SyncCount)
	}
	if len(summary.Fills) != 0 {
		t.Fatalf("fills = %d, want 0 (no windows created)", len(summary.Fills))
	}
}
