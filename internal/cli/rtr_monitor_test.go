package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// lockedBuffer is an io.Writer safe to read while another goroutine writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// monitorErrorReport runs an RTR client, as rtr monitor does, against a cache
// that answers its first query with an Error Report, and returns the first
// telemetry event the report produced, the NDJSON written, and the monitor's
// classification of that event and its log.
func monitorErrorReport(t *testing.T, code uint16, text string) (telemetry.SessionEvent, string, *telemetry.AnomalyEvent, bool, string) {
	t.Helper()
	cache := rtrtest.NewCache(t)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	var ndjson, logs lockedBuffer
	rec := telemetry.NewRecorder(&ndjson, 16, quiet)
	client, err := rtr.NewClient(cache.Addr(), "tcp", nil, store.NewVRPStore(), store.NewASPAStore(), 2, quiet)
	if err != nil {
		t.Fatal(err)
	}
	client.SetTelemetry(rec)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.Start(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	q := cache.Next(5 * time.Second)
	q.Conn.Send(rtrtest.ErrorReport(2, code, text))
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-rec.Events():
			if ev.EventType == telemetry.EventConnected {
				continue
			}
			log := slog.New(slog.NewTextHandler(&logs, nil))
			anomaly, observed := observeRTREvent(telemetry.NewDetector(telemetry.DefaultAnomalyConfig()), ev, log)
			return ev, ndjson.String(), anomaly, observed, logs.String()
		case <-deadline:
			t.Fatal("no telemetry event for the cache's Error Report")
		}
	}
}

// Error Report code 2 (No Data Available, Routinator's "Running initial
// validation" at startup) is a cache that is not ready yet: recorded as a
// cache_not_ready event with its code and text, logged at INFO, not an
// anomaly and not taken into the baseline. Driven end to end, from the
// cache's Error Report through the client's telemetry to the monitor.
func TestRTRMonitorNoDataAvailableIsNotAnAnomaly(t *testing.T) {
	ev, ndjson, anomaly, observed, logs := monitorErrorReport(t, 2, "Running initial validation")
	if ev.EventType != telemetry.EventCacheNotReady || ev.ErrorCode == nil || *ev.ErrorCode != 2 ||
		ev.ErrorText != "Running initial validation" {
		t.Errorf("telemetry event = %+v, want cache_not_ready with code 2 and the cache's text", ev)
	}
	var line struct {
		EventType string `json:"event_type"`
		ErrorCode *int   `json:"error_code"`
		ErrorText string `json:"error_text"`
	}
	for _, l := range strings.Split(strings.TrimSpace(ndjson), "\n") {
		if strings.Contains(l, `"cache_not_ready"`) {
			if err := json.Unmarshal([]byte(l), &line); err != nil {
				t.Fatalf("NDJSON %q: %v", l, err)
			}
		}
	}
	if line.EventType != "cache_not_ready" || line.ErrorCode == nil || *line.ErrorCode != 2 ||
		line.ErrorText != "Running initial validation" {
		t.Errorf("NDJSON record = %+v, want cache_not_ready, error_code 2, the cache's text", line)
	}
	if anomaly != nil || observed {
		t.Errorf("classified as anomaly %+v (observed %v), want no anomaly and no baseline update", anomaly, observed)
	}
	if !strings.Contains(logs, "level=INFO") || !strings.Contains(logs, "error_code=2") ||
		strings.Contains(logs, "level=WARN") || strings.Contains(logs, "level=ERROR") {
		t.Errorf("monitor log = %q, want one INFO line with the error code", logs)
	}
}

// Any other Error Report is still a high-severity structural anomaly, end to
// end for Corrupt Data and directly for other codes and none.
func TestRTRMonitorOtherErrorReportsStayHighSeverity(t *testing.T) {
	ev, _, anomaly, _, _ := monitorErrorReport(t, 0, "Corrupt Data")
	if ev.EventType != telemetry.EventError {
		t.Errorf("Corrupt Data recorded as %q, want error", ev.EventType)
	}
	if anomaly == nil || anomaly.Category != "structural" || anomaly.Severity != "high" || anomaly.Trigger != "error_report" {
		t.Errorf("Corrupt Data classified as %+v, want a high-severity structural error_report", anomaly)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	detector := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	for _, code := range []*uint16{nil, ptr(uint16(0)), ptr(uint16(4)), ptr(uint16(3))} {
		ev := telemetry.SessionEvent{Cache: "c", EventType: telemetry.EventError, ErrorCode: code, Timestamp: time.Now()}
		anomaly, _ := observeRTREvent(detector, ev, log)
		if anomaly == nil || anomaly.Category != "structural" || anomaly.Severity != "high" || anomaly.Trigger != "error_report" {
			t.Errorf("error code %v classified as %+v, want a high-severity structural error_report", code, anomaly)
		}
	}
}

// A cache that answers "not ready" repeatedly, then completes its first
// (full) sync, raises no anomaly, and the baseline is exactly as before.
func TestRTRMonitorRepeatedNotReadyThenFullSync(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	start := time.Unix(1_700_000_000, 0)
	for i := 0; i < 40; i++ { // a baseline from incremental syncs
		observeRTREvent(d, telemetry.SessionEvent{
			Cache: "c", EventType: telemetry.EventSync, SyncType: telemetry.SyncTypeIncremental,
			Timestamp: start.Add(time.Duration(i) * time.Minute), IntervalSince: time.Minute,
			SyncDuration: time.Duration(40+i%5) * time.Millisecond, VRPAnnounced: 3 + i%4, VRPWithdrawn: 1 + i%3,
		}, log)
	}
	dir := t.TempDir()
	before, after := filepath.Join(dir, "before.json"), filepath.Join(dir, "after.json")
	if err := d.Save(before); err != nil {
		t.Fatal(err)
	}

	code := uint16(2)
	ts := start.Add(time.Hour)
	for i := 0; i < 5; i++ {
		for _, typ := range []telemetry.EventType{telemetry.EventCacheNotReady, telemetry.EventError} {
			// EventError with code 2 is how a recording from before this
			// change carries it.
			ev := telemetry.SessionEvent{Cache: "c", EventType: typ, ErrorCode: &code,
				ErrorText: "Running initial validation", Timestamp: ts}
			if a, observed := observeRTREvent(d, ev, log); a != nil || observed {
				t.Fatalf("%s code 2: anomaly %+v, observed %v; want neither", typ, a, observed)
			}
		}
		ts = ts.Add(10 * time.Second)
	}
	full := telemetry.SessionEvent{Cache: "c", EventType: telemetry.EventSync, SyncType: telemetry.SyncTypeFull,
		Timestamp: ts, IntervalSince: 2 * time.Hour, SyncDuration: 4 * time.Second, VRPAnnounced: 750_000, VRPTotal: 750_000}
	if a, observed := observeRTREvent(d, full, log); a != nil || observed {
		t.Fatalf("full sync after not-ready: anomaly %+v, observed %v; want neither", a, observed)
	}

	if err := d.Save(after); err != nil {
		t.Fatal(err)
	}
	// Compare the windows, not the save time.
	windows := func(path string) string {
		var f struct {
			Caches json.RawMessage `json:"caches"`
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		return string(f.Caches)
	}
	if b, a := windows(before), windows(after); b != a || !strings.Contains(b, "values") {
		t.Errorf("the anomaly baseline changed across the not-ready reports and the full sync:\nbefore %s\nafter  %s", b, a)
	}
}

// The anomaly counter is exported at 0 for the monitored cache before any
// anomaly.
func TestAnomalyCounterExportedAtZero(t *testing.T) {
	initAnomalyMetrics("rtr.example:3323")
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, mf := range mfs {
		if mf.GetName() != "raven_rtr_anomaly_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["cache"] == "rtr.example:3323" && m.GetCounter().GetValue() == 0 {
				seen[labels["severity"]] = true
			}
		}
	}
	for _, sev := range telemetry.AnomalySeverities {
		if !seen[sev] {
			t.Errorf("raven_rtr_anomaly_total{severity=%q} not exported at 0", sev)
		}
	}
}

func ptr[T any](v T) *T { return &v }
