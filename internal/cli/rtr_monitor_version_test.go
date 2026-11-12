package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// monitorRun is rtr monitor's client and event consumer, as RunE wires
// them, running against a fake cache, with the NDJSON they write.
type monitorRun struct {
	srv    *rtrtest.Server
	client *rtr.Client
	ndjson *lockedBuffer
	stop   func()
}

// runMonitor starts the monitor's client (built by newMonitorClient with
// --rtr-version rtrVersion) and its consumer against srv. configure, if
// not nil, runs on the client before it starts.
func runMonitor(t *testing.T, srv *rtrtest.Server, rtrVersion string, configure func(*rtr.Client)) *monitorRun {
	t.Helper()
	return runMonitorWith(t, srv, rtrVersion, configure, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))
}

// runMonitorWith is runMonitor with the given anomaly detector (one with a
// warm baseline, say).
func runMonitorWith(t *testing.T, srv *rtrtest.Server, rtrVersion string, configure func(*rtr.Client),
	detector *telemetry.Detector) *monitorRun {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &monitorRun{srv: srv, ndjson: &lockedBuffer{}}
	rec := telemetry.NewRecorder(m.ndjson, 64, quiet)
	client, err := newMonitorClient(srv.Addr(), "tcp", rtrVersion, rec, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(client)
	}
	m.client = client
	initAnomalyMetrics(srv.Addr())

	consumed := make(chan struct{})
	go func() {
		defer close(consumed)
		consumeRTREvents(rec, detector, nil, nil, quiet)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.Start(ctx)
	}()
	stopped := false
	m.stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-done // Record must not run after Close
		rec.Close()
		<-consumed
	}
	t.Cleanup(m.stop)
	return m
}

// records returns the NDJSON records of the given event type.
func (m *monitorRun) records(t *testing.T, eventType string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(m.ndjson.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("NDJSON %q: %v", line, err)
		}
		if rec["event_type"] == eventType {
			out = append(out, rec)
		}
	}
	return out
}

// waitRecords waits until the NDJSON holds at least n records of eventType.
func (m *monitorRun) waitRecords(t *testing.T, eventType string, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if recs := m.records(t, eventType); len(recs) >= n {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("fewer than %d %s records within 5s; NDJSON:\n%s", n, eventType, m.ndjson)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func monitorCache(max uint8) rtrtest.ServerConfig {
	return rtrtest.ServerConfig{MaxVersion: max, Session: 3, Refresh: 3600, Retry: 600, Expire: 7200}
}

// #55: a cache that speaks only version 1 turns down the monitor's version
// 2 with Error Report code 4. That is negotiation: one informational
// version_downgrade record (2 -> 1, code 4), no error record, no anomaly
// record and raven_rtr_anomaly_total unchanged.
func TestMonitorCode4DuringNegotiationIsNotAnAnomaly(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(1))
	// The counter is process-wide and a later run may reuse the port.
	anomaliesBefore := rtrtest.CounterSum("raven_rtr_anomaly_total", srv.Addr())
	m := runMonitor(t, srv, "auto", nil)
	m.waitRecords(t, "sync", 1)
	m.stop()

	downs := m.records(t, "version_downgrade")
	if len(downs) != 1 {
		t.Fatalf("%d version_downgrade records, want 1; NDJSON:\n%s", len(downs), m.ndjson)
	}
	d := downs[0]
	if d["proto_version"] != 2.0 || d["next_proto_version"] != 1.0 || d["error_code"] != 4.0 ||
		d["downgrade_reason"] != "unsupported_version" {
		t.Errorf("version_downgrade record %v, want 2 -> 1, error_code 4, unsupported_version", d)
	}
	if n := len(m.records(t, "error")) + len(m.records(t, "anomaly")); n != 0 {
		t.Errorf("%d error or anomaly records, want none; NDJSON:\n%s", n, m.ndjson)
	}
	if got := rtrtest.CounterSum("raven_rtr_anomaly_total", m.srv.Addr()) - anomaliesBefore; got != 0 {
		t.Errorf("raven_rtr_anomaly_total rose by %v, want unchanged", got)
	}
	if got := m.client.ProtocolVersion(); got != 1 {
		t.Errorf("session at version %d, want 1", got)
	}
}

// Code 4 on a session already established is still a fault: the monitor
// records an error and a high structural anomaly, and counts it.
func TestMonitorCode4AfterEstablishedIsAnAnomaly(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(2))
	anomaliesBefore := rtrtest.CounterSum("raven_rtr_anomaly_total", srv.Addr())
	m := runMonitor(t, srv, "auto", nil)
	m.waitRecords(t, "sync", 1)
	m.srv.Session().Send(rtrtest.ErrorReport(2, rtrtest.CodeUnsupportedVersion, "Unsupported Protocol Version"))
	anomalies := m.waitRecords(t, "anomaly", 1)
	m.stop()
	if a := anomalies[0]; a["category"] != "structural" || a["severity"] != "high" || a["trigger"] != "error_report" {
		t.Errorf("anomaly %v, want a high structural error_report anomaly", a)
	}
	if got := rtrtest.CounterSum("raven_rtr_anomaly_total", m.srv.Addr()) - anomaliesBefore; got != 1 {
		t.Errorf("raven_rtr_anomaly_total rose by %v, want 1", got)
	}
	if n := len(m.records(t, "version_downgrade")); n != 0 {
		t.Errorf("%d version_downgrade records for an established session, want 0", n)
	}
}

// #54 and #57: with --rtr-version 0, against a cache that would turn down
// version 2 with code 4, the monitor opens at version 0, records no code 4,
// never re-probes (even with a short re-probe interval), and its connected
// and sync records say "proto_version":0.
func TestMonitorRTRVersionZero(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(0))
	m := runMonitor(t, srv, "0", func(c *rtr.Client) { c.SetVersionReprobeInterval(20 * time.Millisecond) })
	m.waitRecords(t, "sync", 1)
	srv.NoQuery(200*time.Millisecond, "pinned to 0: no re-probe")
	m.stop()

	for _, q := range srv.Received() {
		if q.Version != 0 {
			t.Errorf("query at version %d, want only version 0", q.Version)
		}
	}
	if !strings.Contains(m.ndjson.String(), `"event_type":"connected"`) ||
		!strings.Contains(m.ndjson.String(), `"proto_version":0`) {
		t.Errorf("NDJSON without a connected record at proto_version 0:\n%s", m.ndjson)
	}
	for _, typ := range []string{"connected", "sync", "disconnected"} {
		recs := m.records(t, typ)
		if len(recs) == 0 {
			t.Errorf("no %s record", typ)
		}
		for _, r := range recs {
			if v, ok := r["proto_version"]; !ok || v != 0.0 {
				t.Errorf("%s record proto_version %v (present %t), want 0", typ, v, ok)
			}
		}
	}
	if strings.Contains(m.ndjson.String(), `"error_code":4`) {
		t.Errorf("NDJSON records a code 4:\n%s", m.ndjson)
	}
}

func TestParseMonitorRTRVersion(t *testing.T) {
	for _, tc := range []struct {
		in      string
		version uint8
		pinned  bool
		ok      bool
	}{
		{"auto", 2, false, true},
		{"", 2, false, true},
		{"0", 0, true, true},
		{"1", 1, true, true},
		{"2", 2, true, true},
		{"3", 0, false, false},
		{"v2", 0, false, false},
	} {
		v, pinned, err := parseMonitorRTRVersion(tc.in)
		if (err == nil) != tc.ok || (tc.ok && (v != tc.version || pinned != tc.pinned)) {
			t.Errorf("parseMonitorRTRVersion(%q) = %d, %t, %v; want %d, %t, ok %t", tc.in, v, pinned, err, tc.version, tc.pinned, tc.ok)
		}
	}
}
