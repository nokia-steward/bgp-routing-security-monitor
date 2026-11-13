package cli

import (
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

// #66: in raven rtr monitor a duplicate announcement is an error record
// (code 7, error_origin client, error_count) and a high structural anomaly
// with trigger protocol_error, one per sync. vrp_total counts the VRP once.
// The session is not dropped: a Reset Query on it resyncs, and the resync's
// full sync, faulty too, is the second error; the rate limit stops there.
func TestMonitorDuplicateAnnouncement(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(2))
	vrps := rtrtest.GenVRPs(0, 3, 65001)
	srv.SetData(vrps, nil)
	srv.RepeatInReset(vrps[:2], nil)
	anomaliesBefore := rtrtest.CounterSum("raven_rtr_anomaly_total", srv.Addr())
	m := runMonitor(t, srv, "auto", nil)
	syncs := m.waitRecords(t, "sync", 2)
	anomalies := m.waitRecords(t, "anomaly", 2)
	m.stop()

	for i, s := range syncs {
		if s["vrp_total"] != 3.0 || s["sync_type"] != "full" {
			t.Errorf("sync %d %v, want vrp_total 3 (each distinct VRP once), full", i, s)
		}
	}
	errs := m.records(t, "error")
	if len(errs) != 2 {
		t.Fatalf("%d error records, want one per sync (2); NDJSON:\n%s", len(errs), m.ndjson)
	}
	for _, e := range errs {
		if e["error_code"] != 7.0 || e["error_origin"] != "client" || e["error_count"] != 2.0 {
			t.Errorf("error record %v, want error_code 7, error_origin client, error_count 2", e)
		}
	}
	for _, a := range anomalies {
		if a["category"] != "structural" || a["severity"] != "high" || a["trigger"] != "protocol_error" {
			t.Errorf("anomaly %v, want a high structural protocol_error anomaly", a)
		}
	}
	if got := rtrtest.CounterSum("raven_rtr_anomaly_total", srv.Addr()) - anomaliesBefore; got != 2 {
		t.Errorf("raven_rtr_anomaly_total rose by %v, want 2", got)
	}
	resets := 0
	for _, q := range srv.Received() {
		if q.Type == rtrtest.PDUResetQuery {
			resets++
		}
	}
	if resets != 2 {
		t.Errorf("%d Reset Queries, want 2: the first sync and one self-healing resync", resets)
	}
	for _, d := range m.records(t, "disconnected") {
		if d["disconnect_reason"] != "shutdown" {
			t.Errorf("disconnected %v: a protocol error must not end the session", d)
		}
	}
}
