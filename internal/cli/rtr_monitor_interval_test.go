package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

// #75: Routinator 0.16 lowers its End of Data refresh to 1-2 s before each
// validation run, so the monitor polls again within seconds and finds the
// serial unchanged. On a cache announcing refresh 2, then 1, then 600, with
// no serial change, those polls raise no anomaly and do not enter the
// serial_change_interval_ns window: they are not serial changes.
func TestMonitorShortRefreshPollsAreNoAnomaly(t *testing.T) {
	cfg := monitorCache(2)
	cfg.Refresh = 2
	srv := rtrtest.NewServer(t, cfg)
	srv.SetData(rtrtest.GenVRPs(0, 3, 65001), nil)
	detector := warmDetector(srv.Addr())
	m := runMonitorWith(t, srv, "auto", nil, detector)

	m.waitRecords(t, "sync", 1) // the full sync, announcing refresh 2
	srv.SetRefresh(1)
	m.waitRecords(t, "sync", 2) // 2 s later, serial unchanged, refresh 1
	srv.SetRefresh(600)
	syncs := m.waitRecords(t, "sync", 3) // 1 s later, serial unchanged, refresh 600
	m.stop()

	for i, s := range syncs[1:3] {
		if s["serial_changed"] != false || s["sync_type"] != "incremental" {
			t.Fatalf("sync %d %v, want an incremental poll with the serial unchanged", i+1, s)
		}
	}
	if gap := time.Duration(syncs[2]["interval_since_ns"].(float64)); gap > 1500*time.Millisecond {
		t.Errorf("third poll %v after the second, want about 1 s (refresh 1)", gap)
	}
	if a := m.records(t, "anomaly"); len(a) != 0 {
		t.Errorf("anomalies %v, want none from polls that found the serial unchanged", a)
	}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := detector.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Caches map[string]map[string]struct {
			Pos int `json:"pos"`
		} `json:"caches"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if w := file.Caches[srv.Addr()]; w["serial_change_interval_ns"].Pos != 150 {
		t.Errorf("serial_change_interval_ns window at %d values, want warmDetector's 150: polls entered it", w["serial_change_interval_ns"].Pos)
	}
	if _, ok := file.Caches[srv.Addr()]["interval_since_ns"]; ok {
		t.Error("snapshot has an interval_since_ns window; the detector no longer scores it")
	}
}
