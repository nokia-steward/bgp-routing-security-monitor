package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// ndjsonSchemaPath is the NDJSON contract (docs/reference/telemetry-ndjson.md).
const ndjsonSchemaPath = "../../schema/rtr-monitor-ndjson.v1.json"

// warmDetector returns a detector whose windows for each cache are past warm-up
// with a quiet baseline: a ~600 s cadence, ~100 ms syncs, a few VRPs per
// sync. A sync of 1,200 VRPs is then a statistical anomaly.
func warmDetector(caches ...string) *telemetry.Detector {
	d := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	for _, cache := range caches {
		warmCache(d, cache)
	}
	return d
}

// warmCache gives d warmDetector's baseline for cache.
func warmCache(d *telemetry.Detector, cache string) {
	base := time.Now().Add(-48 * time.Hour)
	for i := range 150 {
		d.ObserveSyncTotals(cache, base.Add(time.Duration(i)*10*time.Minute), map[string]float64{
			telemetry.MetricIntervalSince: float64(600*time.Second + time.Duration(i%7)*time.Second),
			telemetry.MetricSyncDuration:  float64(100*time.Millisecond + time.Duration(i%5)*time.Millisecond),
			telemetry.MetricVRPAnnounced:  float64(i % 5),
			telemetry.MetricVRPWithdrawn:  float64(i % 4),
			telemetry.MetricASPAAnnounced: float64(i % 2),
			telemetry.MetricASPAWithdrawn: 0,
		}, telemetry.Totals{VRPs: 1250, ASPAs: 2})
	}
}

// waitDisconnect waits for a disconnected record with the given reason.
func (m *monitorRun) waitDisconnect(t *testing.T, reason string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, r := range m.records(t, "disconnected") {
			if r["disconnect_reason"] == reason {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no disconnected record with reason %s within 5s; NDJSON:\n%s", reason, m.ndjson)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// contractScenarios drive raven rtr monitor (its client, recorder and
// detector, as RunE wires them) against the fake RTR cache, together
// through every record type and every enum value the contract lists. Each
// returns the NDJSON the monitor wrote.
var contractScenarios = map[string]func(t *testing.T) string{
	// connected, sync (full and incremental), a statistical anomaly, reset
	// and its structural anomaly, error and its structural anomaly,
	// disconnected (error_report).
	"lifecycle at version 2": func(t *testing.T) string {
		srv := rtrtest.NewServer(t, monitorCache(2))
		srv.SetData(rtrtest.GenVRPs(0, 50, 65001), []rtrtest.ASPASet{
			{Customer: 64500, Providers: []uint32{64501}}, {Customer: 64510, Providers: []uint32{64511}},
		})
		m := runMonitorWith(t, srv, "auto", nil, warmDetector(srv.Addr()))
		m.waitRecords(t, "sync", 1)
		srv.Advance(rtrtest.Delta{
			AnnounceVRPs: rtrtest.GenVRPs(1000, 1200, 65002), WithdrawVRPs: rtrtest.GenVRPs(0, 3, 65001),
			AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64520, Providers: []uint32{64521}}}, WithdrawASPAs: []uint32{64510},
		})
		srv.Notify()
		m.waitRecords(t, "anomaly", 1)
		srv.Session().Send(rtrtest.CacheReset(2))
		m.waitRecords(t, "reset", 1)
		m.waitRecords(t, "sync", 3)
		m.waitRecords(t, "anomaly", 2)
		srv.Session().Send(rtrtest.ErrorReport(2, 0, "Corrupt Data"))
		m.waitDisconnect(t, "error_report")
		m.waitRecords(t, "anomaly", 3)
		m.stop()
		return m.ndjson.String()
	},
	// version_downgrade (unsupported_version), disconnected
	// (version_upgrade) when the cache gains version 2, disconnected (eof).
	"downgrade, upgrade, eof": func(t *testing.T) string {
		srv := rtrtest.NewServer(t, monitorCache(1))
		m := runMonitor(t, srv, "auto", func(c *rtr.Client) { c.SetVersionReprobeInterval(50 * time.Millisecond) })
		m.waitRecords(t, "sync", 1)
		srv.SetMaxVersion(2)
		// The code 4 downgrade has its own disconnected (error_report):
		// wait for each reason, not a count.
		m.waitDisconnect(t, "version_upgrade")
		m.waitRecords(t, "sync", 2)
		srv.Session().Close()
		m.waitDisconnect(t, "eof") // before stop, or the session ends as shutdown
		m.stop()
		return m.ndjson.String()
	},
	// version_downgrade (session_dropped), disconnected (reset), then
	// disconnected (shutdown) on stop.
	"session dropped": func(t *testing.T) string {
		cfg := monitorCache(1)
		cfg.Unsupported = rtrtest.CloseRST
		m := runMonitor(t, rtrtest.NewServer(t, cfg), "auto", nil)
		m.waitDisconnect(t, "reset")
		m.waitRecords(t, "sync", 1)
		m.stop()
		return m.ndjson.String()
	},
	// cache_not_ready and its disconnected (error_report, code 2).
	"no data available": func(t *testing.T) string {
		srv := rtrtest.NewServer(t, monitorCache(2))
		srv.Then(rtrtest.ReportError(rtrtest.CodeNoDataAvailable))
		m := runMonitor(t, srv, "auto", nil)
		m.waitRecords(t, "cache_not_ready", 1)
		m.waitDisconnect(t, "error_report")
		m.stop()
		return m.ndjson.String()
	},
	// disconnected (timeout): Refresh and Retry 1 s, the first poll
	// unanswered.
	"timeout": func(t *testing.T) string {
		cfg := monitorCache(2)
		cfg.Refresh, cfg.Retry = 1, 1
		srv := rtrtest.NewServer(t, cfg)
		m := runMonitor(t, srv, "auto", nil)
		m.waitRecords(t, "sync", 1)
		srv.Then(rtrtest.Stall)
		m.waitDisconnect(t, "timeout")
		m.stop()
		return m.ndjson.String()
	},
	// proto_version 0 throughout (a version 0 End of Data).
	"pinned to version 0": func(t *testing.T) string {
		m := runMonitor(t, rtrtest.NewServer(t, monitorCache(2)), "0", nil)
		m.waitRecords(t, "sync", 1)
		m.stop()
		return m.ndjson.String()
	},
	// Three caches compared: divergence with every kind a majority allows
	// (vrp_missing, vrp_extra, aspa_missing, aspa_extra, aspa_mismatch) and
	// aspa_split, divergence_resolved, and an upstream_change carrying every
	// kind of change.
	"three caches compared": func(t *testing.T) string {
		s := newCaches(t, 2, 2, 2)
		a, b, c := s[0], s[1], s[2]
		a.SetData(append(slices.Clone(baseVRPs), rtrtest.GenVRPs(6000, 2, 65003)...), []rtrtest.ASPASet{
			{Customer: 64500, Providers: []uint32{64501, 64502}}, {Customer: 64510, Providers: []uint32{64511}},
			{Customer: 64520, Providers: []uint32{64521}}, {Customer: 64530, Providers: []uint32{1}},
		})
		b.SetData(baseVRPs, []rtrtest.ASPASet{
			{Customer: 64500, Providers: []uint32{64501, 64502}}, {Customer: 64510, Providers: []uint32{64511}},
			{Customer: 64530, Providers: []uint32{2}},
		})
		c.SetData(baseVRPs[2:], []rtrtest.ASPASet{
			{Customer: 64500, Providers: []uint32{64501}}, {Customer: 64530, Providers: []uint32{3}},
		})
		r := runCompare(t, s, testSettle, warmDetector(addrs(s...)...))
		outlast()
		r.tick(t, a)
		r.waitRecords(t, "divergence", 3)
		// b's only difference is the three-way split on 64530: c takes
		// b's provider set, and b agrees with the majority again.
		r.advance(t, c, rtrtest.Delta{WithdrawASPAs: []uint32{64530}})
		r.advance(t, c, rtrtest.Delta{AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64530, Providers: []uint32{2}}}})
		r.waitRecords(t, "divergence_resolved", 1)
		big := rtrtest.Delta{
			AnnounceVRPs: rtrtest.GenVRPs(10000, 1200, 65004), WithdrawVRPs: rtrtest.GenVRPs(10, 3, 65001),
			AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64540, Providers: []uint32{64541}}},
		}
		for _, srv := range s {
			r.advance(t, srv, big)
		}
		r.waitRecords(t, "upstream_change", 1)
		r.stop()
		return r.ndjson.String()
	},
	// Two caches compared: no majority, so vrp_split and aspa_split.
	"two caches compared": func(t *testing.T) string {
		s := newCaches(t, 2, 2)
		s[0].SetData(append(slices.Clone(baseVRPs), extraVRPs...), []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{1}}})
		s[1].SetData(baseVRPs, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{2}}})
		r := runCompare(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))
		outlast()
		r.tick(t, s[0])
		r.waitRecords(t, "divergence", 2)
		r.stop()
		return r.ndjson.String()
	},
	// disconnected (error): pinned to 2, the cache answers at 1.
	"pinned, answered at another version": func(t *testing.T) string {
		cfg := monitorCache(1)
		cfg.Unsupported = rtrtest.Answer
		m := runMonitor(t, rtrtest.NewServer(t, cfg), "2", nil)
		m.waitDisconnect(t, "error")
		m.stop()
		return m.ndjson.String()
	},
}

// The drift test: every NDJSON line raven rtr monitor writes, through every
// record type, is valid against schema/rtr-monitor-ndjson.v1.json: a known
// record type, every required field present, the JSON types and enum
// values the schema says, and no field the schema does not list. And the
// scenarios cover every record type and every enum value, so a field the
// schema requires that stops being emitted, or a record type that stops
// being written, fails too.
func TestNDJSONMatchesContract(t *testing.T) {
	schema := loadSchema(t, ndjsonSchemaPath)
	var mu sync.Mutex
	outputs := map[string]string{}
	t.Run("scenarios", func(t *testing.T) {
		for name, run := range contractScenarios {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				out := run(t)
				mu.Lock()
				outputs[name] = out
				mu.Unlock()
			})
		}
	})
	if t.Failed() {
		return
	}

	seen := map[string]map[string]bool{} // "event_type", "disconnect_reason", ... -> values
	note := func(field string, v any) {
		if seen[field] == nil {
			seen[field] = map[string]bool{}
		}
		seen[field][fmt.Sprint(v)] = true
	}
	var dump []string
	zeroSync := false
	names := make([]string, 0, len(outputs))
	for name := range outputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for i, line := range strings.Split(strings.TrimSpace(outputs[name]), "\n") {
			dump = append(dump, line)
			dec := json.NewDecoder(strings.NewReader(line))
			dec.UseNumber()
			var rec map[string]any
			if err := dec.Decode(&rec); err != nil {
				t.Errorf("%s line %d: not JSON: %v: %s", name, i+1, err, line)
				continue
			}
			for _, e := range schema.validate(rec, schema.root, fmt.Sprintf("%s line %d", name, i+1)) {
				t.Errorf("%s\n    %s", e, line)
			}
			// RFC 3339 with a UTC offset is the contract; RAVEN writes UTC.
			ts, _ := rec["timestamp"].(string)
			if parsed, err := time.Parse(time.RFC3339Nano, ts); err != nil || !strings.HasSuffix(ts, "Z") || parsed.Location() != time.UTC {
				t.Errorf("%s line %d: timestamp %q, want RFC 3339 in UTC (Z): %v", name, i+1, ts, err)
			}
			// A sync's zero values are written, not left out: the
			// scenarios include a sync at serial 0 of an empty cache.
			if rec["event_type"] == "sync" && fmt.Sprint(rec["serial"]) == "0" && fmt.Sprint(rec["vrp_total"]) == "0" &&
				fmt.Sprint(rec["vrp_announced"]) == "0" && fmt.Sprint(rec["aspa_total"]) == "0" {
				zeroSync = true
			}
			for _, f := range []string{"event_type", "disconnect_reason", "downgrade_reason", "sync_type",
				"reset_reason", "category", "severity", "proto_version"} {
				if v, ok := rec[f]; ok {
					note(f, v)
				}
			}
			// The comparison records' nested enums.
			if cs, ok := rec["counts"].(map[string]any); ok {
				for k := range cs {
					note("counts", k)
				}
			}
			if ss, ok := rec["samples"].([]any); ok {
				for _, x := range ss {
					if sm, ok := x.(map[string]any); ok {
						for _, f := range []string{"kind", "change"} {
							if v, ok := sm[f]; ok {
								note(f, v)
							}
						}
					}
				}
			}
		}
	}
	if path := os.Getenv("RAVEN_NDJSON_DUMP"); path != "" {
		os.WriteFile(path, []byte(strings.Join(dump, "\n")+"\n"), 0o644)
	}

	if !zeroSync {
		t.Error("no sync record with serial, vrp_total, vrp_announced and aspa_total written as 0: zero values are left out, or no scenario syncs an empty cache")
	}

	// Coverage: every record type and every enum value the schema lists
	// was emitted. A record type or value that stops being written fails
	// here; one added to the schema must be added to a scenario.
	defs, _ := schema.root["$defs"].(map[string]any)
	for typ := range defs {
		if !seen["event_type"][typ] {
			t.Errorf("no %s record emitted: the scenarios no longer cover it", typ)
		}
	}
	for field, defName := range map[string]string{
		"disconnect_reason": "disconnected", "downgrade_reason": "version_downgrade", "sync_type": "sync",
		"reset_reason": "reset", "category": "anomaly", "severity": "anomaly", "proto_version": "sync",
	} {
		props := schema.def(defName)["properties"].(map[string]any)
		for _, v := range props[field].(map[string]any)["enum"].([]any) {
			if field == "severity" && v == "medium" {
				continue // a correlated trip; the detector tests cover it, see below
			}
			if !seen[field][fmt.Sprint(v)] {
				t.Errorf("%s %v never emitted: the scenarios no longer cover it", field, v)
			}
		}
	}
	// Divergence kinds, as counts keys and as sample kinds, and upstream
	// change kinds.
	divProps := schema.def("divergence")["properties"].(map[string]any)
	sampleProps := func(def string) map[string]any {
		return schema.def(def)["properties"].(map[string]any)["samples"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	}
	for field, enum := range map[string]any{
		"counts": divProps["counts"].(map[string]any)["propertyNames"].(map[string]any)["enum"],
		"kind":   sampleProps("divergence")["kind"].(map[string]any)["enum"],
		"change": sampleProps("upstream_change")["change"].(map[string]any)["enum"],
	} {
		for _, v := range enum.([]any) {
			if !seen[field][fmt.Sprint(v)] {
				t.Errorf("%s %v never emitted: the scenarios no longer cover it", field, v)
			}
		}
	}
	if !slices.Equal(asStrings(divProps["counts"].(map[string]any)["propertyNames"].(map[string]any)["enum"]), telemetry.DivergenceKinds) {
		t.Errorf("schema divergence kinds differ from telemetry.DivergenceKinds %v", telemetry.DivergenceKinds)
	}
}

// severity "medium" (a correlated trip) is written by the same code as
// "high"; it is checked here through RecordAnomaly rather than staged
// through a live session.
func TestNDJSONCorrelatedAnomalyMatchesContract(t *testing.T) {
	schema := loadSchema(t, ndjsonSchemaPath)
	var buf lockedBuffer
	rec := telemetry.NewRecorder(&buf, 1, nil)
	rec.RecordAnomaly(&telemetry.AnomalyEvent{
		Timestamp: time.Now(), Cache: "c:323", Category: "statistical", Trigger: "correlated", Severity: "medium",
		ZScores: map[string]float64{telemetry.MetricIntervalSince: 4, telemetry.MetricSyncDuration: 4.2},
		Raw: map[string]float64{telemetry.MetricIntervalSince: 1.2e12, telemetry.MetricSyncDuration: 3e10,
			telemetry.MetricVRPAnnounced: 3, telemetry.MetricVRPWithdrawn: 1, telemetry.MetricASPAAnnounced: 0, telemetry.MetricASPAWithdrawn: 0},
	})
	line := strings.TrimSpace(buf.String())
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if errs := schema.validate(v, schema.root, "correlated anomaly"); len(errs) != 0 {
		t.Errorf("%v\n    %s", errs, line)
	}
	if v["trigger"] != "interval_since_ns+sync_duration_ns" {
		t.Errorf("trigger %v, want the crossing metrics joined with +", v["trigger"])
	}
}

// The schema's version is the one the code writes.
func TestNDJSONSchemaVersion(t *testing.T) {
	schema := loadSchema(t, ndjsonSchemaPath)
	for name, d := range schema.root["$defs"].(map[string]any) {
		sv := d.(map[string]any)["properties"].(map[string]any)["schema_version"].(map[string]any)["const"]
		if fmt.Sprint(sv) != fmt.Sprint(telemetry.NDJSONSchemaVersion) {
			t.Errorf("%s: schema_version const %v, code writes %d", name, sv, telemetry.NDJSONSchemaVersion)
		}
		if !slices.Contains(asStrings(d.(map[string]any)["required"]), "schema_version") {
			t.Errorf("%s: schema_version not required", name)
		}
	}
	if !strings.Contains(ndjsonSchemaPath, fmt.Sprintf(".v%d.json", telemetry.NDJSONSchemaVersion)) {
		t.Errorf("schema file %s does not carry version %d in its name", ndjsonSchemaPath, telemetry.NDJSONSchemaVersion)
	}
}
