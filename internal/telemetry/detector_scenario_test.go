package telemetry

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// loadScenario reads the hand-crafted NDJSON fixture into SessionEvents.
func loadScenario(t *testing.T) []SessionEvent {
	t.Helper()
	f, err := os.Open("testdata/anomaly_scenario.ndjson")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	var events []SessionEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev SessionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("parse fixture line %q: %v", line, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return events
}

// syncMetrics builds the metric map ObserveSync expects from a sync event.
// The fixture's interval_since_ns stands in for serial_change_interval_ns,
// the timing statistic the detector scores now (#75): the scenario tests
// the detector's trips, not how the interval is measured.
func syncMetrics(ev SessionEvent) map[string]float64 {
	return map[string]float64{
		MetricSerialChangeInterval: float64(ev.IntervalSince),
		MetricSyncDuration:         float64(ev.SyncDuration),
		MetricVRPAnnounced:         float64(ev.VRPAnnounced),
		MetricVRPWithdrawn:         float64(ev.VRPWithdrawn),
		MetricASPAAnnounced:        float64(ev.ASPAAnnounced),
		MetricASPAWithdrawn:        float64(ev.ASPAWithdrawn),
	}
}

func TestDetectorScenario(t *testing.T) {
	events := loadScenario(t)
	if len(events) < 4 {
		t.Fatalf("fixture has %d events, need the prefix + 3 anomaly records", len(events))
	}

	// Fixture layout: [normal prefix...] [hard] [correlated] [structural].
	prefix := events[:len(events)-3]
	hard := events[len(events)-3]
	correlated := events[len(events)-2]
	structural := events[len(events)-1]

	if got := len(prefix); got < DefaultAnomalyConfig().WarmupMinimum {
		t.Fatalf("prefix has %d records, must exceed WarmupMinimum=%d to exercise evaluation",
			got, DefaultAnomalyConfig().WarmupMinimum)
	}

	d := NewDetector(DefaultAnomalyConfig())

	// 1. Normal prefix: no record may return a non-nil event, for either reason
	//    (below warm-up, or evaluated-and-in-baseline once warm).
	for i, ev := range prefix {
		if ev.EventType != EventSync {
			t.Fatalf("prefix[%d] is %q, want a sync record", i, ev.EventType)
		}
		if got := d.ObserveSync(ev.Cache, ev.Timestamp, syncMetrics(ev)); got != nil {
			t.Fatalf("prefix[%d] produced an anomaly: %+v", i, got)
		}
	}

	// 2. Hard trip on vrp_withdrawn.
	if hard.EventType != EventSync {
		t.Fatalf("hard record is %q, want a sync record", hard.EventType)
	}
	hardEv := d.ObserveSync(hard.Cache, hard.Timestamp, syncMetrics(hard))
	if hardEv == nil {
		t.Fatal("hard record produced no anomaly")
	}
	if hardEv.Category != "statistical" || hardEv.Severity != "high" || hardEv.Trigger != MetricVRPWithdrawn {
		t.Fatalf("hard event = {category:%q severity:%q trigger:%q}, want statistical/high/%s",
			hardEv.Category, hardEv.Severity, hardEv.Trigger, MetricVRPWithdrawn)
	}

	// 3. Correlated (medium) trip on sync_duration_ns + interval_since_ns.
	if correlated.EventType != EventSync {
		t.Fatalf("correlated record is %q, want a sync record", correlated.EventType)
	}
	corrEv := d.ObserveSync(correlated.Cache, correlated.Timestamp, syncMetrics(correlated))
	if corrEv == nil {
		t.Fatal("correlated record produced no anomaly")
	}
	if corrEv.Category != "statistical" || corrEv.Severity != "medium" {
		t.Fatalf("correlated event = {category:%q severity:%q}, want statistical/medium",
			corrEv.Category, corrEv.Severity)
	}
	// The detector reports a correlated trip as Trigger=="correlated" with the
	// crossing metrics in ZScores; the "+"-joined name is assembled separately.
	if corrEv.Trigger != "correlated" {
		t.Fatalf("correlated trigger = %q, want %q", corrEv.Trigger, "correlated")
	}
	for _, m := range []string{MetricSyncDuration, MetricSerialChangeInterval} {
		if _, ok := corrEv.ZScores[m]; !ok {
			t.Fatalf("correlated ZScores missing %q: %v", m, corrEv.ZScores)
		}
	}
	if len(corrEv.ZScores) != 2 {
		t.Fatalf("correlated ZScores = %v, want exactly the two crossing metrics", corrEv.ZScores)
	}
	// anomalyTrigger joins the crossers in canonical order (interval before duration).
	if got := anomalyTrigger(corrEv); got != "serial_change_interval_ns+sync_duration_ns" {
		t.Fatalf("anomalyTrigger = %q, want %q", got, "serial_change_interval_ns+sync_duration_ns")
	}

	// 4. Structural trip: fed via ObserveStructural, high regardless of windows.
	if structural.EventType != EventReset {
		t.Fatalf("structural record is %q, want %q", structural.EventType, EventReset)
	}
	structEv := d.ObserveStructural(structural.Cache, "cache_reset", structural.Timestamp)
	if structEv == nil {
		t.Fatal("structural record produced no anomaly")
	}
	if structEv.Category != "structural" || structEv.Severity != "high" {
		t.Fatalf("structural event = {category:%q severity:%q}, want structural/high",
			structEv.Category, structEv.Severity)
	}
}
