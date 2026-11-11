package telemetry

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Recorder is the sink for RTR SessionEvents. Each recorded event is written
// as one NDJSON line to the configured sink and mirrored onto a buffered
// channel for downstream consumers (e.g. the anomaly detector).
//
// A nil *Recorder is a valid no-op: Record and Close may be called on it
// safely. This lets callers hold an optional recorder without nil checks at
// every call site.
type Recorder struct {
	mu  sync.Mutex
	enc *json.Encoder

	events chan SessionEvent
	log    *slog.Logger
}

// NewRecorder returns a Recorder that writes NDJSON to sink and buffers up to
// buf events on the channel returned by Events. A buf of 0 uses an unbuffered
// channel; sends that would block are dropped (see Record).
func NewRecorder(sink io.Writer, buf int, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	if buf < 0 {
		buf = 0
	}
	return &Recorder{
		enc:    json.NewEncoder(sink),
		events: make(chan SessionEvent, buf),
		log:    log.With("subsystem", "telemetry"),
	}
}

// Events returns the channel on which recorded events are emitted. Consumers
// must drain it promptly; a full channel causes Record to drop events rather
// than block the producing RTR read loop.
func (r *Recorder) Events() <-chan SessionEvent {
	if r == nil {
		return nil
	}
	return r.events
}

// Record writes ev as an NDJSON line and performs a non-blocking send on the
// event channel. It is safe to call on a nil Recorder (no-op). If ev.Timestamp
// is the zero value it is stamped with the current time. Timestamps are
// written in UTC.
func (r *Recorder) Record(ev SessionEvent) {
	if r == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	ev.Timestamp = ev.Timestamp.UTC()
	ev.SchemaVersion = NDJSONSchemaVersion

	r.mu.Lock()
	if err := r.enc.Encode(ev); err != nil {
		r.log.Error("failed to write telemetry event", "error", err, "cache", ev.Cache, "event_type", ev.EventType)
	}
	r.mu.Unlock()

	// Non-blocking send: a stalled or absent consumer must never wall the RTR
	// read loop. Dropped events are logged so the gap is visible.
	select {
	case r.events <- ev:
	default:
		r.log.Warn("telemetry event channel full, dropping event", "cache", ev.Cache, "event_type", ev.EventType)
	}
}

// anomalyRecord is the NDJSON form of a detected anomaly, written to the same
// sink as SessionEvent. event_type is always "anomaly".
type anomalyRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Cache     string    `json:"cache"`
	EventType string    `json:"event_type"`
	// SchemaVersion is NDJSONSchemaVersion.
	SchemaVersion int                `json:"schema_version"`
	Category      string             `json:"category"`
	Trigger       string             `json:"trigger"`
	Severity      string             `json:"severity"`
	ZScores       map[string]float64 `json:"z_scores,omitempty"`
	Raw           map[string]float64 `json:"raw,omitempty"`
}

// RecordAnomaly writes ev as an NDJSON "anomaly" record to the same sink as
// Record, serialized by the same mutex so an anomaly line never interleaves
// with a SessionEvent line. Unlike Record it does not echo onto the event
// channel: anomalies are terminal outputs, not inputs to further detection.
// Safe to call on a nil Recorder (no-op).
func (r *Recorder) RecordAnomaly(ev *AnomalyEvent) {
	if r == nil || ev == nil {
		return
	}
	rec := anomalyRecord{
		Timestamp:     ev.Timestamp.UTC(),
		Cache:         ev.Cache,
		EventType:     "anomaly",
		SchemaVersion: NDJSONSchemaVersion,
		Category:      ev.Category,
		Trigger:       anomalyTrigger(ev),
		Severity:      ev.Severity,
		ZScores:       ev.ZScores,
		Raw:           ev.Raw,
	}

	r.mu.Lock()
	if err := r.enc.Encode(rec); err != nil {
		r.log.Error("failed to write anomaly event", "error", err, "cache", ev.Cache, "trigger", rec.Trigger)
	}
	r.mu.Unlock()
}

// anomalyTrigger derives the record's trigger string. On a correlated trip the
// detector sets Trigger == "correlated"; the record instead lists the metrics
// that crossed the soft threshold, joined with "+" in canonical order for
// readable logs and demos. Any other trigger (a hard-trip metric name or a
// structural event type) passes through unchanged.
func anomalyTrigger(ev *AnomalyEvent) string {
	if ev.Trigger != "correlated" {
		return ev.Trigger
	}
	var names []string
	for _, m := range trackedMetrics {
		if _, ok := ev.ZScores[m]; ok {
			names = append(names, m)
		}
	}
	if len(names) == 0 {
		return ev.Trigger
	}
	return strings.Join(names, "+")
}

// Close closes the event channel. It is safe to call on a nil Recorder and
// must be called at most once. After Close, Record must not be called.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	close(r.events)
}
