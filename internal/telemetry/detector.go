package telemetry

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Metric names tracked per sync by the anomaly detector. Exported so the
// integration and seed paths (later steps) can build the metrics map with the
// exact keys ObserveSync expects.
const (
	MetricIntervalSince = "interval_since_ns"
	MetricSyncDuration  = "sync_duration_ns"
	MetricVRPAnnounced  = "vrp_announced"
	MetricVRPWithdrawn  = "vrp_withdrawn"
	MetricASPAAnnounced = "aspa_announced"
	MetricASPAWithdrawn = "aspa_withdrawn"
)

// trackedMetrics is the canonical evaluation order. Iterating this (rather
// than ranging the input map, whose order is randomized) keeps trigger
// selection and z-score maps deterministic across calls.
var trackedMetrics = []string{
	MetricIntervalSince,
	MetricSyncDuration,
	MetricVRPAnnounced,
	MetricVRPWithdrawn,
	MetricASPAAnnounced,
	MetricASPAWithdrawn,
}

// aspa_* metrics get tighter thresholds than the general metrics: the 14-day
// baseline had far sparser non-zero samples for them (269 aspa_announced, 39
// aspa_withdrawn out of 1345 syncs), so a given deviation carries less
// evidence and warrants earlier flagging. These are fixed per the empirical
// baseline rather than derived from the general config thresholds.
const (
	aspaSoftZThreshold = 3.0
	aspaHardZThreshold = 5.0
)

// AnomalyConfig tunes the statistical detector. See DefaultAnomalyConfig for
// the values derived from the baseline analysis.
type AnomalyConfig struct {
	WindowSize      int     // 500
	WarmupMinimum   int     // 100
	SoftZThreshold  float64 // 3.5 (3.0 for aspa_* metrics)
	HardZThreshold  float64 // 6.0 (5.0 for aspa_* metrics)
	CorrelatedCount int     // 2
}

// DefaultAnomalyConfig returns the detector configuration derived from the
// 14-day baseline collection.
func DefaultAnomalyConfig() AnomalyConfig {
	return AnomalyConfig{
		WindowSize:      500,
		WarmupMinimum:   100,
		SoftZThreshold:  3.5,
		HardZThreshold:  6.0,
		CorrelatedCount: 2,
	}
}

// thresholdsFor returns the (soft, hard) modified-z thresholds for a metric,
// applying the tighter aspa_* thresholds where applicable.
func (c AnomalyConfig) thresholdsFor(metric string) (soft, hard float64) {
	switch metric {
	case MetricASPAAnnounced, MetricASPAWithdrawn:
		return aspaSoftZThreshold, aspaHardZThreshold
	default:
		return c.SoftZThreshold, c.HardZThreshold
	}
}

// metricWindow is a fixed-size ring buffer of the most recent observations for
// a single (cache, metric) pair. It is safe for concurrent use.
type metricWindow struct {
	mu     sync.Mutex
	values []float64 // fixed-size ring buffer, len == cap
	cap    int
	pos    int
	filled bool
}

// newMetricWindow returns a window holding at most capacity values. A capacity
// below 1 is clamped to 1 so the buffer is always usable.
func newMetricWindow(capacity int) *metricWindow {
	if capacity < 1 {
		capacity = 1
	}
	return &metricWindow{
		values: make([]float64, capacity),
		cap:    capacity,
	}
}

// add inserts v, overwriting the oldest value once the buffer is full.
func (w *metricWindow) add(v float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.values[w.pos] = v
	w.pos = (w.pos + 1) % w.cap
	if w.pos == 0 {
		w.filled = true
	}
}

// count returns the number of values currently held (up to cap).
func (w *metricWindow) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.countLocked()
}

func (w *metricWindow) countLocked() int {
	if w.filled {
		return w.cap
	}
	return w.pos
}

// medianMAD returns the median and the median absolute deviation of the
// current window contents. ok is false when the window is empty. Ring order is
// irrelevant to both statistics, so the live values are copied and sorted.
func (w *metricWindow) medianMAD() (median, mad float64, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := w.countLocked()
	if n == 0 {
		return 0, 0, false
	}

	vals := make([]float64, n)
	if w.filled {
		copy(vals, w.values)
	} else {
		copy(vals, w.values[:w.pos])
	}
	sort.Float64s(vals)
	median = medianOfSorted(vals)

	devs := make([]float64, n)
	for i, v := range vals {
		devs[i] = math.Abs(v - median)
	}
	sort.Float64s(devs)
	mad = medianOfSorted(devs)

	return median, mad, true
}

// medianOfSorted returns the median of an already-sorted, non-empty slice.
func medianOfSorted(sorted []float64) float64 {
	n := len(sorted)
	mid := n / 2
	if n%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// modifiedZ computes the Iglewicz-Hoaglin modified z-score. It reports ok ==
// false when MAD is 0, signalling insufficient variance to evaluate reliably.
func modifiedZ(x, median, mad float64) (z float64, ok bool) {
	if mad == 0 {
		return 0, false
	}
	return 0.6745 * (x - median) / mad, true
}

// AnomalyEvent describes a detected anomaly. Category is "structural" or
// "statistical". For statistical events, ZScores holds every metric that
// crossed the soft threshold and Raw holds the observed metric values.
type AnomalyEvent struct {
	Timestamp time.Time
	Cache     string
	Category  string // "structural" | "statistical"
	Trigger   string // metric name, or "correlated", or event type
	Severity  string // one of AnomalySeverities
	ZScores   map[string]float64
	Raw       map[string]float64
}

// AnomalySeverities are the severities the detector reports.
var AnomalySeverities = []string{"high", "medium"}

// Detector maintains per-cache, per-metric rolling windows and evaluates each
// sync against them. It is safe for concurrent use.
type Detector struct {
	cfg     AnomalyConfig
	mu      sync.Mutex
	windows map[string]map[string]*metricWindow // cache -> metric -> window
}

// NewDetector returns a detector configured with cfg.
func NewDetector(cfg AnomalyConfig) *Detector {
	return &Detector{
		cfg:     cfg,
		windows: make(map[string]map[string]*metricWindow),
	}
}

// ObserveStructural records a structural event (cache_reset / error_report).
// These bypass the statistical model entirely — the baseline had zero of
// either, so any occurrence is anomalous by definition. No window is touched.
func (d *Detector) ObserveStructural(cache, eventType string, ts time.Time) *AnomalyEvent {
	return &AnomalyEvent{
		Timestamp: ts,
		Cache:     cache,
		Category:  "structural",
		Trigger:   eventType,
		Severity:  "high",
	}
}

// ErrorCodeNoDataAvailable is RTR Error Report code 2 (RFC 8210 §12): the
// cache has no data to serve yet, typically because it is still running its
// first validation after starting.
const ErrorCodeNoDataAvailable uint16 = 2

// ObserveError classifies an Error Report from the cache. No Data Available
// is a cache that is starting up, not a fault: it is not an anomaly, and
// ObserveError returns nil (the RTR client records it as an
// EventCacheNotReady event). Any other error is a high-severity structural
// anomaly. No window is touched either way.
func (d *Detector) ObserveError(cache string, code *uint16, ts time.Time) *AnomalyEvent {
	if code != nil && *code == ErrorCodeNoDataAvailable {
		return nil
	}
	return d.ObserveStructural(cache, "error_report", ts)
}

// ObserveSync evaluates one sync's metrics against the rolling windows and
// updates them. It returns a non-nil event on a hard trip (any metric whose z
// reaches the hard threshold) or a correlated trip (at least CorrelatedCount
// metrics whose z reaches the soft threshold), otherwise nil. Thresholds are
// one-sided: only values above the window median can trip.
//
// Evaluation uses the window contents as they stand before this sync's values
// are inserted. On a hard trip, the confirmed-anomalous metrics are excluded
// from insertion to avoid poisoning the baseline; every other observed value
// is inserted normally.
func (d *Detector) ObserveSync(cache string, ts time.Time, metrics map[string]float64) *AnomalyEvent {
	d.mu.Lock()
	defer d.mu.Unlock()

	cacheWindows := d.windows[cache]
	if cacheWindows == nil {
		cacheWindows = make(map[string]*metricWindow, len(trackedMetrics))
		d.windows[cache] = cacheWindows
	}

	raw := make(map[string]float64)
	softZ := make(map[string]float64)
	hardSet := make(map[string]bool)
	hardTrigger := ""
	hardZ := -1.0

	var present []string
	for _, name := range trackedMetrics {
		v, ok := metrics[name]
		if !ok {
			continue
		}
		present = append(present, name)
		raw[name] = v

		w := cacheWindows[name]
		if w == nil {
			w = newMetricWindow(d.cfg.WindowSize)
			cacheWindows[name] = w
		}

		// Warm-up: not enough samples to evaluate; the value is still
		// inserted below.
		if w.count() < d.cfg.WarmupMinimum {
			continue
		}
		median, mad, ok := w.medianMAD()
		if !ok {
			continue
		}
		z, ok := modifiedZ(v, median, mad)
		if !ok {
			continue // MAD == 0: insufficient variance to evaluate.
		}
		// Upper tail only, for every tracked metric: the failures worth
		// flagging (a stalled validator, a slow repository, a burst of
		// churn) all push values up. A shorter interval, a faster sync or a
		// quieter delta is never anomalous, however large its negative z.
		soft, hard := d.cfg.thresholdsFor(name)
		if z >= soft {
			softZ[name] = z
		}
		if z >= hard {
			hardSet[name] = true
			// Largest z wins the Trigger slot; ties resolve to the first
			// metric in canonical order since we only replace on strictly
			// greater z.
			if z > hardZ {
				hardZ = z
				hardTrigger = name
			}
		}
	}

	switch {
	case len(hardSet) > 0:
		// Insert every observed value except the confirmed hard-trip anomalies.
		for _, name := range present {
			if hardSet[name] {
				continue
			}
			cacheWindows[name].add(raw[name])
		}
		return &AnomalyEvent{
			Timestamp: ts,
			Cache:     cache,
			Category:  "statistical",
			Severity:  "high",
			Trigger:   hardTrigger,
			ZScores:   softZ,
			Raw:       raw,
		}

	case len(softZ) >= d.cfg.CorrelatedCount:
		// Soft trips are borderline/plausibly legitimate and median/MAD is
		// robust to a modest fraction of them, so all values are inserted.
		for _, name := range present {
			cacheWindows[name].add(raw[name])
		}
		return &AnomalyEvent{
			Timestamp: ts,
			Cache:     cache,
			Category:  "statistical",
			Severity:  "medium",
			Trigger:   "correlated",
			ZScores:   softZ,
			Raw:       raw,
		}

	default:
		for _, name := range present {
			cacheWindows[name].add(raw[name])
		}
		return nil
	}
}
