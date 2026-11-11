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

// Totals is the size of a cache's data set as of a sync: the VRPs and ASPA
// records it holds. The count metrics' minimum spread is relative to it.
type Totals struct {
	VRPs  int
	ASPAs int
}

// TotalsOf returns a sync event's totals.
func TotalsOf(ev SessionEvent) Totals { return Totals{VRPs: ev.VRPTotal, ASPAs: ev.ASPATotal} }

// SyncMetrics builds the metric map ObserveSync expects from a sync event.
func SyncMetrics(ev SessionEvent) map[string]float64 {
	return map[string]float64{
		MetricIntervalSince: float64(ev.IntervalSince),
		MetricSyncDuration:  float64(ev.SyncDuration),
		MetricVRPAnnounced:  float64(ev.VRPAnnounced),
		MetricVRPWithdrawn:  float64(ev.VRPWithdrawn),
		MetricASPAAnnounced: float64(ev.ASPAAnnounced),
		MetricASPAWithdrawn: float64(ev.ASPAWithdrawn),
	}
}

// Minimum spread (scale floor) per statistic. The modified z divides by the
// window's MAD, which for a cache polled on a fixed timer is close to 0, or
// exactly 0: Fort polled every 600 s had an interval MAD of 5 ms and a sync
// duration MAD of 1.3 ms (#59), so a sync 0.6 s slower than usual scored
// z = 341, and a window with MAD 0 could never trip at all. The scale is
// therefore max(MAD, floor), with a floor that says how small a deviation
// is still noise for that statistic, whatever the window's spread:
//
//   - interval_since_ns, sync_duration_ns: max(1% of |median|, 1 s). Timer
//     and scheduling jitter, and the time a sync itself takes, are of the
//     order of a second or of a small fraction of the cadence; 1% of a 600 s
//     cadence is 6 s. A hard trip then needs about 9 s (1 s floor x 6 /
//     0.6745) above a short median, or ~9% of a long one: a stalled or
//     slowed validator, or a cadence that really changed.
//   - vrp_*: max(1, 0.01% of VRPs held). On a ~1M-VRP cache that is 100,
//     so a hard trip needs ~890 VRPs above the median in one sync: ordinary
//     churn (23 of a million at DaKnObNET, z = 7.08 before) stays quiet, a
//     1,200-VRP burst trips. ASPA Explorer's notifier, tuned by hand on
//     live caches, alerts at 1,000.
//   - aspa_*: max(1, 0.1% of ASPAs held). ASPA sets are three orders of
//     magnitude smaller and change in ones; 0.1% keeps a floor of 1 (a
//     single record) on today's caches and grows with them. The ASPA hard
//     threshold is 5, so a hard trip needs ~8 records above the median on
//     a cache holding up to 1,000.
//
// The floor of 1 for counts covers an empty or unknown total. A floor is a
// scale, not a minimum effect: z still means deviations from this cache's
// normal, and alerting policy (how large a change is worth a page) stays
// with the consumer.
const (
	timingFloorAbs = float64(time.Second)
	timingFloorRel = 0.01
	vrpFloorRel    = 0.0001
	aspaFloorRel   = 0.001
	countFloorAbs  = 1.0
)

// minScale returns the scale floor for metric, given its window median and
// the cache's totals.
func minScale(metric string, median float64, totals Totals) float64 {
	switch metric {
	case MetricIntervalSince, MetricSyncDuration:
		return math.Max(timingFloorRel*math.Abs(median), timingFloorAbs)
	case MetricVRPAnnounced, MetricVRPWithdrawn:
		return math.Max(countFloorAbs, vrpFloorRel*float64(totals.VRPs))
	case MetricASPAAnnounced, MetricASPAWithdrawn:
		return math.Max(countFloorAbs, aspaFloorRel*float64(totals.ASPAs))
	default:
		return countFloorAbs
	}
}

// scale is the spread a metric's z is measured in: the window's MAD, never
// below the metric's floor.
func scale(metric string, median, mad float64, totals Totals) float64 {
	return math.Max(mad, minScale(metric, median, totals))
}

// modifiedZ computes the Iglewicz-Hoaglin modified z-score against a scale
// (see scale), which is always positive.
func modifiedZ(x, median, scale float64) float64 {
	return 0.6745 * (x - median) / scale
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
//
// The count metrics' minimum spread depends on the cache's totals, which
// ObserveSync does not have: it takes them as zero. The RTR monitor and the
// seed path use ObserveSyncTotals.
func (d *Detector) ObserveSync(cache string, ts time.Time, metrics map[string]float64) *AnomalyEvent {
	return d.ObserveSyncTotals(cache, ts, metrics, Totals{})
}

// ObserveSyncTotals is ObserveSync for a cache holding totals, which set the
// count metrics' minimum spread.
func (d *Detector) ObserveSyncTotals(cache string, ts time.Time, metrics map[string]float64, totals Totals) *AnomalyEvent {
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
		// MAD 0 and MAD near 0 alike: the floor keeps the scale realistic,
		// so a constant window still trips on a large deviation.
		z := modifiedZ(v, median, scale(name, median, mad, totals))
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
