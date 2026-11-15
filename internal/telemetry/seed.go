package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// SeedWindowFill reports one window's fill level after seeding.
type SeedWindowFill struct {
	Cache  string
	Metric string
	Count  int
	Cap    int
}

// SeedSummary reports the outcome of SeedBaseline. Fills is ordered by cache
// name and then canonical metric order for stable presentation.
type SeedSummary struct {
	LinesProcessed int
	SyncCount      int // total sync records seen (includes full syncs)
	FullSyncSkip   int // full syncs excluded from the windows (subset of SyncCount)
	Fills          []SeedWindowFill
	// DataGaps is, per cache, the gaps between data changes learned (see
	// DataTracker) and the staleness threshold they give, by cache name.
	DataGaps []SeedDataGaps
}

// SeedDataGaps reports one cache's learned gaps between data changes.
type SeedDataGaps struct {
	Cache     string
	Gaps      int
	Threshold time.Duration
	Source    ThresholdSource
}

// SeedBaseline replays recorded NDJSON telemetry from r into a fresh Detector
// (configured with DefaultAnomalyConfig), populating the rolling windows so the
// resulting snapshot can warm-start a live monitor.
//
// Only incremental sync records feed the windows; connected/disconnected and
// structural (reset/error) records are skipped, as are full syncs (Reset Query
// table dumps) — their near-whole-table "announced" counts are not comparable
// to the incremental deltas the baseline models and must not touch the windows.
// The input is treated as ground-truth-normal, so this is purely about filling
// windows, not detecting. Anomaly events returned by ObserveSync are discarded.
// Blank lines are ignored; any non-blank line that fails to parse aborts with an
// error rather than silently degrading the baseline.
func SeedBaseline(r io.Reader) (*Detector, *SeedSummary, error) {
	detector := NewDetector(DefaultAnomalyConfig())
	summary := &SeedSummary{}

	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var ev SessionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, nil, fmt.Errorf("parse line %d: %w", lineNo, err)
		}
		summary.LinesProcessed++

		if ev.EventType != EventSync {
			continue
		}
		summary.SyncCount++
		normalizeLegacySync(&ev, []byte(line))

		// Every sync, full ones too, shows whether the data changed: the
		// gaps between changes teach the staleness threshold.
		detector.data.Observe(ev)

		// Full syncs report near the entire table as "announced"; they are not
		// comparable to incremental deltas, so they never feed the windows.
		// Mirrors the live monitor path (internal/cli/rtr_monitor.go).
		if ev.SyncType == SyncTypeFull {
			summary.FullSyncSkip++
			continue
		}

		detector.ObserveSyncTotals(ev.Cache, ev.Timestamp, SyncMetrics(ev), TotalsOf(ev))
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read input: %w", err)
	}

	summary.Fills = detector.windowFills()
	for _, cache := range detector.data.Caches() {
		thr, src, n := detector.data.Threshold(cache)
		summary.DataGaps = append(summary.DataGaps, SeedDataGaps{Cache: cache, Gaps: n, Threshold: thr, Source: src})
	}
	return detector, summary, nil
}

// normalizeLegacySync fills in the net counts of an incremental sync record
// from a RAVEN before them (line is the record as read): its PDU counts
// stand in, which is what such a RAVEN's detector observed. Absent JSON
// fields unmarshal to zero, matching the live path's "default optional
// metrics to 0" convention. A full sync's PDU counts are its whole data set,
// not a change: its net counts stay 0, and DataTracker compares its totals.
func normalizeLegacySync(ev *SessionEvent, line []byte) {
	if ev.SyncType == SyncTypeFull || hasNetCounts(line) {
		return
	}
	ev.VRPAdded, ev.VRPRemoved = ev.VRPAnnounced, ev.VRPWithdrawn
	ev.ASPAAdded, ev.ASPARemoved = ev.ASPAAnnounced, ev.ASPAWithdrawn
}

// windowFills returns the fill level of every window, ordered by cache name and
// then canonical metric order.
func (d *Detector) windowFills() []SeedWindowFill {
	d.mu.Lock()
	defer d.mu.Unlock()

	caches := make([]string, 0, len(d.windows))
	for cache := range d.windows {
		caches = append(caches, cache)
	}
	sort.Strings(caches)

	var fills []SeedWindowFill
	for _, cache := range caches {
		windows := d.windows[cache]
		for _, metric := range trackedMetrics {
			w, ok := windows[metric]
			if !ok {
				continue
			}
			fills = append(fills, SeedWindowFill{
				Cache:  cache,
				Metric: metric,
				Count:  w.count(),
				Cap:    w.cap,
			})
		}
	}
	return fills
}

// hasNetCounts reports whether a sync record carries the net counts
// (vrp_added, vrp_removed, aspa_added, aspa_removed), which RAVEN writes on
// every sync record since they were added.
func hasNetCounts(line []byte) bool {
	var probe struct {
		VRPAdded *int `json:"vrp_added"`
	}
	return json.Unmarshal(line, &probe) == nil && probe.VRPAdded != nil
}
