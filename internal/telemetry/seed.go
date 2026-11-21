package telemetry

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
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

// SeedGaps fills in the gap history of those of caches that have none (an
// anomaly snapshot from before data_gaps, one without that cache, or no
// snapshot) from the sync records in r, a raven rtr monitor NDJSON log: the
// gaps a replay of them learns, by the same rules as the live tracker (its
// --stale-threshold; data_fingerprint where present, the totals stand-in
// before it). It does not read r when every cache has a history. It
// returns the gaps seeded for each cache that had none, 0 included, and
// how many lines it skipped as unreadable (a line cut short by a crash,
// say). An error reading r seeds nothing.
func (t *DataTracker) SeedGaps(r io.Reader, caches []string) (seeded map[string]int, skipped int, err error) {
	t.mu.Lock()
	threshold := t.threshold
	var need []string
	for _, c := range caches {
		if cd := t.caches[c]; (cd == nil || cd.gaps.count() == 0) && !slices.Contains(need, c) {
			need = append(need, c)
		}
	}
	t.mu.Unlock()
	if len(need) == 0 {
		return nil, 0, nil
	}

	replay := NewDataTracker()
	replay.SetThreshold(threshold)
	br := bufio.NewReader(r)
	for {
		line, rerr := br.ReadBytes('\n')
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return nil, 0, fmt.Errorf("read log: %w", rerr)
		}
		if line = bytes.TrimSpace(line); len(line) > 0 {
			var ev SessionEvent
			switch {
			case json.Unmarshal(line, &ev) != nil:
				skipped++
			case ev.EventType == EventSync && slices.Contains(need, ev.Cache):
				normalizeLegacySync(&ev, line)
				replay.Observe(ev)
			}
		}
		if rerr != nil {
			break
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	seeded = make(map[string]int, len(need))
	for _, c := range need {
		seeded[c] = 0
		cd := t.cacheLocked(c)
		if src := replay.caches[c]; src != nil && cd.gaps.count() == 0 {
			cd.gaps.restore(src.gaps.snapshot())
			seeded[c] = cd.gaps.count()
		}
	}
	return seeded, skipped, nil
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
