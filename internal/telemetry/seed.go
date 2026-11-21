package telemetry

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
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

		if sync, full := detector.replay(ev, []byte(line)); sync {
			summary.SyncCount++
			if full {
				summary.FullSyncSkip++
			}
		}
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

// replay feeds one record of a raven rtr monitor log (line, as read) to d
// as the live monitor does: a sync to the data tracker (full syncs too: they
// show whether the data changed) and to the statistics (ObserveSyncEvent,
// which evaluates no full sync), a connected or disconnected record to the
// serial-change clock (ObserveSession). Anomalies are discarded. It reports
// whether the record was a sync, and a full one.
func (d *Detector) replay(ev SessionEvent, line []byte) (sync, full bool) {
	switch ev.EventType {
	case EventSync:
		normalizeLegacySync(&ev, line)
		d.data.Observe(ev)
		d.ObserveSyncEvent(ev)
		return true, ev.SyncType == SyncTypeFull
	case EventConnected, EventDisconnected:
		d.ObserveSession(ev)
	}
	return false, false
}

// LogSeed is what SeedFromLog seeded for one cache: its gaps between data
// changes, if it had none (Gaps, and how many), and its
// serial_change_interval_ns window, if it had none (Intervals, and how
// many values). A count may be 0: the log held nothing for it.
type LogSeed struct {
	Gaps, Intervals         bool
	GapCount, IntervalCount int
}

// SeedFromLog fills in, for those of caches the anomaly snapshot left
// without them (one from an earlier release, one without that cache, or no
// snapshot), the gap history (#80) and the serial_change_interval_ns window
// (#75) from the records in r, a raven rtr monitor NDJSON log. They are what
// a replay of the log learns, the replay raven rtr seed-baseline makes, by
// the live rules (--stale-threshold; data_fingerprint where present, the
// totals stand-in before it; serial changes within a session). The other
// windows are left as the snapshot had them. It does not read r when every
// cache has both. It returns, per cache that lacked either, what it seeded,
// and how many lines it skipped as unreadable (a line cut short by a crash,
// say). An error reading r seeds nothing.
func (d *Detector) SeedFromLog(r io.Reader, caches []string) (seeded map[string]LogSeed, skipped int, err error) {
	need := map[string]LogSeed{}
	d.data.mu.Lock()
	threshold := d.data.threshold
	for _, c := range caches {
		if cd := d.data.caches[c]; cd == nil || cd.gaps.count() == 0 {
			ls := need[c]
			ls.Gaps = true
			need[c] = ls
		}
	}
	d.data.mu.Unlock()
	d.mu.Lock()
	for _, c := range caches {
		if w := d.windows[c][MetricSerialChangeInterval]; w == nil || w.count() == 0 {
			ls := need[c]
			ls.Intervals = true
			need[c] = ls
		}
	}
	d.mu.Unlock()
	if len(need) == 0 {
		return nil, 0, nil
	}

	scratch := NewDetector(d.cfg)
	scratch.data.SetThreshold(threshold)
	br := bufio.NewReader(r)
	for {
		line, rerr := br.ReadBytes('\n')
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return nil, 0, fmt.Errorf("read log: %w", rerr)
		}
		if line = bytes.TrimSpace(line); len(line) > 0 {
			var ev SessionEvent
			if json.Unmarshal(line, &ev) != nil {
				skipped++
			} else if _, ok := need[ev.Cache]; ok {
				scratch.replay(ev, line)
			}
		}
		if rerr != nil {
			break
		}
	}

	for c, ls := range need {
		if ls.Gaps {
			d.data.mu.Lock()
			cd := d.data.cacheLocked(c)
			if src := scratch.data.caches[c]; src != nil && cd.gaps.count() == 0 {
				cd.gaps.restore(src.gaps.snapshot())
			}
			ls.GapCount = cd.gaps.count()
			d.data.mu.Unlock()
		}
		if ls.Intervals {
			d.mu.Lock()
			if src := scratch.windows[c][MetricSerialChangeInterval]; src != nil && src.count() > 0 {
				if d.windows[c] == nil {
					d.windows[c] = make(map[string]*metricWindow, len(trackedMetrics))
				}
				w := d.windows[c][MetricSerialChangeInterval]
				if w == nil {
					w = newMetricWindow(d.cfg.WindowSize)
					d.windows[c][MetricSerialChangeInterval] = w
				}
				if w.count() == 0 {
					w.restore(src.snapshot())
				}
			}
			if w := d.windows[c][MetricSerialChangeInterval]; w != nil {
				ls.IntervalCount = w.count()
			}
			d.mu.Unlock()
		}
		need[c] = ls
	}
	return need, skipped, nil
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
