package telemetry

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"sync"
	"time"
)

// Data staleness and data regression.
//
// The anomaly detector looks at how a cache syncs (cadence, duration, the
// size of each change). A cache can sync perfectly on time and still serve
// data that has stopped moving: an anycast node whose validator is stuck,
// a Routinator that stopped re-validating. And a cache can go back to data
// it served earlier: a reconnect that lands on a lagging anycast node. The
// DataTracker watches the data itself.
//
// The data changes when a sync's set (VRPs and ASPA records) differs from
// the set before it: the sync record's data_fingerprint (see
// store.Fingerprint), or for records without one its net counts and totals.
// Serials play no part: they restart with every session, differ between
// anycast nodes, and a reconnect that lands on the same data changes the
// serial but not the data.
//
// Per cache, the tracker keeps the gaps between data changes (the last
// DataGapWindow) and learns from them how long this cache's data normally
// goes without a change. The data is stale when it has gone longer than
// max(4 x median gap, 3 x 90th percentile gap, StaleThresholdFloor); with
// fewer than StaleMinGaps gaps known, DefaultStaleThreshold. The age is
// checked at every sync (Observe) and between syncs (Tick), so a cache that
// stops syncing goes stale too.
//
// It also keeps the fingerprints of recent sets (FingerprintHistoryMax, at
// most FingerprintHistoryAge old). A sync whose set is one of those, not
// the current one, is a return to earlier data, data_regressed, if it is
// significant: that set was current, in all, longer than the stale
// threshold, or stopped being current longer ago than that. A briefer
// return is churn (records added and removed again) and a normal data
// change. A significant return is not a data change: the data is as old as
// that set, so the staleness clock runs from when that set was first
// current.

const (
	// DefaultStaleThreshold is the staleness threshold until StaleMinGaps
	// gaps between data changes are known.
	DefaultStaleThreshold = 4 * time.Hour
	// StaleThresholdFloor is the least learned threshold: a cache whose
	// data changes every few minutes is not stale after ten.
	StaleThresholdFloor = 30 * time.Minute
	// StaleMinGaps is how many gaps between data changes the threshold is
	// learned from, at least.
	StaleMinGaps = 20
	// DataGapWindow is how many gaps between data changes are kept per
	// cache: about five days at a change every 15 minutes.
	DataGapWindow = 500
	// FingerprintHistoryMax and FingerprintHistoryAge bound the earlier sets
	// a return to earlier data is recognised against: the last 50 sets,
	// none that stopped being current more than 7 days ago. About 100
	// bytes each, so at most ~5 KB per cache.
	FingerprintHistoryMax = 50
	FingerprintHistoryAge = 7 * 24 * time.Hour

	staleMedianFactor = 4
	staleP90Factor    = 3
)

// ThresholdSource says where a staleness threshold came from.
type ThresholdSource string

const (
	// ThresholdLearned is learned from this cache's gaps between changes.
	ThresholdLearned ThresholdSource = "learned"
	// ThresholdDefault is DefaultStaleThreshold, before StaleMinGaps gaps.
	ThresholdDefault ThresholdSource = "default"
	// ThresholdConfigured is --stale-threshold (rtr.stale-threshold).
	ThresholdConfigured ThresholdSource = "configured"
)

// Scope of a stale episode with several caches compared: every compared
// cache went stale within the settle window (upstream: the data stopped
// moving at its source, or at every cache alike), or only some did
// (local).
const (
	ScopeUpstream = "upstream"
	ScopeLocal    = "local"
)

// DataEventKind is a DataEvent's record type (its event_type).
type DataEventKind string

const (
	DataStale         DataEventKind = "stale"
	DataStaleResolved DataEventKind = "stale_resolved"
	DataRegressed     DataEventKind = "data_regressed"
)

// The structural anomaly triggers for stale data and a return to earlier
// data.
const (
	TriggerDataStale     = "data_stale"
	TriggerDataRegressed = "data_regressed"
)

// DataEvent is what the DataTracker reports: a stale episode beginning or
// ending, or a return to earlier data.
type DataEvent struct {
	Kind      DataEventKind
	Timestamp time.Time
	Cache     string

	// Stale: the serial at detection; when the current data became current
	// (LastChange), how long ago (Gap), the threshold (ExpectedGap), the
	// syncs since that saw no change, where the threshold came from and
	// from how many gaps. Scope only with several caches compared.
	Serial             uint32
	LastChange         time.Time
	Gap                time.Duration
	ExpectedGap        time.Duration
	SyncsWithoutChange int
	ThresholdSource    ThresholdSource
	GapsLearned        int
	Scope              string
	// CacheState is the cache's connection state when the episode began:
	// CacheConnected (serving data that does not change) or
	// CacheDisconnected (unreachable while its last data ages).
	CacheState string

	// StaleResolved: how the episode ended (Resolution); the episode's start and length (StaleSince,
	// Duration), the serials before and after, and the resolving sync's
	// net counts. Gap and LastChange are the data's, as on Stale.
	StaleSince                time.Time
	Duration                  time.Duration
	SerialBefore, SerialAfter uint32
	VRPAdded, VRPRemoved      int
	ASPAAdded, ASPARemoved    int
	SyncType                  SyncType
	Fingerprint               string
	FirstCurrent, LastCurrent time.Time
	Ago                       time.Duration
	Resolution                string
}

// Connection state of a cache when a stale episode began (cache_state).
const (
	CacheConnected    = "connected"
	CacheDisconnected = "disconnected"
)

// How a stale episode ended (resolution): the data changed within a
// session, or the first sync after a reconnect brought new data. A
// reconnect to the same data does not end an episode.
const (
	ResolvedDataChange       = "data_change"
	ResolvedReconnectNewData = "reconnect_new_data"
)

// Anomaly returns the structural anomaly a stale or data_regressed event
// raises; nil for stale_resolved.
func (e DataEvent) Anomaly() *AnomalyEvent {
	trigger := ""
	switch e.Kind {
	case DataStale:
		trigger = TriggerDataStale
	case DataRegressed:
		trigger = TriggerDataRegressed
	default:
		return nil
	}
	return &AnomalyEvent{Timestamp: e.Timestamp, Cache: e.Cache, Category: "structural", Trigger: trigger, Severity: "high"}
}

// fpEntry is an earlier set: its fingerprint, when it was first and last
// current (last: when it stopped being current), the serial it was last
// current at, how many syncs saw it, and how long it was current in all.
type fpEntry struct {
	fp          string
	first, last time.Time
	serial      uint32
	syncs       int
	held        time.Duration
}

type staleEpisode struct {
	since   time.Time
	ev      DataEvent
	pending bool // held until its scope is known (several caches)
}

// cacheData is one cache's data state.
type cacheData struct {
	gaps *metricWindow // gaps between data changes, ns

	have         bool
	current      string    // the current set's fingerprint
	currentFirst time.Time // when the current set was first current: the staleness clock
	lastChange   time.Time // the last data change (not a return to earlier data)
	serial       uint32
	totals       Totals
	noChange     int // syncs since the last data change
	currentSyncs int // syncs that saw the current set
	// currentSince is when the current set's present stint began;
	// currentHeld how long it was current in earlier stints.
	currentSince time.Time
	currentHeld  time.Duration
	history      []fpEntry
	stale        *staleEpisode
	regressions  int
	// connected is whether the cache has a session: set by its connected
	// record or any sync, cleared by its disconnected record.
	// droppedSinceSync is whether a session ended, or a new one began,
	// since its last sync.
	connected        bool
	droppedSinceSync bool
}

// DataTracker detects stale data and returns to earlier data per cache, from
// sync records (Observe). It is safe for concurrent use.
type DataTracker struct {
	mu        sync.Mutex
	threshold time.Duration // override; 0 learns
	group     func() (members []string, settle time.Duration)
	caches    map[string]*cacheData
}

// NewDataTracker returns a tracker that learns each cache's threshold.
func NewDataTracker() *DataTracker {
	return &DataTracker{caches: make(map[string]*cacheData)}
}

// SetThreshold makes d the staleness threshold for every cache, in place of
// the learned one; 0 goes back to learning.
func (t *DataTracker) SetThreshold(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.threshold = max(d, 0)
}

// SetGroup makes the tracker report the scope of stale episodes among
// several compared caches: group returns the caches compared now and the
// settle window. A stale record is then held until its scope is known: at
// once when every compared cache is stale within the settle window
// (upstream), or when the settle window has passed since it went stale
// (local), at the first sync or Tick after that.
func (t *DataTracker) SetGroup(group func() (members []string, settle time.Duration)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.group = group
}

func (t *DataTracker) cacheLocked(name string) *cacheData {
	cd := t.caches[name]
	if cd == nil {
		cd = &cacheData{gaps: newMetricWindow(DataGapWindow)}
		t.caches[name] = cd
	}
	return cd
}

// thresholdLocked returns cd's staleness threshold, where it came from and
// how many gaps it knows.
func (t *DataTracker) thresholdLocked(cd *cacheData) (time.Duration, ThresholdSource, int) {
	n := cd.gaps.count()
	if t.threshold > 0 {
		return t.threshold, ThresholdConfigured, n
	}
	if n < StaleMinGaps {
		return DefaultStaleThreshold, ThresholdDefault, n
	}
	vals := cd.gaps.sorted()
	median := medianOfSorted(vals)
	p90 := quantileOfSorted(vals, 0.9)
	thr := math.Max(math.Max(staleMedianFactor*median, staleP90Factor*p90), float64(StaleThresholdFloor))
	return time.Duration(thr), ThresholdLearned, n
}

// quantileOfSorted is the nearest-rank q-quantile of a sorted, non-empty
// slice.
func quantileOfSorted(sorted []float64, q float64) float64 {
	i := int(math.Ceil(q*float64(len(sorted)))) - 1
	return sorted[min(max(i, 0), len(sorted)-1)]
}

// Threshold returns cache's staleness threshold now, where it came from, and
// how many gaps between data changes it knows.
func (t *DataTracker) Threshold(cache string) (time.Duration, ThresholdSource, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.thresholdLocked(t.cacheLocked(cache))
}

// DataStatus is a cache's data state at a time.
type DataStatus struct {
	// Age is how long the cache's current data has been current (since
	// when it was first current, for a return to earlier data).
	Age time.Duration
	// Stale reports a stale episode in progress.
	Stale bool
	// CacheState is the stale episode's cache_state; empty when not stale.
	CacheState string
	// Regressions is how many returns to earlier data were seen.
	Regressions int
}

// Status returns cache's data state at now; ok is false before its first
// sync.
func (t *DataTracker) Status(cache string, now time.Time) (st DataStatus, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cd := t.caches[cache]
	if cd == nil || !cd.have {
		return DataStatus{}, false
	}
	st = DataStatus{Age: max(now.Sub(cd.currentFirst), 0), Stale: cd.stale != nil, Regressions: cd.regressions}
	if cd.stale != nil {
		st.CacheState = cd.stale.ev.CacheState
	}
	return st, true
}

// identity returns the set a sync record's cache holds, as a fingerprint,
// whether it differs from cd's current set, and whether it is a stand-in.
//
// A record without data_fingerprint (from a RAVEN before it) stands in for
// it with its net counts and totals: the data changed if the sync added or
// removed anything, or the totals moved; the stand-in fingerprint of a
// changed set is its serial and totals, so equal totals at the same serial
// after different data count as the same set. Records from before the net
// counts carry their PDU counts there instead (see normalizeLegacySync).
func identity(cd *cacheData, ev SessionEvent) (fp string, changed, standIn bool) {
	if ev.DataFingerprint != "" {
		return ev.DataFingerprint, !cd.have || ev.DataFingerprint != cd.current, false
	}
	net := ev.VRPAdded + ev.VRPRemoved + ev.ASPAAdded + ev.ASPARemoved
	if cd.have && net == 0 && TotalsOf(ev) == cd.totals {
		return cd.current, false, true
	}
	return fmt.Sprintf("serial=%d vrps=%d aspas=%d", ev.Serial, ev.VRPTotal, ev.ASPATotal), true, true
}

// Observe takes in one record and returns what it showed. A sync can show a
// return to earlier data, a stale episode ending or beginning (with several
// caches, a held stale record of any cache whose scope is now known). A
// connected or disconnected record only updates the cache's connection
// state (see CacheState). Other records are ignored.
func (t *DataTracker) Observe(ev SessionEvent) []DataEvent {
	switch ev.EventType {
	case EventSync:
	case EventConnected, EventDisconnected:
		t.mu.Lock()
		defer t.mu.Unlock()
		cd := t.cacheLocked(ev.Cache)
		// Either one means the session the last sync came from is over:
		// records from older RAVENs have no disconnected record, only the
		// next session's connected.
		cd.connected = ev.EventType == EventConnected
		cd.droppedSinceSync = cd.have
		return nil
	default:
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := ev.Timestamp
	cd := t.cacheLocked(ev.Cache)
	// A sync is proof of a session, whether or not its connected record was
	// seen. Whether the session dropped since the last sync decides how an
	// episode it ends was resolved.
	reconnected := cd.droppedSinceSync
	cd.connected, cd.droppedSinceSync = true, false
	fp, changed, standIn := identity(cd, ev)
	before := cd.serial
	cd.serial = ev.Serial
	var out []DataEvent

	switch {
	case !cd.have:
		cd.have = true
		cd.becomeCurrent(fp, now, 0)
		cd.lastChange = now

	case !changed:
		cd.noChange++
		cd.currentSyncs++
		out = append(out, t.checkStaleLocked(ev.Cache, cd, now)...)

	default:
		if fp != cd.current {
			cd.retire(now, before)
		}
		if i := cd.find(fp, standIn); i >= 0 {
			h := cd.history[i]
			cd.history = slices.Delete(cd.history, i, i+1)
			if t.significantLocked(cd, h, now) {
				// A return to an earlier set: not a data change. The
				// data is as old as that set.
				cd.becomeCurrent(fp, now, h.held)
				cd.currentFirst, cd.currentSyncs = h.first, h.syncs+1
				cd.noChange++
				cd.regressions++
				out = append(out, DataEvent{
					Kind: DataRegressed, Timestamp: now, Cache: ev.Cache,
					SerialBefore: before, SerialAfter: ev.Serial, SyncType: ev.SyncType, Fingerprint: fp,
					FirstCurrent: h.first, LastCurrent: h.last, Ago: now.Sub(h.last),
				})
				out = append(out, t.checkStaleLocked(ev.Cache, cd, now)...)
				break
			}
			// Too brief, and too recent, to be anything but churn: a
			// record added and removed again. A normal data change, and
			// the set's earlier stints are forgotten.
		}
		cd.gaps.add(float64(now.Sub(cd.lastChange)))
		if ep := cd.stale; ep != nil {
			if ep.pending {
				out = append(out, t.releaseLocked(cd))
			}
			out = append(out, DataEvent{
				Kind: DataStaleResolved, Timestamp: now, Cache: ev.Cache, Resolution: resolution(reconnected),
				LastChange: cd.currentFirst, Gap: now.Sub(cd.currentFirst),
				StaleSince: ep.since, Duration: now.Sub(ep.since),
				SerialBefore: before, SerialAfter: ev.Serial, SyncType: ev.SyncType,
				VRPAdded: ev.VRPAdded, VRPRemoved: ev.VRPRemoved, ASPAAdded: ev.ASPAAdded, ASPARemoved: ev.ASPARemoved,
			})
			cd.stale = nil
		}
		cd.becomeCurrent(fp, now, 0)
		cd.lastChange = now
		cd.noChange = 0
	}
	cd.totals = TotalsOf(ev)
	cd.prune(now)
	return append(out, t.releaseHeldLocked(now)...)
}

// Tick evaluates every cache's data age at now, between syncs: a cache whose
// data outlasts its threshold goes stale when it does, not at its next sync,
// and one that stops syncing altogether goes stale too. It returns the stale
// records that begin, and the held ones whose scope is now known, in cache
// order. raven rtr monitor and raven serve call it every 15 seconds.
func (t *DataTracker) Tick(now time.Time) []DataEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	names := make([]string, 0, len(t.caches))
	for name, cd := range t.caches {
		if cd.have {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var out []DataEvent
	for _, name := range names {
		out = append(out, t.checkStaleLocked(name, t.caches[name], now)...)
	}
	return append(out, t.releaseHeldLocked(now)...)
}

func cacheState(cd *cacheData) string {
	if cd.connected {
		return CacheConnected
	}
	return CacheDisconnected
}

func resolution(reconnected bool) string {
	if reconnected {
		return ResolvedReconnectNewData
	}
	return ResolvedDataChange
}

// becomeCurrent makes fp cd's current set from now, as first current now,
// having been current for held before. A data change also sets lastChange.
func (cd *cacheData) becomeCurrent(fp string, now time.Time, held time.Duration) {
	cd.current, cd.currentFirst, cd.currentSince, cd.currentHeld = fp, now, now, held
	cd.currentSyncs = 1
}

// significantLocked reports whether returning to h at now is worth a
// data_regressed: h was current, in all, for longer than cd's stale
// threshold, or stopped being current longer ago than that. A set that
// toggles back every sync (a record added in one sync and removed in the
// next, churn of the same few records) is neither.
func (t *DataTracker) significantLocked(cd *cacheData, h fpEntry, now time.Time) bool {
	thr, _, _ := t.thresholdLocked(cd)
	return h.held > thr || now.Sub(h.last) > thr
}

// retire moves cd's current set into its history, as current until now at
// serial.
func (cd *cacheData) retire(now time.Time, serial uint32) {
	cd.history = append(cd.history, fpEntry{fp: cd.current, first: cd.currentFirst, last: now, serial: serial,
		syncs: cd.currentSyncs, held: cd.currentHeld + now.Sub(cd.currentSince)})
}

// find returns the index of the earlier set fp in cd's history, or -1.
//
// A stand-in (serial and totals, see identity) matches only a set that at
// least two syncs saw. Totals move by a few records per sync, a random walk
// that revisits its values, and serials restart with every session: on the
// anycast fixture, serial and totals alone matched five sets from earlier
// sessions that were current for a single sync, each a coincidence. A set
// that a sync confirmed unchanged is one the cache really held for a while.
// Real fingerprints need no such rule.
func (cd *cacheData) find(fp string, standIn bool) int {
	return slices.IndexFunc(cd.history, func(e fpEntry) bool { return e.fp == fp && (!standIn || e.syncs >= 2) })
}

// prune bounds the history: FingerprintHistoryMax sets, none that stopped
// being current more than FingerprintHistoryAge before now.
func (cd *cacheData) prune(now time.Time) {
	cd.history = slices.DeleteFunc(cd.history, func(e fpEntry) bool { return now.Sub(e.last) > FingerprintHistoryAge })
	if n := len(cd.history) - FingerprintHistoryMax; n > 0 {
		cd.history = slices.Delete(cd.history, 0, n)
	}
}

// checkStaleLocked starts a stale episode if cd's data has outlasted its
// threshold and none is in progress. Without a group the record is
// returned at once; with one it is held for its scope.
func (t *DataTracker) checkStaleLocked(name string, cd *cacheData, now time.Time) []DataEvent {
	if cd.stale != nil {
		return nil
	}
	thr, src, n := t.thresholdLocked(cd)
	age := now.Sub(cd.currentFirst)
	if age <= thr {
		return nil
	}
	cd.stale = &staleEpisode{since: now, pending: t.group != nil, ev: DataEvent{
		Kind: DataStale, Timestamp: now, Cache: name, Serial: cd.serial,
		LastChange: cd.currentFirst, Gap: age, ExpectedGap: thr, SyncsWithoutChange: cd.noChange,
		ThresholdSource: src, GapsLearned: n, CacheState: cacheState(cd),
	}}
	if cd.stale.pending {
		return nil
	}
	return []DataEvent{cd.stale.ev}
}

// releaseHeldLocked returns the held stale records whose scope is known at
// now, in cache order.
func (t *DataTracker) releaseHeldLocked(now time.Time) []DataEvent {
	if t.group == nil {
		return nil
	}
	names := make([]string, 0, len(t.caches))
	for name, cd := range t.caches {
		if cd.stale != nil && cd.stale.pending {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var out []DataEvent
	for _, name := range names {
		cd := t.caches[name]
		members, settle := t.group()
		// Nothing to compare with (fewer than two caches compared now):
		// no scope to wait for.
		if len(members) < 2 || t.upstreamLocked(cd) || now.Sub(cd.stale.since) > settle {
			out = append(out, t.releaseLocked(cd))
		}
	}
	return out
}

// upstreamLocked reports whether every compared cache, cd's among them, is
// stale, each within the settle window of cd's going stale.
func (t *DataTracker) upstreamLocked(cd *cacheData) bool {
	members, settle := t.group()
	if len(members) < 2 || !slices.ContainsFunc(members, func(m string) bool { return t.caches[m] == cd }) {
		return false
	}
	for _, m := range members {
		o := t.caches[m]
		if o == nil || o.stale == nil {
			return false
		}
		if d := o.stale.since.Sub(cd.stale.since); d > settle || d < -settle {
			return false
		}
	}
	return true
}

// releaseLocked returns cd's held stale record with its scope, as known
// now (an episode ending before its settle window passed is decided early).
func (t *DataTracker) releaseLocked(cd *cacheData) DataEvent {
	ev := cd.stale.ev
	members, _ := t.group()
	switch {
	case len(members) < 2:
		// Nothing to compare with: no scope.
	case t.upstreamLocked(cd):
		ev.Scope = ScopeUpstream
	default:
		ev.Scope = ScopeLocal
	}
	cd.stale.pending = false
	return ev
}

// gapSnapshots returns every cache's gap history, for the anomaly snapshot.
func (t *DataTracker) gapSnapshots() map[string]windowSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]windowSnapshot, len(t.caches))
	for name, cd := range t.caches {
		if cd.gaps.count() > 0 {
			out[name] = cd.gaps.snapshot()
		}
	}
	return out
}

// restoreGaps loads gap histories from an anomaly snapshot.
func (t *DataTracker) restoreGaps(gaps map[string]windowSnapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for name, snap := range gaps {
		t.cacheLocked(name).gaps.restore(snap)
	}
}

// Caches returns the names of the caches the tracker has seen, sorted.
func (t *DataTracker) Caches() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	names := make([]string, 0, len(t.caches))
	for name := range t.caches {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
