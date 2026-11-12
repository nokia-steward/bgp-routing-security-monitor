package telemetry

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/bits"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Cross-cache comparison for raven rtr monitor run against several caches.
//
// Each cache keeps its own VRP and ASPA set (CrossCacheMember), fed from its
// RTR client's update callback. After every End of Data from any cache, the
// sets of every cache that is in a session and has completed a sync in it
// (the compared caches) are compared. An item some compared caches hold and
// others do not is a difference; one that has kept the same shape (who holds
// it) for longer than the settle window is persistent, and is attributed to
// the caches in the minority:
//
//   - held by a majority: missing at the caches that lack it
//   - held by a minority: extra at the caches that hold it
//   - an even split: split, at every compared cache
//
// A cache's persistent differences are reported per episode, not per item:
// one divergence record when its first persistent difference appears, one
// divergence_resolved record when it has no difference left. Separately, a
// change large enough to trip the anomaly detector at every compared cache
// within the settle window, overlapping by at least UpstreamOverlap, is one
// upstream_change: a problem upstream of every validator, not at one.

// Divergence kinds: the keys of a divergence record's counts, the kind of
// each sample, and the kind label of raven_rtr_divergent_items.
const (
	DivergenceVRPMissing   = "vrp_missing"
	DivergenceVRPExtra     = "vrp_extra"
	DivergenceVRPSplit     = "vrp_split"
	DivergenceASPAMissing  = "aspa_missing"
	DivergenceASPAExtra    = "aspa_extra"
	DivergenceASPAMismatch = "aspa_mismatch"
	DivergenceASPASplit    = "aspa_split"
)

// DivergenceKinds lists every divergence kind, in report order.
var DivergenceKinds = []string{
	DivergenceVRPMissing, DivergenceVRPExtra, DivergenceVRPSplit,
	DivergenceASPAMissing, DivergenceASPAExtra, DivergenceASPAMismatch, DivergenceASPASplit,
}

// Upstream change sample ops.
const (
	ChangeVRPAnnounced = "vrp_announced"
	ChangeVRPWithdrawn = "vrp_withdrawn"
	ChangeASPAChanged  = "aspa_changed"
)

const (
	// SettleUnknown is the settle window until every compared cache has an
	// observed refresh interval.
	SettleUnknown = 30 * time.Minute
	// SettleFloor is the least automatic settle window.
	SettleFloor = 10 * time.Minute
	// MaxCrossCaches is how many caches a CrossCache can compare.
	MaxCrossCaches = 64
	// UpstreamOverlap is how far two caches' changes must overlap to be the
	// same change: shared items over the larger change's items.
	UpstreamOverlap = 0.9
	// maxSamples bounds the sample items of a record.
	maxSamples = 20
	// intervalSamples is how many recent interval_since values a cache's
	// median refresh interval is taken over.
	intervalSamples = 15
	// changeRing bounds the recent changes kept per cache to match against
	// the detector's verdicts, and the large ones kept for upstream matching.
	changeRing = 8
)

// vrpKey is a VRP in 24 bytes: the comparison holds one per VRP per cache,
// so it avoids types.VRP's netip.Prefix (32 bytes, with a pointer).
type vrpKey struct {
	hi, lo uint64
	asn    uint32
	bits   uint8
	maxLen uint8
	v6     bool
}

func keyOf(v types.VRP) vrpKey {
	a := v.Prefix.Addr()
	b := a.As16()
	return vrpKey{
		hi: binary.BigEndian.Uint64(b[:8]), lo: binary.BigEndian.Uint64(b[8:]),
		asn: v.ASN, bits: uint8(v.Prefix.Bits()), maxLen: v.MaxLength, v6: !a.Is4(),
	}
}

func (k vrpKey) prefix() netip.Prefix {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], k.hi)
	binary.BigEndian.PutUint64(b[8:], k.lo)
	a := netip.AddrFrom16(b)
	if !k.v6 {
		a = a.Unmap()
	}
	return netip.PrefixFrom(a, int(k.bits))
}

func compareVRPKeys(a, b vrpKey) int {
	if a.v6 != b.v6 {
		if a.v6 {
			return 1
		}
		return -1
	}
	return cmp.Or(cmp.Compare(a.hi, b.hi), cmp.Compare(a.lo, b.lo), cmp.Compare(a.bits, b.bits),
		cmp.Compare(a.maxLen, b.maxLen), cmp.Compare(a.asn, b.asn))
}

// CrossCacheMember is one cache's side of the comparison: its own VRP and
// ASPA set, and its session state. Its methods are the RTR client's
// callbacks.
type CrossCacheMember struct {
	cc   *CrossCache
	name string
	bit  uint64

	vrpStore  *store.VRPStore
	aspaStore *store.ASPAStore

	// The cache's data as of its last End of Data. A VRP the cache
	// announced twice counts twice, as in its VRPStore.
	vrps  map[vrpKey]uint32
	aspas map[uint32][]uint32 // customer AS -> sorted providers

	inSession bool  // connected, and completed a sync in this session
	version   uint8 // the session's RTR version

	intervals []time.Duration // recent interval_since, oldest first

	changes []*ccChange          // recent incremental changes, oldest first
	trips   map[uint32]time.Time // detector trips whose change is not in changes yet
	large   []*ccChange          // recent changes that tripped the detector

	episode  *ccEpisode
	episodes int
	gauges   map[string]int
}

// ccChange is one incremental sync's change at a cache.
type ccChange struct {
	member   *CrossCacheMember
	serial   uint32
	at       time.Time
	ann, wd  []types.VRP
	aspa     []uint32
	tripped  bool
	consumed bool // part of an upstream_change already
	keys     map[changeKey]struct{}
}

type changeKey struct {
	op   uint8 // 0 announced, 1 withdrawn, 2 ASPA changed
	vrp  vrpKey
	cust uint32
}

func (ch *ccChange) keySet() map[changeKey]struct{} {
	if ch.keys == nil {
		ch.keys = make(map[changeKey]struct{}, len(ch.ann)+len(ch.wd)+len(ch.aspa))
		for _, v := range ch.ann {
			ch.keys[changeKey{op: 0, vrp: keyOf(v)}] = struct{}{}
		}
		for _, v := range ch.wd {
			ch.keys[changeKey{op: 1, vrp: keyOf(v)}] = struct{}{}
		}
		for _, c := range ch.aspa {
			ch.keys[changeKey{op: 2, cust: c}] = struct{}{}
		}
	}
	return ch.keys
}

// overlap is the share of items two changes have in common, over the larger
// change's items; 0 when either is empty.
func overlap(a, b *ccChange) float64 {
	ka, kb := a.keySet(), b.keySet()
	if len(ka) == 0 || len(kb) == 0 {
		return 0
	}
	if len(ka) > len(kb) {
		ka, kb = kb, ka
	}
	shared := 0
	for k := range ka {
		if _, ok := kb[k]; ok {
			shared++
		}
	}
	return float64(shared) / float64(max(len(ka), len(kb)))
}

type ccEpisode struct {
	n       int
	started time.Time
}

// vrpDiff is a VRP the compared caches disagree on. first is when it first
// had this shape (compared caches, holders).
type vrpDiff struct {
	first            time.Time
	members, holders uint64
}

// aspaGroup is the compared caches holding one provider set for a customer
// (none: providers nil).
type aspaGroup struct {
	mask      uint64
	providers []uint32
}

// aspaDiff is a customer AS whose provider set the compared caches disagree
// on.
type aspaDiff struct {
	first   time.Time
	members uint64
	sig     uint64 // the grouping's shape
	groups  []aspaGroup
}

// CrossCache compares the data of several RTR caches. It is safe for
// concurrent use: its members' callbacks run on their clients' goroutines,
// ObserveSync on the telemetry consumer's.
type CrossCache struct {
	mu     sync.Mutex
	rec    *Recorder
	log    *slog.Logger
	now    func() time.Time
	settle time.Duration // override; 0 is automatic
	gauge  func(cache, kind string, n int)
	// compared, if set, is told when a cache joins or leaves the comparison.
	compared func(cache string, compared bool)

	members []*CrossCacheMember
	byName  map[string]*CrossCacheMember

	dirty                bool   // some member's data changed since the last diff
	lastMembers, lastV2s uint64 // compared caches as of the last diff
	vrpDiffs             map[vrpKey]*vrpDiff
	aspaDiffs            map[uint32]*aspaDiff
}

// NewCrossCache returns a comparison writing its records to rec. settle, if
// above 0, replaces the automatic settle window. gauge, if not nil, is told
// each cache's persistent divergent items per kind when the count changes.
func NewCrossCache(rec *Recorder, settle time.Duration, gauge func(cache, kind string, n int), log *slog.Logger) *CrossCache {
	if log == nil {
		log = slog.Default()
	}
	return &CrossCache{
		rec: rec, log: log.With("subsystem", "rtr-compare"), now: time.Now, settle: settle, gauge: gauge,
		byName: map[string]*CrossCacheMember{}, vrpDiffs: map[vrpKey]*vrpDiff{}, aspaDiffs: map[uint32]*aspaDiff{},
	}
}

// Add registers a cache and the stores its RTR client fills. Call before
// any client starts.
func (c *CrossCache) Add(name string, vrps *store.VRPStore, aspas *store.ASPAStore) (*CrossCacheMember, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.members) >= MaxCrossCaches {
		return nil, fmt.Errorf("at most %d caches can be compared", MaxCrossCaches)
	}
	if _, dup := c.byName[name]; dup {
		return nil, fmt.Errorf("cache %q given twice", name)
	}
	m := &CrossCacheMember{
		cc: c, name: name, bit: 1 << len(c.members), vrpStore: vrps, aspaStore: aspas,
		vrps: map[vrpKey]uint32{}, aspas: map[uint32][]uint32{}, trips: map[uint32]time.Time{},
		gauges: map[string]int{},
	}
	c.members = append(c.members, m)
	c.byName[name] = m
	return m, nil
}

// Update applies a sync's change to the member's set: the RTR client's
// update callback, with the client's serial. A Full delta re-reads the
// stores.
func (m *CrossCacheMember) Update(d *store.Delta, serial uint32) {
	c := m.cc
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dirty = true
	if d.Full {
		m.vrps = make(map[vrpKey]uint32, m.vrpStore.Count())
		for _, v := range m.vrpStore.All() {
			m.vrps[keyOf(v)]++
		}
		m.aspas = map[uint32][]uint32{}
		for _, r := range m.aspaStore.Snapshot() {
			m.aspas[r.CustomerASN] = r.ProviderASNs
		}
		return
	}
	for _, v := range d.VRPAnnounced {
		m.vrps[keyOf(v)]++
	}
	// One copy per withdrawal, as VRPStore.RemoveVRP.
	for _, v := range d.VRPWithdrawn {
		k := keyOf(v)
		if n := m.vrps[k]; n > 1 {
			m.vrps[k] = n - 1
		} else {
			delete(m.vrps, k)
		}
	}
	for _, cust := range d.ASPACustomers {
		r := m.aspaStore.GetRecord(cust)
		if r == nil {
			delete(m.aspas, cust)
			continue
		}
		ps := make([]uint32, 0, len(r.Providers))
		for p := range r.Providers {
			ps = append(ps, p)
		}
		slices.Sort(ps)
		m.aspas[cust] = ps
	}

	ch := &ccChange{member: m, serial: serial, at: c.now(), ann: d.VRPAnnounced, wd: d.VRPWithdrawn, aspa: d.ASPACustomers}
	m.changes = append(m.changes, ch)
	if len(m.changes) > changeRing {
		m.changes = m.changes[1:]
	}
	if _, ok := m.trips[serial]; ok {
		delete(m.trips, serial)
		c.noteLarge(m, ch)
	}
}

// Synced records a completed sync (End of Data) at RTR version version, and
// compares the caches: the RTR client's sync callback.
func (m *CrossCacheMember) Synced(version uint8) {
	c := m.cc
	c.mu.Lock()
	defer c.mu.Unlock()
	joined := !m.inSession
	m.inSession, m.version = true, version
	if joined && c.compared != nil {
		c.compared(m.name, true)
	}
	c.compare()
}

// Disconnected takes the member out of the comparison until its next
// session completes a sync: the RTR client's disconnect callback.
func (m *CrossCacheMember) Disconnected() {
	c := m.cc
	c.mu.Lock()
	defer c.mu.Unlock()
	if m.inSession && c.compared != nil {
		c.compared(m.name, false)
	}
	m.inSession = false
}

// OnCompared sets fn to be told each time a cache joins the comparison (its
// session completed a sync) or leaves it (it disconnected). Call before any
// client starts.
func (c *CrossCache) OnCompared(fn func(cache string, compared bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.compared = fn
}

// ObserveSync takes in a sync record of a member and the anomaly the
// detector raised on it, if any: its refresh interval, and whether it was a
// large change (a statistical anomaly on a count).
func (c *CrossCache) ObserveSync(ev SessionEvent, anomaly *AnomalyEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.byName[ev.Cache]
	if m == nil || ev.EventType != EventSync {
		return
	}
	if ev.IntervalSince > 0 {
		m.intervals = append(m.intervals, ev.IntervalSince)
		if len(m.intervals) > intervalSamples {
			m.intervals = m.intervals[1:]
		}
	}
	if !largeChange(anomaly) {
		return
	}
	for i := len(m.changes) - 1; i >= 0; i-- {
		if ch := m.changes[i]; ch.serial == ev.Serial && !ch.tripped {
			c.noteLarge(m, ch)
			return
		}
	}
	// The client's update callback has not run yet for this sync.
	m.trips[ev.Serial] = ev.Timestamp
	if len(m.trips) > changeRing {
		var oldest uint32
		var at time.Time
		for s, t := range m.trips {
			if at.IsZero() || t.Before(at) {
				oldest, at = s, t
			}
		}
		delete(m.trips, oldest)
	}
}

// largeChange reports whether anomaly says a sync changed far more than the
// cache's normal: a statistical anomaly on a VRP or ASPA count.
func largeChange(a *AnomalyEvent) bool {
	if a == nil || a.Category != "statistical" {
		return false
	}
	for _, metric := range []string{MetricVRPAnnounced, MetricVRPWithdrawn, MetricASPAAnnounced, MetricASPAWithdrawn} {
		if _, ok := a.ZScores[metric]; ok {
			return true
		}
	}
	return false
}

// comparedLocked returns the compared caches, and the masks of them and of
// those at version 2 (whose ASPA sets are compared).
func (c *CrossCache) comparedLocked() (members []*CrossCacheMember, all, v2 uint64) {
	for _, m := range c.members {
		if m.inSession {
			members = append(members, m)
			all |= m.bit
			if m.version >= 2 {
				v2 |= m.bit
			}
		}
	}
	return members, all, v2
}

// settleLocked is the settle window for members: the override, else twice
// the slowest member's median refresh interval, at least SettleFloor, and
// SettleUnknown while a member has no interval yet.
func (c *CrossCache) settleLocked(members []*CrossCacheMember) time.Duration {
	if c.settle > 0 {
		return c.settle
	}
	var slowest time.Duration
	for _, m := range members {
		if len(m.intervals) == 0 {
			return SettleUnknown
		}
		s := slices.Clone(m.intervals)
		slices.Sort(s)
		med := s[len(s)/2]
		if len(s)%2 == 0 {
			med = (s[len(s)/2-1] + s[len(s)/2]) / 2
		}
		slowest = max(slowest, med)
	}
	return max(2*slowest, SettleFloor)
}

// Settle returns the settle window in effect for the caches compared now.
func (c *CrossCache) Settle() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	members, _, _ := c.comparedLocked()
	return c.settleLocked(members)
}

func (c *CrossCache) names(mask uint64) []string {
	out := []string{}
	for _, m := range c.members {
		if mask&m.bit != 0 {
			out = append(out, m.name)
		}
	}
	return out
}

// compare is run after every End of Data: it brings the differences up to
// date, then opens and closes each compared cache's episode.
func (c *CrossCache) compare() {
	members, all, v2 := c.comparedLocked()
	if len(members) < 2 {
		return
	}
	now := c.now()
	if c.dirty || all != c.lastMembers || v2 != c.lastV2s {
		c.diffVRPs(members, all, now)
		c.diffASPAs(members, v2, now)
		c.dirty, c.lastMembers, c.lastV2s = false, all, v2
	}
	settle := c.settleLocked(members)

	// Per compared cache: persistent items per kind, whether any difference
	// (persistent or not) is attributed to it, when its earliest persistent
	// one appeared.
	type tally struct {
		counts map[string]int
		any    bool
		first  time.Time
	}
	t := make(map[*CrossCacheMember]*tally, len(members))
	for _, m := range members {
		t[m] = &tally{counts: map[string]int{}}
	}
	note := func(mask uint64, kind string, first time.Time) {
		persistent := now.Sub(first) > settle
		for _, m := range members {
			if mask&m.bit == 0 {
				continue
			}
			x := t[m]
			x.any = true
			if persistent {
				x.counts[kind]++
				if x.first.IsZero() || first.Before(x.first) {
					x.first = first
				}
			}
		}
	}
	for _, d := range c.vrpDiffs {
		mask, kind := d.attribution()
		note(mask, kind, d.first)
	}
	for _, d := range c.aspaDiffs {
		for _, a := range d.attribution() {
			note(a.mask, a.kind, d.first)
		}
	}

	for _, m := range members {
		x := t[m]
		total := 0
		for _, n := range x.counts {
			total += n
		}
		switch {
		case m.episode == nil && total > 0:
			m.episodes++
			m.episode = &ccEpisode{n: m.episodes, started: x.first}
			c.emitDivergence(m, members, all, settle, now, x.counts)
		case m.episode != nil && !x.any:
			c.emitResolved(m, all, now)
			m.episode = nil
		}
		if c.gauge != nil {
			for _, k := range DivergenceKinds {
				if n, ok := m.gauges[k]; !ok || n != x.counts[k] {
					m.gauges[k] = x.counts[k]
					c.gauge(m.name, k, x.counts[k])
				}
			}
		}
	}
}

// attribution says which compared caches a VRP difference is attributed to,
// and as what.
func (d *vrpDiff) attribution() (uint64, string) {
	n, h := bits.OnesCount64(d.members), bits.OnesCount64(d.holders)
	switch {
	case 2*h > n:
		return d.members &^ d.holders, DivergenceVRPMissing
	case 2*h < n:
		return d.holders, DivergenceVRPExtra
	default:
		return d.members, DivergenceVRPSplit
	}
}

type aspaAttr struct {
	mask uint64
	kind string
}

// majority returns the index of the group holding a strict majority of the
// compared caches, or -1.
func (d *aspaDiff) majority() int {
	n := bits.OnesCount64(d.members)
	for i, g := range d.groups {
		if 2*bits.OnesCount64(g.mask) > n {
			return i
		}
	}
	return -1
}

// attribution says which compared caches an ASPA difference is attributed
// to, and as what.
func (d *aspaDiff) attribution() []aspaAttr {
	maj := d.majority()
	if maj < 0 {
		return []aspaAttr{{d.members, DivergenceASPASplit}}
	}
	var out []aspaAttr
	for i, g := range d.groups {
		switch {
		case i == maj:
		case len(g.providers) == 0:
			out = append(out, aspaAttr{g.mask, DivergenceASPAMissing})
		case len(d.groups[maj].providers) == 0:
			out = append(out, aspaAttr{g.mask, DivergenceASPAExtra})
		default:
			out = append(out, aspaAttr{g.mask, DivergenceASPAMismatch})
		}
	}
	return out
}

// diffVRPs finds every VRP the compared caches do not all hold. A VRP whose
// shape (compared caches, holders) is unchanged keeps its first-seen time.
func (c *CrossCache) diffVRPs(members []*CrossCacheMember, all uint64, now time.Time) {
	diffs := make(map[vrpKey]*vrpDiff, len(c.vrpDiffs))
	keep := func(k vrpKey, holders uint64) {
		if old := c.vrpDiffs[k]; old != nil && old.members == all && old.holders == holders {
			diffs[k] = old
			return
		}
		diffs[k] = &vrpDiff{first: now, members: all, holders: holders}
	}
	base := members[0]
	for k := range base.vrps {
		h := base.bit
		for _, m := range members[1:] {
			if _, ok := m.vrps[k]; ok {
				h |= m.bit
			}
		}
		if h != all {
			keep(k, h)
		}
	}
	// Whatever the first cache lacks.
	for _, m := range members[1:] {
		for k := range m.vrps {
			if _, ok := base.vrps[k]; ok {
				continue
			}
			if _, ok := diffs[k]; ok {
				continue
			}
			h := uint64(0)
			for _, o := range members[1:] {
				if _, ok := o.vrps[k]; ok {
					h |= o.bit
				}
			}
			keep(k, h)
		}
	}
	c.vrpDiffs = diffs
}

// diffASPAs finds every customer AS whose provider set the compared caches
// at version 2 do not agree on. Caches below version 2 have no ASPA and are
// left out; with fewer than two at version 2 nothing is compared.
func (c *CrossCache) diffASPAs(members []*CrossCacheMember, v2 uint64, now time.Time) {
	diffs := map[uint32]*aspaDiff{}
	var cmpd []*CrossCacheMember
	for _, m := range members {
		if v2&m.bit != 0 {
			cmpd = append(cmpd, m)
		}
	}
	if len(cmpd) >= 2 {
		seen := map[uint32]struct{}{}
		for _, m := range cmpd {
			for cust := range m.aspas {
				if _, ok := seen[cust]; ok {
					continue
				}
				seen[cust] = struct{}{}
				var groups []aspaGroup
				for _, o := range cmpd {
					ps := o.aspas[cust]
					i := slices.IndexFunc(groups, func(g aspaGroup) bool { return slices.Equal(g.providers, ps) })
					if i < 0 {
						groups = append(groups, aspaGroup{providers: ps})
						i = len(groups) - 1
					}
					groups[i].mask |= o.bit
				}
				if len(groups) < 2 {
					continue
				}
				// The shape: the groups' masks, and which group has none.
				h := fnv.New64a()
				sorted := slices.Clone(groups)
				sort.Slice(sorted, func(i, j int) bool { return sorted[i].mask < sorted[j].mask })
				var b [9]byte
				for _, g := range sorted {
					binary.BigEndian.PutUint64(b[:8], g.mask)
					b[8] = 0
					if len(g.providers) == 0 {
						b[8] = 1
					}
					h.Write(b[:])
				}
				d := &aspaDiff{first: now, members: v2, sig: h.Sum64(), groups: groups}
				if old := c.aspaDiffs[cust]; old != nil && old.members == v2 && old.sig == d.sig {
					d.first = old.first
				}
				diffs[cust] = d
			}
		}
	}
	c.aspaDiffs = diffs
}

// DivergenceSample is one item of a divergence record: a VRP or a customer
// AS the cache disagrees on.
type DivergenceSample struct {
	Kind        string  `json:"kind"`
	Prefix      string  `json:"prefix,omitempty"`
	MaxLength   *uint8  `json:"max_length,omitempty"`
	ASN         *uint32 `json:"asn,omitempty"`
	CustomerASN *uint32 `json:"customer_asn,omitempty"`
	// Providers is the cache's provider set; absent when it has none.
	Providers []uint32 `json:"providers,omitempty"`
	// MajorityProviders is the majority's provider set; absent on a split
	// and when the majority has none.
	MajorityProviders []uint32 `json:"majority_providers,omitempty"`
	// Agree are the compared caches that hold what this cache holds (it
	// included), Disagree the others.
	Agree    []string `json:"agree"`
	Disagree []string `json:"disagree"`

	order   int
	vrp     vrpKey
	isASPA  bool
	cust    uint32
	against uint64 // Disagree as a mask
}

type divergenceRecord struct {
	Timestamp     time.Time          `json:"timestamp"`
	Cache         string             `json:"cache"`
	EventType     string             `json:"event_type"`
	SchemaVersion int                `json:"schema_version"`
	Episode       int                `json:"episode"`
	StartedAt     time.Time          `json:"started_at"`
	Compared      []string           `json:"compared"`
	SettleNS      time.Duration      `json:"settle_ns"`
	Counts        map[string]int     `json:"counts"`
	Samples       []DivergenceSample `json:"samples"`
	SplitWith     []string           `json:"split_with,omitempty"`
}

type divergenceResolvedRecord struct {
	Timestamp     time.Time     `json:"timestamp"`
	Cache         string        `json:"cache"`
	EventType     string        `json:"event_type"`
	SchemaVersion int           `json:"schema_version"`
	Episode       int           `json:"episode"`
	StartedAt     time.Time     `json:"started_at"`
	DurationNS    time.Duration `json:"duration_ns"`
	Compared      []string      `json:"compared"`
}

func kindOrder(kind string) int { return slices.Index(DivergenceKinds, kind) }

func (c *CrossCache) emitDivergence(m *CrossCacheMember, members []*CrossCacheMember, all uint64, settle time.Duration, now time.Time, counts map[string]int) {
	persistent := func(first time.Time) bool { return now.Sub(first) > settle }
	var samples []DivergenceSample
	var splitWith uint64
	for k, d := range c.vrpDiffs {
		mask, kind := d.attribution()
		if mask&m.bit == 0 || !persistent(d.first) {
			continue
		}
		same := d.holders
		if d.holders&m.bit == 0 {
			same = all &^ d.holders
		}
		if kind == DivergenceVRPSplit {
			splitWith |= all &^ same
		}
		samples = append(samples, DivergenceSample{Kind: kind, order: kindOrder(kind), vrp: k, against: all &^ same})
	}
	for cust, d := range c.aspaDiffs {
		if !persistent(d.first) {
			continue
		}
		for _, a := range d.attribution() {
			if a.mask&m.bit == 0 {
				continue
			}
			var same uint64
			for _, g := range d.groups {
				if g.mask&m.bit != 0 {
					same = g.mask
				}
			}
			if a.kind == DivergenceASPASplit {
				splitWith |= d.members &^ same
			}
			s := DivergenceSample{Kind: a.kind, order: kindOrder(a.kind), isASPA: true, cust: cust, against: d.members &^ same}
			s.Providers = slices.Clone(m.aspas[cust])
			if maj := d.majority(); maj >= 0 && len(d.groups[maj].providers) > 0 {
				s.MajorityProviders = slices.Clone(d.groups[maj].providers)
			}
			samples = append(samples, s)
		}
	}
	slices.SortFunc(samples, func(a, b DivergenceSample) int {
		if a.order != b.order {
			return cmp.Compare(a.order, b.order)
		}
		if a.isASPA {
			return cmp.Compare(a.cust, b.cust)
		}
		return compareVRPKeys(a.vrp, b.vrp)
	})
	samples = pickSamples(samples, func(s DivergenceSample) int { return s.order })
	for i := range samples {
		s := &samples[i]
		if s.isASPA {
			cust := s.cust
			s.CustomerASN = &cust
		} else {
			maxLen, asn := s.vrp.maxLen, s.vrp.asn
			s.Prefix, s.MaxLength, s.ASN = s.vrp.prefix().String(), &maxLen, &asn
		}
		members := all
		if s.isASPA {
			members = c.aspaDiffs[s.cust].members
		}
		s.Agree, s.Disagree = c.names(members&^s.against), c.names(s.against)
	}
	if samples == nil {
		samples = []DivergenceSample{}
	}
	rec := divergenceRecord{
		Timestamp: now.UTC(), Cache: m.name, EventType: "divergence", SchemaVersion: NDJSONSchemaVersion,
		Episode: m.episode.n, StartedAt: m.episode.started.UTC(), Compared: c.names(all), SettleNS: settle,
		Counts: counts, Samples: samples,
	}
	if splitWith != 0 {
		rec.SplitWith = c.names(splitWith)
	}
	c.log.Warn("RTR cache diverges from the other caches", "cache", m.name, "episode", m.episode.n,
		"counts", counts, "since", m.episode.started, "split_with", rec.SplitWith)
	c.rec.write(rec, m.name, rec.EventType)
}

func (c *CrossCache) emitResolved(m *CrossCacheMember, all uint64, now time.Time) {
	rec := divergenceResolvedRecord{
		Timestamp: now.UTC(), Cache: m.name, EventType: "divergence_resolved", SchemaVersion: NDJSONSchemaVersion,
		Episode: m.episode.n, StartedAt: m.episode.started.UTC(), DurationNS: now.Sub(m.episode.started),
		Compared: c.names(all),
	}
	c.log.Info("RTR cache agrees with the other caches again", "cache", m.name, "episode", m.episode.n,
		"duration", rec.DurationNS)
	c.rec.write(rec, m.name, rec.EventType)
}

// UpstreamChangeCache is one cache's part of an upstream_change.
type UpstreamChangeCache struct {
	Cache        string    `json:"cache"`
	Serial       uint32    `json:"serial"`
	Timestamp    time.Time `json:"timestamp"`
	VRPAnnounced int       `json:"vrp_announced"`
	VRPWithdrawn int       `json:"vrp_withdrawn"`
	ASPAChanged  int       `json:"aspa_changed"`
}

// UpstreamChangeSample is one item every cache's change has.
type UpstreamChangeSample struct {
	Change      string  `json:"change"`
	Prefix      string  `json:"prefix,omitempty"`
	MaxLength   *uint8  `json:"max_length,omitempty"`
	ASN         *uint32 `json:"asn,omitempty"`
	CustomerASN *uint32 `json:"customer_asn,omitempty"`
}

type upstreamChangeRecord struct {
	Timestamp     time.Time              `json:"timestamp"`
	Cache         string                 `json:"cache"`
	EventType     string                 `json:"event_type"`
	SchemaVersion int                    `json:"schema_version"`
	Caches        []string               `json:"caches"`
	Changes       []UpstreamChangeCache  `json:"changes"`
	Overlap       float64                `json:"overlap"`
	SettleNS      time.Duration          `json:"settle_ns"`
	Samples       []UpstreamChangeSample `json:"samples"`
}

// noteLarge records that ch tripped the detector at m, and reports an
// upstream change if every compared cache now has the same one.
func (c *CrossCache) noteLarge(m *CrossCacheMember, ch *ccChange) {
	ch.tripped = true
	m.large = append(m.large, ch)
	if len(m.large) > changeRing {
		m.large = m.large[1:]
	}
	members, _, _ := c.comparedLocked()
	if len(members) < 2 || !m.inSession {
		return
	}
	settle := c.settleLocked(members)
	group := []*ccChange{ch}
	minOverlap := 1.0
	for _, o := range members {
		if o == m {
			continue
		}
		var best *ccChange
		bestOverlap := 0.0
		for _, cand := range o.large {
			d := cand.at.Sub(ch.at)
			if cand.consumed || d > settle || d < -settle {
				continue
			}
			if ov := overlap(ch, cand); ov >= UpstreamOverlap && ov > bestOverlap {
				best, bestOverlap = cand, ov
			}
		}
		if best == nil {
			return // not (yet) at every compared cache
		}
		group = append(group, best)
		minOverlap = min(minOverlap, bestOverlap)
	}
	for _, g := range group {
		g.consumed = true
	}
	c.emitUpstream(m, group, minOverlap, settle)
}

func (c *CrossCache) emitUpstream(m *CrossCacheMember, group []*ccChange, ov float64, settle time.Duration) {
	slices.SortFunc(group, func(a, b *ccChange) int { return cmp.Compare(a.member.bit, b.member.bit) })
	rec := upstreamChangeRecord{
		Timestamp: c.now().UTC(), Cache: m.name, EventType: "upstream_change", SchemaVersion: NDJSONSchemaVersion,
		Overlap: ov, SettleNS: settle, Samples: []UpstreamChangeSample{},
	}
	for _, g := range group {
		rec.Caches = append(rec.Caches, g.member.name)
		rec.Changes = append(rec.Changes, UpstreamChangeCache{
			Cache: g.member.name, Serial: g.serial, Timestamp: g.at.UTC(),
			VRPAnnounced: len(g.ann), VRPWithdrawn: len(g.wd), ASPAChanged: len(g.aspa),
		})
	}
	// Samples: items every cache's change has.
	var common []changeKey
	for k := range group[0].keySet() {
		in := true
		for _, g := range group[1:] {
			if _, ok := g.keySet()[k]; !ok {
				in = false
				break
			}
		}
		if in {
			common = append(common, k)
		}
	}
	slices.SortFunc(common, func(a, b changeKey) int {
		return cmp.Or(cmp.Compare(a.op, b.op), compareVRPKeys(a.vrp, b.vrp), cmp.Compare(a.cust, b.cust))
	})
	common = pickSamples(common, func(k changeKey) int { return int(k.op) })
	for _, k := range common {
		s := UpstreamChangeSample{}
		switch k.op {
		case 0, 1:
			s.Change = ChangeVRPAnnounced
			if k.op == 1 {
				s.Change = ChangeVRPWithdrawn
			}
			maxLen, asn := k.vrp.maxLen, k.vrp.asn
			s.Prefix, s.MaxLength, s.ASN = k.vrp.prefix().String(), &maxLen, &asn
		default:
			cust := k.cust
			s.Change, s.CustomerASN = ChangeASPAChanged, &cust
		}
		rec.Samples = append(rec.Samples, s)
	}
	c.log.Warn("the same large change reached every compared RTR cache: upstream of the validators",
		"caches", rec.Caches, "overlap", ov)
	c.rec.write(rec, m.name, rec.EventType)
}

// pickSamples returns at most maxSamples of items, which are sorted by group
// and within it: taken from each group in turn, so a large group does not
// crowd out a small one, and in the same order.
func pickSamples[T any](items []T, group func(T) int) []T {
	if len(items) <= maxSamples {
		return items
	}
	var groups [][]T
	for i, it := range items {
		if i == 0 || group(it) != group(items[i-1]) {
			groups = append(groups, nil)
		}
		groups[len(groups)-1] = append(groups[len(groups)-1], it)
	}
	taken := make([]int, len(groups))
	for n := 0; n < maxSamples; {
		for g := range groups {
			if n < maxSamples && taken[g] < len(groups[g]) {
				taken[g]++
				n++
			}
		}
	}
	out := make([]T, 0, maxSamples)
	for g := range groups {
		out = append(out, groups[g][:taken[g]]...)
	}
	return out
}

// Tracked returns, per compared cache, how many differences (persistent or
// still settling) are attributed to it, per kind. For tests and
// diagnostics.
func (c *CrossCache) Tracked() map[string]map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]map[string]int{}
	add := func(mask uint64, kind string) {
		for _, m := range c.members {
			if mask&m.bit != 0 {
				if out[m.name] == nil {
					out[m.name] = map[string]int{}
				}
				out[m.name][kind]++
			}
		}
	}
	for _, d := range c.vrpDiffs {
		add(d.attribution())
	}
	for _, d := range c.aspaDiffs {
		for _, a := range d.attribution() {
			add(a.mask, a.kind)
		}
	}
	return out
}
