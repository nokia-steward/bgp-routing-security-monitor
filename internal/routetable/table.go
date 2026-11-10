package routetable

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"sync"

	"github.com/gaissmai/bart"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

const defaultShards = 256

// Table is RAVEN's internal route table: every route of every monitored
// router, in each RIB it is reported in (Adj-RIB-In, Loc-RIB, Adj-RIB-Out),
// with validation annotations.
//
// Architecture: hybrid BART prefix index + sharded flat map (see ARCHITECTURE.md §2.3).
type Table struct {
	// Primary store: sharded flat map keyed by RouteKey (router, peer
	// distinguisher, peer address, prefix, path ID, RIB type)
	shards []shard

	// Prefix index: BART trie mapping prefix -> route keys, of every RIB.
	// A prefix's list holds at most one key per peer, path and RIB carrying
	// it, so it stays short and a linear scan is cheap; a map per prefix
	// would roughly triple the index's memory when most prefixes have a
	// single route.
	//
	// A withdrawal shortens a list in place, and an insert may append into
	// its spare capacity, so a list must not be read once prefixMu is
	// released: readers copy what they need under the lock. Copying on
	// removal instead would put an allocation on every withdrawal.
	prefixMu  sync.RWMutex
	prefixIdx bart.Table[[]types.RouteKey]

	// Secondary index: origin ASN -> route keys, of every RIB
	asnMu  sync.RWMutex
	asnIdx map[uint32]keySet

	// Secondary index: security posture -> route keys, of the default
	// view's routes only (types.DefaultView: Adj-RIB-In pre-policy and
	// Loc-RIB; see Insert)
	postureMu  sync.RWMutex
	postureIdx map[types.SecurityPosture]keySet
}

// keySet is the set of route keys under one ASN or posture index entry.
// These entries used to be slices, scanned linearly on every insert and
// removal; with about a million keys under a single posture that made index
// maintenance quadratic.
type keySet map[types.RouteKey]struct{}

// keys copies the set's members. Callers hold the index's lock: a map must
// not be read while another goroutine writes it.
func (s keySet) keys() []types.RouteKey {
	out := make([]types.RouteKey, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

type shard struct {
	mu     sync.RWMutex
	routes map[types.RouteKey]*types.Route

	// owned indexes the shard's routes by owning BMP session and peer, so a
	// withdraw-all finds the routes it removes without scanning the table.
	// A route is indexed under the OwnerSession and peer it had when
	// inserted; neither may change while it is in the table.
	owned map[ownerKey]routeSet

	// perPeer counts the shard's routes by peer (router, distinguisher and
	// address) and RIB type. It changes exactly when routes does: a key
	// added, or a key removed.
	perPeer map[types.PeerRef]*types.RIBCounts
}

// ownerKey is an owner index entry: a BMP session and one peer it reports,
// with the peer's Loc-RIB routes apart from its other RIBs. The peer
// includes the router, so unowned routes (session 0) of the same peer
// address on two routers are two entries.
type ownerKey struct {
	session uint64
	peer    types.PeerRef
	// locRIB is set for Loc-RIB routes. A Loc-RIB instance's Peer Down
	// removes only these, a BGP peer's only the others, so neither can
	// take the other's routes even if they share a peer address.
	locRIB bool
}

// ownerKeyOf is the owner index entry of a route of peer in RIB rib, owned
// by session.
func ownerKeyOf(session uint64, peer types.PeerRef, rib types.RIBType) ownerKey {
	return ownerKey{session: session, peer: peer, locRIB: rib == types.LocRIB}
}

// routeSet is keyed by pointer rather than RouteKey: 8 bytes per route
// instead of 64, and a pointer also tells a route apart from a later
// announcement stored under the same key.
type routeSet map[*types.Route]struct{}

// own indexes r under its owner. The caller holds s.mu.
func (s *shard) own(r *types.Route) {
	k := ownerKeyOf(r.OwnerSession, r.Peer(), r.RIBType)
	set := s.owned[k]
	if set == nil {
		set = make(routeSet)
		s.owned[k] = set
	}
	set[r] = struct{}{}
}

// disown drops r from the owner index. It is a no-op for a route a Removal
// has already detached. The caller holds s.mu.
func (s *shard) disown(r *types.Route) {
	k := ownerKeyOf(r.OwnerSession, r.Peer(), r.RIBType)
	if set, ok := s.owned[k]; ok {
		delete(set, r)
		if len(set) == 0 {
			delete(s.owned, k)
		}
	}
}

// Filter holds query parameters for ListRoutes.
type Filter struct {
	PeerAddr  string
	Prefix    string
	OriginASN uint32
	Posture   string
	AFI       string // "ipv4" | "ipv6" | ""
	// RIBs are the RIBs listed; zero is the default view
	// (types.DefaultView). Without one, a route a router reports in
	// several RIBs was listed, and counted, once per RIB.
	RIBs types.RIBSet
}

// ListRoutes returns routes matching the given filter.
// Used by the what-if simulator and ASPA recommender.
func (t *Table) ListRoutes(ctx context.Context, f Filter) ([]types.Route, error) {
	var ptrs []*types.Route
	ribs := f.RIBs
	if ribs == 0 {
		ribs = types.DefaultView
	}

	switch {
	case f.PeerAddr != "":
		addr, err := netip.ParseAddr(f.PeerAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid peer addr: %w", err)
		}
		ptrs = t.GetByPeerIn(addr, ribs)
	case f.Prefix != "":
		p, err := netip.ParsePrefix(f.Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix: %w", err)
		}
		ptrs = t.GetByPrefixIn(p, ribs)
	case f.OriginASN != 0:
		ptrs = t.GetByOriginASNIn(f.OriginASN, ribs)
	case f.Posture != "" && PostureIndexed(ribs):
		ptrs = t.GetByPostureIn(types.SecurityPosture(f.Posture), ribs)
	case f.Posture != "":
		for _, r := range t.AllIn(ribs) {
			if r.SecurityPosture == types.SecurityPosture(f.Posture) {
				ptrs = append(ptrs, r)
			}
		}
	default:
		ptrs = t.AllIn(ribs)
	}

	// Apply AFI filter
	routes := make([]types.Route, 0, len(ptrs))
	for _, r := range ptrs {
		if f.AFI == "ipv4" && !r.Prefix.Addr().Is4() {
			continue
		}
		if f.AFI == "ipv6" && !r.Prefix.Addr().Is6() {
			continue
		}
		routes = append(routes, *r)
	}
	return routes, nil
}

// New creates a new Route Table.
func New() *Table {
	t := &Table{
		shards:     make([]shard, defaultShards),
		asnIdx:     make(map[uint32]keySet),
		postureIdx: make(map[types.SecurityPosture]keySet),
	}
	for i := range t.shards {
		t.shards[i].routes = make(map[types.RouteKey]*types.Route)
		t.shards[i].owned = make(map[ownerKey]routeSet)
		t.shards[i].perPeer = make(map[types.PeerRef]*types.RIBCounts)
	}
	return t
}

// Insert adds or updates a route in the table.
func (t *Table) Insert(route *types.Route) {
	key := route.Key()

	// Write to primary store
	s := t.getShard(key)
	s.mu.Lock()
	old := s.routes[key]
	s.routes[key] = route
	if old == nil {
		// A new key counts; a re-announcement does not.
		c := s.perPeer[key.Peer]
		if c == nil {
			c = new(types.RIBCounts)
			s.perPeer[key.Peer] = c
		}
		c[key.RIBType]++
	}
	// Re-inserting the stored pointer itself changes nothing in the owner
	// index.
	if old != route {
		if old != nil {
			s.disown(old)
		}
		s.own(route)
	}
	s.mu.Unlock()

	// Update prefix index
	t.prefixMu.Lock()
	existing, _ := t.prefixIdx.Get(route.Prefix)
	if !containsKey(existing, key) {
		t.prefixIdx.Insert(route.Prefix, append(existing, key))
	}
	t.prefixMu.Unlock()

	// Update ASN index. A re-announcement with a new origin arrives as a new
	// route for the same key, so the old origin's entry must be dropped.
	originASN := route.OriginASN()
	t.asnMu.Lock()
	if old != nil {
		if oldASN := old.OriginASN(); oldASN != 0 && oldASN != originASN {
			t.unindexASN(oldASN, key)
		}
	}
	if originASN != 0 {
		addKey(t.asnIdx, originASN, key)
	}
	t.asnMu.Unlock()

	// Update posture index: the default view's routes only, the view the
	// status posture counts report. It used to take every RIB, so a router
	// sending pre- and post-policy was counted twice.
	if types.DefaultView.Has(key.RIBType) {
		t.postureMu.Lock()
		t.unindexPostureExcept(key, route.SecurityPosture)
		if route.SecurityPosture != "" {
			addKey(t.postureIdx, route.SecurityPosture, key)
		}
		t.postureMu.Unlock()
	}
}

// unindexPostureExcept removes key from every posture index entry other than
// keep. The caller holds postureMu.
//
// The old posture is not read off the stored route. RevalidateAll used to
// change a route's posture in place and re-insert the same pointer, so by
// the time Insert ran the stored route already carried the new posture, and
// checking it left the key listed under every posture it had ever had.
// Routes are no longer changed in place (see Replace), but there are only a
// handful of postures, so clearing them all stays cheap and safe.
func (t *Table) unindexPostureExcept(key types.RouteKey, keep types.SecurityPosture) {
	for posture, set := range t.postureIdx {
		if posture != keep {
			delete(set, key)
			if len(set) == 0 {
				delete(t.postureIdx, posture)
			}
		}
	}
}

// unindexASN removes key from asn's index entry, dropping the entry once it
// is empty so the map does not keep one per origin ever seen. The caller
// holds asnMu.
func (t *Table) unindexASN(asn uint32, key types.RouteKey) {
	if set, ok := t.asnIdx[asn]; ok {
		delete(set, key)
		if len(set) == 0 {
			delete(t.asnIdx, asn)
		}
	}
}

// addKey adds key to idx[k], creating the entry if needed.
func addKey[K comparable](idx map[K]keySet, k K, key types.RouteKey) {
	set, ok := idx[k]
	if !ok {
		set = keySet{}
		idx[k] = set
	}
	set[key] = struct{}{}
}

// Withdraw removes the route under key, whichever session owns it, and
// reports whether there was one.
func (t *Table) Withdraw(key types.RouteKey) bool {
	return t.withdrawOne(key, nil)
}

// WithdrawFromSession removes the route under key, withdrawn by BMP session
// session, unless a newer session has since re-announced it: a late
// withdrawal from a superseded session must not remove the newer session's
// route. It reports whether it removed one.
//
// Only key's RIB type is touched. It used to withdraw the prefix from every
// RIB type, so a post-policy withdrawal (inbound policy now rejects the
// route) also removed the pre-policy route the peer still announced.
func (t *Table) WithdrawFromSession(key types.RouteKey, session uint64) bool {
	return t.withdrawOne(key, func(r *types.Route) bool { return r.OwnerSession <= session })
}

// withdrawOne removes the route under key. If pred is non-nil the route is
// only removed when pred reports true; it is checked under the shard lock, so
// a concurrent Insert cannot slip in between the check and the delete.
func (t *Table) withdrawOne(key types.RouteKey, pred func(*types.Route) bool) bool {
	s := t.getShard(key)
	s.mu.Lock()
	route, exists := s.routes[key]
	if exists && pred != nil && !pred(route) {
		exists = false
	}
	if exists {
		delete(s.routes, key)
		s.disown(route)
		if c := s.perPeer[key.Peer]; c != nil {
			c[key.RIBType]--
			if *c == (types.RIBCounts{}) {
				delete(s.perPeer, key.Peer)
			}
		}
	}
	s.mu.Unlock()

	if !exists {
		return false
	}

	// Clean up prefix index
	t.prefixMu.Lock()
	existing, _ := t.prefixIdx.Get(key.Prefix)
	updated := removeKey(existing, key)
	if len(updated) == 0 {
		t.prefixIdx.Delete(key.Prefix)
	} else {
		t.prefixIdx.Insert(key.Prefix, updated)
	}
	t.prefixMu.Unlock()

	// Clean up ASN index
	originASN := route.OriginASN()
	if originASN != 0 {
		t.asnMu.Lock()
		t.unindexASN(originASN, key)
		t.asnMu.Unlock()
	}

	// Clean up posture index. Every entry, not just route.SecurityPosture's:
	// a revalidation may have changed the posture in place before this ran.
	t.postureMu.Lock()
	t.unindexPostureExcept(key, "")
	t.postureMu.Unlock()
	return true
}

// WithdrawAllFromPeer removes, at once, what a peer-down from BMP session
// session removes; see DetachPeer.
func (t *Table) WithdrawAllFromPeer(peer types.PeerRef, session uint64, scope types.RIBType) int {
	return t.DetachPeer(peer, session, scope).Apply()
}

// WithdrawSession removes, at once, what the end of BMP session session
// removes; see DetachSession.
func (t *Table) WithdrawSession(session uint64) int {
	return t.DetachSession(session).Apply()
}

// DetachPeer starts the withdraw-all for a peer-down of peer seen by BMP
// session session. It removes the peer's routes that session owns, and its
// routes no session owns (restored from a snapshot and not yet confirmed):
// the peer is down, so those are gone too. Routes of the peer that another
// session owns, such as a newer session from the same router, are kept.
//
// It costs O(shards); the routes themselves are removed by the Removal.
//
// The peer includes its router, so the unowned routes it takes are that
// router's alone: a peer-down on one router never removes another router's
// routes from the same peer address.
//
// scope is the withdrawal's RIBType (see types.Withdrawal): LocRIB takes
// the peer's Loc-RIB routes only, a Loc-RIB instance going down; any other
// RIB type takes its Adj-RIB-In and Adj-RIB-Out routes only, a BGP peer
// going down.
func (t *Table) DetachPeer(peer types.PeerRef, session uint64, scope types.RIBType) *Removal {
	peer = types.NewPeerRef(peer.Router, peer.Distinguisher, peer.Addr)
	keys := []ownerKey{ownerKeyOf(session, peer, scope)}
	if session != 0 {
		keys = append(keys, ownerKeyOf(0, peer, scope))
	}
	rm := &Removal{t: t}
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for _, k := range keys {
			if set, ok := s.owned[k]; ok {
				rm.add(set)
				delete(s.owned, k)
			}
		}
		s.mu.Unlock()
	}
	return rm
}

// DetachSession starts the withdraw-all for the end of BMP session session:
// every route, from any peer, that the session owns. Routes no session owns
// are left to stale eviction, since the session never confirmed them.
//
// It costs O(owner index entries), one per (session, peer) pair per shard;
// the routes themselves are removed by the Removal.
func (t *Table) DetachSession(session uint64) *Removal {
	rm := &Removal{t: t}
	if session == 0 {
		return rm // never a live session; nothing to end
	}
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, set := range s.owned {
			if k.session == session {
				rm.add(set)
				delete(s.owned, k)
			}
		}
		s.mu.Unlock()
	}
	return rm
}

// DetachUnowned starts the removal of every route no BMP session owns: the
// routes restored from a snapshot that no live session has confirmed since
// (a confirmation is a new route owned by its session). It is stale eviction
// for a table with a running ingest; see EvictStale.
//
// It costs O(owner index entries); the routes themselves are removed by the
// Removal.
func (t *Table) DetachUnowned() *Removal {
	rm := &Removal{t: t}
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, set := range s.owned {
			if k.session == 0 {
				rm.add(set)
				delete(s.owned, k)
			}
		}
		s.mu.Unlock()
	}
	return rm
}

// Removal is a withdraw-all that has been taken out of the owner index but
// not yet applied. Its routes stay readable until Step removes them, in
// bounded chunks so a large withdraw-all does not stall ingest. A route that
// was replaced or withdrawn in the meantime is skipped, so a later
// announcement under the same key survives.
//
// A Removal is not safe for concurrent use.
type Removal struct {
	t    *Table
	sets []routeSet
	cur  []*types.Route
	n    int
}

func (rm *Removal) add(set routeSet) {
	rm.sets = append(rm.sets, set)
	rm.n += len(set)
}

// Len returns the number of routes detached, including any since replaced.
func (rm *Removal) Len() int { return rm.n }

// Step removes up to budget routes and reports how many it removed and
// whether the Removal is finished.
func (rm *Removal) Step(budget int) (removed int, done bool) {
	for budget > 0 {
		if len(rm.cur) == 0 {
			if len(rm.sets) == 0 {
				break
			}
			// One shard's routes for one (session, peer); copied so the
			// next Step can resume where this one stopped.
			set := rm.sets[len(rm.sets)-1]
			rm.sets = rm.sets[:len(rm.sets)-1]
			rm.cur = make([]*types.Route, 0, len(set))
			for r := range set {
				rm.cur = append(rm.cur, r)
			}
			continue
		}
		r := rm.cur[len(rm.cur)-1]
		rm.cur = rm.cur[:len(rm.cur)-1]
		budget--
		if rm.t.removeIfCurrent(r) {
			removed++
		}
	}
	return removed, len(rm.cur) == 0 && len(rm.sets) == 0
}

// Apply removes all of the Removal's routes and returns how many it removed.
func (rm *Removal) Apply() int {
	total := 0
	for {
		n, done := rm.Step(1 << 16)
		total += n
		if done {
			return total
		}
	}
}

// removeIfCurrent removes r if the table still holds this very route.
func (t *Table) removeIfCurrent(r *types.Route) bool {
	return t.withdrawOne(r.Key(), func(cur *types.Route) bool { return cur == r })
}

// Replace swaps updated in for old, a route the table holds, and reports
// whether it did. It does nothing if the table no longer holds old itself
// (it was withdrawn or replaced by a newer announcement since the caller read
// it) or if a pending Removal has detached old (it is on its way out).
//
// updated must be a new object differing from old only in its validation
// annotations (ROV, ASPA, SecurityPosture); the owner and origin indexes are
// carried over unchanged. Routes in the table are never modified in place,
// so readers holding old keep seeing a consistent route.
func (t *Table) Replace(old, updated *types.Route) bool {
	key := old.Key()
	if old == updated || updated.Key() != key ||
		updated.OwnerSession != old.OwnerSession || updated.OriginASN() != old.OriginASN() {
		panic("routetable: Replace may only change a route's validation annotations")
	}

	s := t.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.routes[key] != old {
		return false
	}
	set := s.owned[ownerKeyOf(old.OwnerSession, key.Peer, key.RIBType)]
	if _, indexed := set[old]; !indexed {
		return false
	}
	s.routes[key] = updated
	delete(set, old)
	set[updated] = struct{}{}

	// Under the shard lock, so a concurrent withdrawal of the key cannot
	// unindex it in between and leave updated's posture listed. Lock order
	// shard → postureMu; no reader holds an index lock while taking a
	// shard lock.
	if updated.SecurityPosture != old.SecurityPosture && types.DefaultView.Has(key.RIBType) {
		t.postureMu.Lock()
		t.unindexPostureExcept(key, updated.SecurityPosture)
		if updated.SecurityPosture != "" {
			addKey(t.postureIdx, updated.SecurityPosture, key)
		}
		t.postureMu.Unlock()
	}
	return true
}

// Scan walks every route in the table a bounded batch at a time, so a pass
// over a large table can be interleaved with other work. It reads one shard
// at a time; routes added to a shard after it has been read are not seen.
//
// A Scan is not safe for concurrent use.
type Scan struct {
	t    *Table
	next int // next shard to read
	buf  []*types.Route
}

// NewScan starts a Scan over the table.
func (t *Table) NewScan() *Scan { return &Scan{t: t} }

// Next returns up to n more routes, or none once the scan is finished. The
// slice is only valid until the next call.
func (sc *Scan) Next(n int) []*types.Route {
	for len(sc.buf) < n && sc.next < len(sc.t.shards) {
		s := &sc.t.shards[sc.next]
		sc.next++
		s.mu.RLock()
		for _, r := range s.routes {
			sc.buf = append(sc.buf, r)
		}
		s.mu.RUnlock()
	}
	k := min(n, len(sc.buf))
	out := sc.buf[:k:k]
	sc.buf = sc.buf[k:]
	if len(sc.buf) == 0 {
		sc.buf = nil // let the backing array go
	}
	return out
}

// KeysWithin calls fn for the key of every route whose prefix is equal to or
// more specific than prefix, using the prefix index rather than a table scan.
// fn runs under the index's read lock and must not call back into the table.
func (t *Table) KeysWithin(prefix netip.Prefix, fn func(types.RouteKey)) {
	t.prefixMu.RLock()
	defer t.prefixMu.RUnlock()
	for _, keys := range t.prefixIdx.Subnets(prefix.Masked()) {
		for _, k := range keys {
			fn(k)
		}
	}
}

// MatchScan walks the table one shard at a time and returns the routes a
// predicate selects, without copying any route or collecting the routes it
// rejects. Like Scan, it does not see routes added to a shard after reading
// it.
//
// A MatchScan is not safe for concurrent use.
type MatchScan struct {
	t     *Table
	match func(*types.Route) bool
	next  int
	buf   []*types.Route
}

// NewMatchScan starts a MatchScan. match runs under a shard's read lock and
// must not call back into the table.
func (t *Table) NewMatchScan(match func(*types.Route) bool) *MatchScan {
	return &MatchScan{t: t, match: match}
}

// Next reads the next shard and returns the routes in it that match, how many
// routes it examined, and whether the scan is finished. The slice is only
// valid until the next call.
func (ms *MatchScan) Next() (matched []*types.Route, examined int, done bool) {
	if ms.next >= len(ms.t.shards) {
		return nil, 0, true
	}
	s := &ms.t.shards[ms.next]
	ms.next++
	ms.buf = ms.buf[:0]
	s.mu.RLock()
	for _, r := range s.routes {
		if ms.match(r) {
			ms.buf = append(ms.buf, r)
		}
	}
	examined = len(s.routes)
	s.mu.RUnlock()
	return ms.buf, examined, ms.next >= len(ms.t.shards)
}

// ─── Query Methods ───

// Get returns the route stored under the given key, or nil if not found.
func (t *Table) Get(key types.RouteKey) *types.Route {
	s := t.getShard(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routes[key]
}

// GetByPrefix returns the default view's routes (types.DefaultView) to
// exactly prefix.
func (t *Table) GetByPrefix(prefix netip.Prefix) []*types.Route {
	return t.GetByPrefixIn(prefix, types.DefaultView)
}

// GetByPrefixIn returns the routes of the RIBs ribs to exactly prefix.
func (t *Table) GetByPrefixIn(prefix netip.Prefix, ribs types.RIBSet) []*types.Route {
	t.prefixMu.RLock()
	idx, _ := t.prefixIdx.Get(prefix)
	keys := slices.Clone(idx) // the list is changed in place; see prefixMu
	t.prefixMu.RUnlock()
	return t.resolveKeys(keys, ribs)
}

// GetCoveringIn returns the routes of the RIBs ribs whose prefix is equal to
// or less specific than prefix (its supernets in the prefix index), least
// specific prefix first. A prefix with host bits set is masked first.
func (t *Table) GetCoveringIn(prefix netip.Prefix, ribs types.RIBSet) []*types.Route {
	var lists [][]types.RouteKey
	t.prefixMu.RLock()
	// Supernets yields the longest match first; collected, then reversed.
	for _, keys := range t.prefixIdx.Supernets(prefix.Masked()) {
		lists = append(lists, slices.Clone(keys)) // changed in place; see prefixMu
	}
	t.prefixMu.RUnlock()
	slices.Reverse(lists)
	return t.resolveKeys(slices.Concat(lists...), ribs)
}

// GetWithinIn returns the routes of the RIBs ribs whose prefix is equal to
// or more specific than prefix (its subnets in the prefix index), in CIDR
// order. A prefix with host bits set is masked first.
func (t *Table) GetWithinIn(prefix netip.Prefix, ribs types.RIBSet) []*types.Route {
	var keys []types.RouteKey
	t.prefixMu.RLock()
	for _, ks := range t.prefixIdx.Subnets(prefix.Masked()) {
		keys = append(keys, ks...) // copied out; see prefixMu
	}
	t.prefixMu.RUnlock()
	return t.resolveKeys(keys, ribs)
}

// GetByOriginASN returns the default view's routes originated by asn.
func (t *Table) GetByOriginASN(asn uint32) []*types.Route {
	return t.GetByOriginASNIn(asn, types.DefaultView)
}

// GetByOriginASNIn returns the routes of the RIBs ribs originated by asn.
func (t *Table) GetByOriginASNIn(asn uint32, ribs types.RIBSet) []*types.Route {
	t.asnMu.RLock()
	keys := t.asnIdx[asn].keys()
	t.asnMu.RUnlock()
	return t.resolveKeys(keys, ribs)
}

// PostureIndexed reports whether the posture index holds every route of
// ribs: they are all in the default view.
func PostureIndexed(ribs types.RIBSet) bool { return ribs&^types.DefaultView == 0 }

// GetByPosture returns the default view's routes with a posture.
func (t *Table) GetByPosture(posture types.SecurityPosture) []*types.Route {
	return t.GetByPostureIn(posture, types.DefaultView)
}

// GetByPostureIn returns the routes of the RIBs ribs with a posture. The
// posture index holds the default view only: ribs outside it return none
// (see PostureIndexed).
func (t *Table) GetByPostureIn(posture types.SecurityPosture, ribs types.RIBSet) []*types.Route {
	t.postureMu.RLock()
	keys := t.postureIdx[posture].keys()
	t.postureMu.RUnlock()
	return t.resolveKeys(keys, ribs)
}

// GetByPeer returns the default view's routes from a peer address, on every
// router and in every instance. An IPv4 peer matches in either its plain or
// its IPv4-mapped IPv6 form.
func (t *Table) GetByPeer(peerAddr netip.Addr) []*types.Route {
	return t.GetByPeerIn(peerAddr, types.DefaultView)
}

// GetByPeerIn returns the routes of the RIBs ribs from a peer address, as
// GetByPeer.
func (t *Table) GetByPeerIn(peerAddr netip.Addr, ribs types.RIBSet) []*types.Route {
	peerAddr = peerAddr.Unmap()
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if key.Peer.Addr == peerAddr && ribs.Has(key.RIBType) {
				routes = append(routes, route)
			}
		}
		s.mu.RUnlock()
	}
	return routes
}

// All returns every route in the table regardless of RIB type.
func (t *Table) All() []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for _, route := range s.routes {
			routes = append(routes, route)
		}
		s.mu.RUnlock()
	}
	return routes
}

// AllDefaultView returns the default view's routes (types.DefaultView):
// what the routers received before import policy, and what they selected.
func (t *Table) AllDefaultView() []*types.Route {
	return t.AllIn(types.DefaultView)
}

// AllOfRIB returns the routes of one RIB type.
func (t *Table) AllOfRIB(rib types.RIBType) []*types.Route {
	return t.AllIn(types.RIBSetOf(rib))
}

// AllIn returns the routes of the RIBs ribs.
func (t *Table) AllIn(ribs types.RIBSet) []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if ribs.Has(key.RIBType) {
				routes = append(routes, route)
			}
		}
		s.mu.RUnlock()
	}
	return routes
}

// CountByRIB returns the number of routes of each RIB type. It reads the
// per-peer counts, not the routes.
func (t *Table) CountByRIB() types.RIBCounts {
	var out types.RIBCounts
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for _, c := range s.perPeer {
			for r := range c {
				out[r] += c[r]
			}
		}
		s.mu.RUnlock()
	}
	return out
}

// Count returns the total number of routes.
func (t *Table) Count() uint64 {
	var total uint64
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		total += uint64(len(s.routes))
		s.mu.RUnlock()
	}
	return total
}

// PeerRouteCounts returns how many routes the table holds for each peer
// (per router, per instance, per address), per RIB type: inbound and
// outbound are never added together. Peers with none are absent. It reads
// each shard's counts, not its routes.
func (t *Table) PeerRouteCounts() map[types.PeerRef]types.RIBCounts {
	out := make(map[types.PeerRef]types.RIBCounts)
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for p, c := range s.perPeer {
			sum := out[p]
			for r := range c {
				sum[r] += c[r]
			}
			out[p] = sum
		}
		s.mu.RUnlock()
	}
	return out
}

// Snapshot returns all routes currently in the table.
// Called by the serve shutdown sequence to persist state.
func (t *Table) Snapshot() []*types.Route {
	return t.All()
}

// Restore populates the table from a snapshot.
// All restored routes have Stale=true so that the Event Engine
// ignores them until a live BMP message confirms each one.
func (t *Table) Restore(routes []*types.Route) {
	for _, r := range routes {
		cp := *r
		cp.Stale = true
		t.Insert(&cp)
	}
}

// EvictStale removes all routes still marked Stale from the table and
// returns the number removed.
//
// It is not for a table that ingest is writing to: like any second writer it
// can unindex a route ingest has just inserted under the same key. The
// server evicts through DetachUnowned in its ingest loop instead.
func (t *Table) EvictStale() int {
	return t.evictStale(t.staleKeys())
}

// staleKeys lists the keys of routes marked Stale.
func (t *Table) staleKeys() []types.RouteKey {
	var keys []types.RouteKey
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if route.Stale {
				keys = append(keys, key)
			}
		}
		s.mu.RUnlock()
	}
	return keys
}

// evictStale removes the routes under keys that are still Stale. It runs
// apart from ingest, so the check is made again under the shard lock: a live
// BMP message may have confirmed a route since staleKeys listed it, and that
// route must stay.
func (t *Table) evictStale(keys []types.RouteKey) int {
	evicted := 0
	for _, key := range keys {
		if t.withdrawOne(key, func(r *types.Route) bool { return r.Stale }) {
			evicted++
		}
	}
	return evicted
}

// CountByPosture returns the default view's route counts grouped by
// security posture.
func (t *Table) CountByPosture() map[types.SecurityPosture]uint64 {
	t.postureMu.RLock()
	defer t.postureMu.RUnlock()

	result := make(map[types.SecurityPosture]uint64)
	for posture, set := range t.postureIdx {
		result[posture] = uint64(len(set))
	}
	return result
}

// ─── Internal helpers ───

func (t *Table) getShard(key types.RouteKey) *shard {
	h := fnv.New32a()
	b := key.Peer.Addr.As16()
	h.Write(b[:])
	pb, _ := key.Prefix.MarshalBinary()
	h.Write(pb)
	return &t.shards[h.Sum32()%uint32(len(t.shards))]
}

func (t *Table) resolveKeys(keys []types.RouteKey, ribs types.RIBSet) []*types.Route {
	routes := make([]*types.Route, 0, len(keys))
	for _, key := range keys {
		// The prefix and ASN indexes hold keys of every RIB.
		if !ribs.Has(key.RIBType) {
			continue
		}
		s := t.getShard(key)
		s.mu.RLock()
		if r, ok := s.routes[key]; ok {
			routes = append(routes, r)
		}
		s.mu.RUnlock()
	}
	return routes
}

// containsKey and removeKey maintain a prefix's key list. It holds at most
// one key per peer, so a linear scan is bounded by the peer count, not the
// table size.
func containsKey(keys []types.RouteKey, key types.RouteKey) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

func removeKey(keys []types.RouteKey, key types.RouteKey) []types.RouteKey {
	for i, k := range keys {
		if k == key {
			return append(keys[:i], keys[i+1:]...)
		}
	}
	return keys
}
