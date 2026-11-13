package store

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Owner identifies who put a VRP or ASPA record in a store: one RTR cache's
// client (NewOwner), or Unowned for data no cache's client put there
// (snapshot restore, ReplaceAll, and the methods that take no owner).
//
// In raven serve every cache's client shares one VRP store and one ASPA
// store, but RTR's rules are per cache: a cache announces a VRP at most once
// until it withdraws it (RFC 8210 §5.6), and a full sync replaces that
// cache's data. So the stores track which owners hold each record. A
// duplicate announcement is a cache announcing what it already holds; the
// same VRP from two caches is not one.
type Owner uint8

// Unowned is the owner of data no cache's client put in the store.
const Unowned Owner = 0

// MaxOwners is how many owners a VRP store tracks, Unowned included.
const MaxOwners = 64

// VRPStore holds Validated ROA Payloads indexed for efficient
// Route Origin Validation lookups (RFC 6811).
//
// The RTR client changes the VRP set as an incremental sync's PDUs arrive
// (AddVRPFrom, RemoveVRPFrom) and publishes it at End of Data
// (RebuildIndex); a full sync is built aside (VRPStage) and swapped in whole
// at its End of Data (ReplaceOwner). Lookups (FindCovering) see only
// published sets: until End of Data they see the previous one, whole and
// consistent, as RTR intends. They take no lock and never wait for a
// rebuild, which is built off to the side and swapped in.
//
// The set holds each distinct VRP once, however many owners hold it. Each
// owner holds a VRP with a count: its announcements less its withdrawals,
// never below 0. A cache that announces a VRP it holds and then withdraws it
// (Fort 1.7.0, NICMx/FORT-validator#204) still holds it after.
type VRPStore struct {
	// mu guards the VRP set being built up, the owners, and the serial and
	// session ID.
	mu sync.RWMutex
	// The VRP set: each distinct VRP's place in store order (the order
	// they were first added in) and the owners holding it.
	vrps map[types.VRP]vrpEntry
	// extra holds the announcements beyond the first of an owner that
	// announced a VRP more than once: its count less 1. Almost always
	// empty.
	extra     map[ownedVRP]uint32
	next      uint64            // order of the next VRP added
	owned     [MaxOwners]uint64 // distinct VRPs each owner holds
	nextOwner int

	serial    uint32
	sessionID uint16

	// idx is the published covering-prefix index (see vrpIndex): built
	// whole and never modified after, so the slices FindCovering hands out
	// stay valid and unchanged. buildMu orders rebuilds, so a slower
	// rebuild of an older set can never replace a newer one.
	idx      atomic.Pointer[vrpIndex]
	buildMu  sync.Mutex
	rebuilds atomic.Uint64
}

type vrpEntry struct {
	order  uint64
	owners uint64 // bit o set: owner o holds the VRP
}

type ownedVRP struct {
	o Owner
	v types.VRP
}

// NewVRPStore creates an empty VRP store.
func NewVRPStore() *VRPStore {
	s := &VRPStore{vrps: make(map[types.VRP]vrpEntry), extra: make(map[ownedVRP]uint32), nextOwner: int(Unowned) + 1}
	s.idx.Store(newVRPIndex(nil, nil))
	return s
}

// NewOwner returns an owner no one else has, for one RTR cache's client. ok
// is false once all MaxOwners-1 have been handed out.
func (s *VRPStore) NewOwner() (o Owner, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextOwner >= MaxOwners {
		return 0, false
	}
	o = Owner(s.nextOwner)
	s.nextOwner++
	return o, true
}

// Count returns the number of distinct VRPs in the store, including changes
// not yet published. A VRP several caches hold counts once.
func (s *VRPStore) Count() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint64(len(s.vrps))
}

// OwnerCount returns the number of distinct VRPs o holds, including changes
// not yet published.
func (s *VRPStore) OwnerCount(o Owner) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.owned[o]
}

// Serial returns the current RTR serial number.
func (s *VRPStore) Serial() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serial
}

// SessionID returns the current RTR session ID.
func (s *VRPStore) SessionID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// SetSerial updates the serial and session ID after an RTR sync.
func (s *VRPStore) SetSerial(serial uint32, sessionID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial = serial
	s.sessionID = sessionID
}

// Rebuilds returns how many times the index has been rebuilt and published.
func (s *VRPStore) Rebuilds() uint64 { return s.rebuilds.Load() }

// Clear empties the VRP set: every owner's VRPs. The serial and session ID
// are also reset; they are repopulated on EndOfData. Lookups go on seeing
// the previous set until the next RebuildIndex.
func (s *VRPStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vrps = make(map[types.VRP]vrpEntry)
	s.extra = make(map[ownedVRP]uint32)
	s.owned = [MaxOwners]uint64{}
	s.serial = 0
	s.sessionID = 0
}

// ClearOwner drops o's VRPs and the Unowned ones (a restored snapshot). VRPs
// another owner also holds stay, held by it. Lookups go on seeing the
// previous set until the next RebuildIndex.
func (s *VRPStore) ClearOwner(o Owner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearOwnerLocked(o)
}

func (s *VRPStore) clearOwnerLocked(o Owner) {
	drop := uint64(1)<<o | uint64(1)<<Unowned
	for v, e := range s.vrps {
		if e.owners&drop == 0 {
			continue
		}
		e.owners &^= drop
		if e.owners == 0 {
			delete(s.vrps, v)
		} else {
			s.vrps[v] = e
		}
	}
	for k := range s.extra {
		if k.o == o || k.o == Unowned {
			delete(s.extra, k)
		}
	}
	s.owned[o] = 0
	s.owned[Unowned] = 0
}

// ReplaceOwner makes stage o's VRPs, in place of the ones o held and the
// Unowned ones (a restored snapshot): a full sync's End of Data. VRPs another
// owner also holds stay, held by it. The caller then publishes with
// RebuildIndex; until then lookups see the previous set, so a full sync
// never shows a gap.
func (s *VRPStore) ReplaceOwner(o Owner, stage *VRPStage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearOwnerLocked(o)
	for _, v := range stage.order {
		n := stage.counts[v]
		if n == 0 {
			continue // withdrawn again within the sync
		}
		if _, added := s.addLocked(o, v); added && n > 1 {
			s.extra[ownedVRP{o, v}] = n - 1
		}
	}
}

// ReplaceAll replaces the entire VRP set, as Unowned, and publishes it (used
// on snapshot restore). A VRP listed more than once is stored once.
func (s *VRPStore) ReplaceAll(vrps []types.VRP, serial uint32, sessionID uint16) {
	s.buildMu.Lock()
	defer s.buildMu.Unlock()

	s.mu.Lock()
	s.vrps = make(map[types.VRP]vrpEntry, len(vrps))
	s.extra = make(map[ownedVRP]uint32)
	s.owned = [MaxOwners]uint64{}
	distinct := make([]types.VRP, 0, len(vrps))
	order := make([]uint64, 0, len(vrps))
	for _, v := range vrps {
		if o, added := s.addLocked(Unowned, v); added {
			distinct = append(distinct, v)
			order = append(order, o)
		}
	}
	s.serial = serial
	s.sessionID = sessionID
	s.mu.Unlock()

	s.publish(newVRPIndex(distinct, order))
}

// AddVRP adds a VRP as Unowned, once: adding it again changes nothing.
// Lookups see it from the next RebuildIndex.
func (s *VRPStore) AddVRP(vrp types.VRP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addLocked(Unowned, vrp)
}

// AddVRPFrom records that o announced vrp, adding 1 to its count. added is
// false if o already held vrp: a duplicate announcement (RFC 8210 §5.6). A
// VRP new to the set is seen by lookups from the next RebuildIndex.
func (s *VRPStore) AddVRPFrom(o Owner, vrp types.VRP) (added bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, added = s.addLocked(o, vrp); !added {
		s.extra[ownedVRP{o, vrp}]++
	}
	return added
}

// addLocked makes o hold vrp, if it did not, and reports whether it did not.
func (s *VRPStore) addLocked(o Owner, vrp types.VRP) (order uint64, added bool) {
	bit := uint64(1) << o
	e, ok := s.vrps[vrp]
	if ok && e.owners&bit != 0 {
		return e.order, false
	}
	if !ok {
		e.order = s.next
		s.next++
	}
	e.owners |= bit
	s.vrps[vrp] = e
	s.owned[o]++
	return e.order, true
}

// RemoveVRP removes a VRP held as Unowned. Lookups stop seeing it from the
// next RebuildIndex.
func (s *VRPStore) RemoveVRP(vrp types.VRP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.extra, ownedVRP{Unowned, vrp})
	s.releaseLocked(Unowned, vrp)
}

// RemoveVRPFrom records that o withdrew vrp, taking 1 from its count. known
// is false, and nothing changes, if o did not hold vrp: a withdrawal of an
// unknown record (RFC 8210 §12, error code 6). released reports that o's
// count reached 0, so o no longer holds vrp; the VRP leaves the set once no
// owner holds it, and lookups stop seeing it from the next RebuildIndex.
func (s *VRPStore) RemoveVRPFrom(o Owner, vrp types.VRP) (known, released bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.vrps[vrp]; !ok || e.owners&(uint64(1)<<o) == 0 {
		return false, false
	}
	k := ownedVRP{o, vrp}
	if n := s.extra[k]; n > 0 {
		if n == 1 {
			delete(s.extra, k)
		} else {
			s.extra[k] = n - 1
		}
		return true, false
	}
	s.releaseLocked(o, vrp)
	return true, true
}

// releaseLocked makes o no longer hold vrp.
func (s *VRPStore) releaseLocked(o Owner, vrp types.VRP) {
	bit := uint64(1) << o
	e, ok := s.vrps[vrp]
	if !ok || e.owners&bit == 0 {
		return
	}
	e.owners &^= bit
	if e.owners == 0 {
		delete(s.vrps, vrp)
	} else {
		s.vrps[vrp] = e
	}
	s.owned[o]--
}

// FindCovering returns all VRPs that cover the given prefix.
// A VRP covers a route prefix if the VRP prefix is equal to or
// less specific than the route prefix (RFC 6811 §2). They come shortest
// VRP prefix first and, within a prefix, in the order they were added;
// nil if there are none.
//
// It reads the last published index without locking. The returned slice is
// shared with other callers and must not be modified. In steady state
// FindCovering does not allocate.
func (s *VRPStore) FindCovering(prefix netip.Prefix) []types.VRP {
	return s.idx.Load().covering(prefix)
}

// All returns a copy of all distinct VRPs, in store order, including changes
// not yet published. Used for diagnostics.
func (s *VRPStore) All() []types.VRP {
	s.mu.RLock()
	vrps, order := s.collectLocked()
	s.mu.RUnlock()
	idx := make([]int, len(vrps))
	for i := range idx {
		idx[i] = i
	}
	slices.SortFunc(idx, func(a, b int) int { return cmp.Compare(order[a], order[b]) })
	out := make([]types.VRP, len(vrps))
	for i, j := range idx {
		out[i] = vrps[j]
	}
	return out
}

// collectLocked lists the VRP set and each VRP's store order, in no
// particular order. The caller holds mu.
func (s *VRPStore) collectLocked() ([]types.VRP, []uint64) {
	vrps := make([]types.VRP, 0, len(s.vrps))
	order := make([]uint64, 0, len(s.vrps))
	for v, e := range s.vrps {
		vrps = append(vrps, v)
		order = append(order, e.order)
	}
	return vrps, order
}

// Snapshot returns a copy of all VRPs for persistence.
func (s *VRPStore) Snapshot() []types.VRP {
	return s.All()
}

// Restore replaces the store contents from a snapshot.
// The serial is reset to 0 so the next RTR connection performs a full sync.
func (s *VRPStore) Restore(vrps []types.VRP) {
	s.ReplaceAll(vrps, 0, 0)
}

// RebuildIndex publishes the current VRP set to lookups. The RTR client calls
// it once per sync, at End of Data. The index is built without holding any
// lock lookups take, then swapped in.
func (s *VRPStore) RebuildIndex() {
	s.buildMu.Lock()
	defer s.buildMu.Unlock()
	s.mu.RLock()
	vrps, order := s.collectLocked()
	s.mu.RUnlock()
	s.publish(newVRPIndex(vrps, order))
}

// publish makes idx the index lookups use. The caller holds buildMu.
func (s *VRPStore) publish(idx *vrpIndex) {
	s.idx.Store(idx)
	s.rebuilds.Add(1)
}

// VRPStage is one cache's VRP set as a full sync builds it, aside from the
// store, with the same counts: announcements less withdrawals, never below
// 0. ReplaceOwner swaps it in at End of Data.
type VRPStage struct {
	counts map[types.VRP]uint32
	order  []types.VRP // first announcements, in order
	held   int
}

// NewVRPStage returns an empty stage.
func NewVRPStage() *VRPStage { return &VRPStage{counts: make(map[types.VRP]uint32)} }

// Announce adds 1 to v's count. added is false if v was held already: a
// duplicate announcement.
func (g *VRPStage) Announce(v types.VRP) (added bool) {
	n, seen := g.counts[v]
	g.counts[v] = n + 1
	if n > 0 {
		return false
	}
	if !seen {
		g.order = append(g.order, v)
	}
	g.held++
	return true
}

// Withdraw takes 1 from v's count. known is false, and nothing changes, if v
// was not held: a withdrawal of an unknown record.
func (g *VRPStage) Withdraw(v types.VRP) (known bool) {
	n := g.counts[v]
	if n == 0 {
		return false
	}
	g.counts[v] = n - 1
	if n == 1 {
		g.held--
	}
	return true
}

// Len is the number of distinct VRPs held.
func (g *VRPStage) Len() int { return g.held }
