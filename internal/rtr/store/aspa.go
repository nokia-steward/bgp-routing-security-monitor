package store

import (
	"slices"
	"sort"
	"sync"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// ASPARecord holds the validated provider set for a single customer ASN.
// Per RTR v2 semantics, the provider set is the union of all valid ASPA
// objects for that customer ASN; across caches, it is the union of what each
// cache announced.
type ASPARecord struct {
	CustomerASN uint32
	Providers   map[uint32]struct{} // set of authorized provider ASNs
}

// ASPAStore holds ASPA Validated Payloads received via RTR v2.
// Indexed by customer ASN for O(1) lookup during AS_PATH verification.
//
// Each owner (see Owner) has at most one record per customer ASN, as RTR v2
// has it per cache (draft-ietf-sidrops-8210bis §5.12); lookups see, per
// customer ASN, the union of the owners' provider sets.
type ASPAStore struct {
	mu      sync.RWMutex
	records map[uint32]*ASPARecord        // customer ASN -> union record
	owners  map[uint32]map[Owner][]uint32 // customer ASN -> owner -> providers, sorted
	owned   map[Owner]int                 // customer ASNs each owner has a record for
}

// NewASPAStore creates an empty ASPA store.
func NewASPAStore() *ASPAStore {
	return &ASPAStore{
		records: make(map[uint32]*ASPARecord),
		owners:  make(map[uint32]map[Owner][]uint32),
		owned:   make(map[Owner]int),
	}
}

// AddProvider adds a provider ASN to the Unowned record of a customer.
// Creates the record if it doesn't exist. Reports whether the store changed.
func (s *ASPAStore) AddProvider(customerASN, providerASN uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.owners[customerASN][Unowned]
	if slices.Contains(cur, providerASN) {
		return false
	}
	next := append(slices.Clone(cur), providerASN)
	slices.Sort(next)
	s.setLocked(Unowned, customerASN, next)
	return true
}

// RemoveProvider removes a provider ASN from the Unowned record of a
// customer, and the record if that empties it. Reports whether the store
// changed.
func (s *ASPAStore) RemoveProvider(customerASN, providerASN uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.owners[customerASN][Unowned]
	i := slices.Index(cur, providerASN)
	if i < 0 {
		return false
	}
	s.setLocked(Unowned, customerASN, slices.Delete(slices.Clone(cur), i, i+1))
	return true
}

// Announce records that o announced customerASN's provider set: a new
// record, or a replacement of o's previous one (8210bis §5.12: an
// announcement for a Customer ASN the router already has from that cache
// replaces it). replaced reports that o already had a record for
// customerASN; changed, that what lookups see for customerASN changed.
func (s *ASPAStore) Announce(o Owner, customerASN uint32, providers []uint32) (changed, replaced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, replaced = s.owners[customerASN][o]
	next := slices.Clone(providers)
	slices.Sort(next)
	next = slices.Compact(next)
	before := s.records[customerASN] // setLocked replaces it, never modifies it
	s.setLocked(o, customerASN, next)
	return !sameSet(before, s.records[customerASN]), replaced
}

// Withdraw removes o's record for customerASN (8210bis §5.12: a withdrawal
// removes the entire record from that cache). known reports that o had one;
// changed, that what lookups see for customerASN changed.
func (s *ASPAStore) Withdraw(o Owner, customerASN uint32) (changed, known bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, known = s.owners[customerASN][o]; !known {
		return false, false
	}
	before := s.records[customerASN] // setLocked replaces it, never modifies it
	s.setLocked(o, customerASN, nil)
	return !sameSet(before, s.records[customerASN]), true
}

// setLocked sets o's provider list for customerASN (sorted; empty removes
// o's record) and recomputes the union record. The caller holds mu.
func (s *ASPAStore) setLocked(o Owner, customerASN uint32, providers []uint32) {
	byOwner := s.owners[customerASN]
	_, had := byOwner[o]
	if len(providers) == 0 {
		if had {
			delete(byOwner, o)
			s.owned[o]--
		}
	} else {
		if byOwner == nil {
			byOwner = make(map[Owner][]uint32)
			s.owners[customerASN] = byOwner
		}
		byOwner[o] = providers
		if !had {
			s.owned[o]++
		}
	}
	if len(byOwner) == 0 {
		delete(s.owners, customerASN)
		delete(s.records, customerASN)
		return
	}
	r := &ASPARecord{CustomerASN: customerASN, Providers: make(map[uint32]struct{})}
	for _, ps := range byOwner {
		for _, p := range ps {
			r.Providers[p] = struct{}{}
		}
	}
	s.records[customerASN] = r
}

func sameSet(a, b *ASPARecord) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Providers) != len(b.Providers) {
		return false
	}
	for p := range a.Providers {
		if _, ok := b.Providers[p]; !ok {
			return false
		}
	}
	return true
}

// GetRecord returns a copy of the ASPA record for a customer ASN.
// Returns nil if no record exists.
func (s *ASPAStore) GetRecord(customerASN uint32) *ASPARecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[customerASN]
	if !ok {
		return nil
	}
	// Return a copy to avoid races
	copy := &ASPARecord{
		CustomerASN: r.CustomerASN,
		Providers:   make(map[uint32]struct{}, len(r.Providers)),
	}
	for p := range r.Providers {
		copy.Providers[p] = struct{}{}
	}
	return copy
}

// HasProvider returns true if providerASN is in customerASN's provider set.
func (s *ASPAStore) HasProvider(customerASN, providerASN uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[customerASN]
	if !ok {
		return false
	}
	_, ok = r.Providers[providerASN]
	return ok
}

// HasRecord returns true if the store has any ASPA record for customerASN.
func (s *ASPAStore) HasRecord(customerASN uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.records[customerASN]
	return ok
}

// Count returns the number of customer ASNs with ASPA records. A customer
// several caches have a record for counts once.
func (s *ASPAStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// OwnerCount returns the number of customer ASNs o has a record for.
func (s *ASPAStore) OwnerCount(o Owner) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.owned[o]
}

// Clear drops all ASPA records, every owner's.
func (s *ASPAStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = make(map[uint32]*ASPARecord)
	s.owners = make(map[uint32]map[Owner][]uint32)
	s.owned = make(map[Owner]int)
}

// ClearOwner drops o's records and the Unowned ones (a restored snapshot):
// the start of o's full sync, or o's session falling below version 2.
// Records another owner has stay.
func (s *ASPAStore) ClearOwner(o Owner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c, byOwner := range s.owners {
		_, a := byOwner[o]
		_, b := byOwner[Unowned]
		if a {
			s.setLocked(o, c, nil)
		}
		if b {
			s.setLocked(Unowned, c, nil)
		}
	}
}

// Snapshot returns all ASPA records for persistence.
// Provider sets are converted to sorted slices for deterministic serialisation.
func (s *ASPAStore) Snapshot() []types.ASPARecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]types.ASPARecord, 0, len(s.records))
	for _, r := range s.records {
		providers := make([]uint32, 0, len(r.Providers))
		for p := range r.Providers {
			providers = append(providers, p)
		}
		sort.Slice(providers, func(i, j int) bool { return providers[i] < providers[j] })
		result = append(result, types.ASPARecord{
			CustomerASN:  r.CustomerASN,
			ProviderASNs: providers,
		})
	}
	return result
}

// Restore populates the store from a snapshot, as Unowned, replacing any
// existing records.
func (s *ASPAStore) Restore(aspas []types.ASPARecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = make(map[uint32]*ASPARecord, len(aspas))
	s.owners = make(map[uint32]map[Owner][]uint32, len(aspas))
	s.owned = make(map[Owner]int)
	for _, a := range aspas {
		ps := slices.Clone(a.ProviderASNs)
		slices.Sort(ps)
		ps = slices.Compact(ps)
		s.setLocked(Unowned, a.CustomerASN, ps)
	}
}

// AffectedASNs returns all customer ASNs in the store.
// Used to compute dirty sets for re-validation after ASPA updates.
func (s *ASPAStore) AffectedASNs() []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	asns := make([]uint32, 0, len(s.records))
	for asn := range s.records {
		asns = append(asns, asn)
	}
	return asns
}

// HasProvider returns true if providerASN is in this record's provider set.
func (r *ASPARecord) HasProvider(providerASN uint32) bool {
	if r == nil {
		return false
	}
	_, ok := r.Providers[providerASN]
	return ok
}

// ReplaceOwner makes stage o's records, in place of the ones o had and the
// Unowned ones (a restored snapshot): a full sync's End of Data. Records
// another owner has stay. Lookups see the old records or the new, never a
// mix of none: a full sync never shows a gap.
//
// added and removed are the customer ASes o has a record for now and had
// none for before, and the reverse: the sync's net change at this cache. A
// customer whose provider set the stage replaces counts in neither.
func (s *ASPAStore) ReplaceOwner(o Owner, stage *ASPAStage) (added, removed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range stage.records {
		if _, had := s.owners[c][o]; !had {
			added++
		}
	}
	for c, byOwner := range s.owners {
		if _, ok := byOwner[o]; ok {
			if _, next := stage.records[c]; !next {
				s.setLocked(o, c, nil)
				removed++
			}
		}
		if _, ok := byOwner[Unowned]; ok {
			s.setLocked(Unowned, c, nil)
		}
	}
	for c, ps := range stage.records {
		s.setLocked(o, c, ps)
	}
	return added, removed
}

// ASPAStage is one cache's ASPA records as a full sync builds them, aside
// from the store, with the store's rules (8210bis §5.12): an announcement
// sets or replaces a customer's provider set, a withdrawal removes it.
// ReplaceOwner swaps it in at End of Data.
type ASPAStage struct {
	records map[uint32][]uint32
}

// NewASPAStage returns an empty stage.
func NewASPAStage() *ASPAStage { return &ASPAStage{records: make(map[uint32][]uint32)} }

// Announce sets customerASN's provider set.
func (g *ASPAStage) Announce(customerASN uint32, providers []uint32) {
	ps := slices.Clone(providers)
	slices.Sort(ps)
	ps = slices.Compact(ps)
	if len(ps) == 0 {
		delete(g.records, customerASN)
		return
	}
	g.records[customerASN] = ps
}

// Withdraw removes customerASN's record. known is false if there was none: a
// withdrawal of an unknown record.
func (g *ASPAStage) Withdraw(customerASN uint32) (known bool) {
	if _, known = g.records[customerASN]; known {
		delete(g.records, customerASN)
	}
	return known
}

// Len is the number of customer ASes with a record.
func (g *ASPAStage) Len() int { return len(g.records) }
