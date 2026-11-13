package store

import (
	"math/rand/v2"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store/storetest"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// refStore is the reference the VRP store must match: the original
// string-keyed lookup (a FindCovering that probes every prefix length from /0
// up, VRPs kept in a slice in store order), holding each distinct VRP once
// (issue #66), with RTR's publication points.
// Lookups see the set as of the last RebuildIndex or ReplaceAll; AddVRP,
// RemoveVRP and Clear change only the set being built. (The original store
// also rebuilt on RemoveVRP and emptied the index on Clear, so mid-sync
// lookups saw half-applied syncs.)
type refStore struct {
	vrps     []types.VRP
	have     map[types.VRP]bool // members of vrps
	byPrefix map[string][]types.VRP
}

func newRefStore() *refStore {
	return &refStore{have: make(map[types.VRP]bool), byPrefix: make(map[string][]types.VRP)}
}

func (s *refStore) Clear() { s.vrps, s.have = nil, make(map[types.VRP]bool) }

func (s *refStore) ReplaceAll(vrps []types.VRP) {
	s.Clear()
	for _, v := range vrps {
		s.AddVRP(v)
	}
	s.rebuildIndex()
}

func (s *refStore) AddVRP(vrp types.VRP) {
	if !s.have[vrp] {
		s.have[vrp] = true
		s.vrps = append(s.vrps, vrp)
	}
}

func (s *refStore) RemoveVRP(vrp types.VRP) {
	for i, v := range s.vrps {
		if v.Prefix == vrp.Prefix && v.ASN == vrp.ASN && v.MaxLength == vrp.MaxLength {
			delete(s.have, v)
			s.vrps = append(s.vrps[:i], s.vrps[i+1:]...)
			break
		}
	}
}

func (s *refStore) FindCovering(prefix netip.Prefix) []types.VRP {
	var result []types.VRP
	addr := prefix.Addr()
	for pl := 0; pl <= prefix.Bits(); pl++ {
		candidate, err := addr.Prefix(pl)
		if err != nil {
			continue
		}
		if vrps, ok := s.byPrefix[candidate.String()]; ok {
			result = append(result, vrps...)
		}
	}
	return result
}

func (s *refStore) rebuildIndex() {
	s.byPrefix = make(map[string][]types.VRP, len(s.vrps))
	for _, vrp := range s.vrps {
		key := vrp.Prefix.String()
		s.byPrefix[key] = append(s.byPrefix[key], vrp)
	}
}

// randPrefix draws from a small universe so prefixes nest and repeat, in
// IPv4, IPv6 and IPv4-mapped IPv6, now and then unmasked (host bits set).
func randPrefix(rng *rand.Rand) netip.Prefix {
	var a netip.Addr
	switch rng.IntN(6) {
	case 0, 1, 2:
		a = netip.AddrFrom4([4]byte{10, byte(rng.IntN(4)), byte(rng.IntN(4) * 64), byte(rng.IntN(2) * 128)})
	case 3, 4:
		a = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(rng.IntN(4)), byte(rng.IntN(2) * 128), 0, byte(rng.IntN(3))})
	default:
		a = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 10, 13: byte(rng.IntN(4))})
	}
	bits := rng.IntN(a.BitLen() + 1)
	if rng.IntN(15) == 0 {
		return netip.PrefixFrom(a, bits) // host bits possibly set
	}
	p, _ := a.Prefix(bits)
	return p
}

func randVRP(rng *rand.Rand) types.VRP {
	p := randPrefix(rng)
	return types.VRP{
		Prefix:    p,
		ASN:       uint32(64500 + rng.IntN(4)),
		MaxLength: uint8(p.Bits() + rng.IntN(p.Addr().BitLen()-p.Bits()+1)),
	}
}

// Property: through any sequence of the RTR writer's operations (bulk
// replace, single adds and removes, syncs of many adds and removes ending in
// End of Data, clears), FindCovering returns exactly what the reference
// returns: the same VRPs, in the same order, for IPv4, IPv6, IPv4-mapped and
// invalid prefixes, both mid-sync and after End of Data. Count and All follow
// the set being built.
func TestFindCoveringMatchesReference(t *testing.T) {
	for seed := uint64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewPCG(seed, 7))
		s, ref := NewVRPStore(), newRefStore()
		var live []types.VRP
		check := func(op string) {
			t.Helper()
			for i := 0; i < 60; i++ {
				p := randPrefix(rng)
				if i == 0 {
					p = netip.Prefix{} // invalid
				}
				got, want := s.FindCovering(p), ref.FindCovering(p)
				if !slices.Equal(got, want) || (got == nil) != (want == nil) {
					t.Fatalf("seed %d after %s: FindCovering(%s)\n got  %v\n want %v", seed, op, p, got, want)
				}
			}
			if got, want := s.All(), ref.vrps; !slices.Equal(got, want) || s.Count() != uint64(len(want)) {
				t.Fatalf("seed %d after %s: All = %v (Count %d), want %v", seed, op, got, s.Count(), want)
			}
		}
		removeOne := func() types.VRP {
			v := randVRP(rng)
			if len(live) > 0 && rng.IntN(4) > 0 {
				i := rng.IntN(len(live))
				v = live[i]
				live = append(live[:i], live[i+1:]...)
			}
			return v
		}
		for step := 0; step < 60; step++ {
			switch r := rng.IntN(20); {
			case r == 0:
				s.Clear()
				ref.Clear()
				live = nil
				check("Clear")
			case r == 1:
				vrps := make([]types.VRP, rng.IntN(40))
				for i := range vrps {
					vrps[i] = randVRP(rng)
					if i > 0 && rng.IntN(10) == 0 {
						vrps[i] = vrps[i-1] // duplicate
					}
				}
				live = slices.Clone(vrps)
				s.ReplaceAll(slices.Clone(vrps), 1, 1)
				ref.ReplaceAll(slices.Clone(vrps))
				check("ReplaceAll")
			case r < 12:
				v := randVRP(rng)
				s.AddVRP(v)
				ref.AddVRP(v)
				live = append(live, v)
				check("AddVRP") // not yet indexed, in either
			case r < 15:
				v := removeOne()
				s.RemoveVRP(v)
				ref.RemoveVRP(v)
				check("RemoveVRP") // not yet unindexed, in either
			case r < 17:
				// A sync: a batch of withdrawals, or of mixed withdrawals
				// and announcements, checked mid-sync and at End of Data.
				mixed := rng.IntN(2) == 0
				for n := 1 + rng.IntN(25); n > 0; n-- {
					if mixed && rng.IntN(2) == 0 {
						v := randVRP(rng)
						if len(live) > 0 && rng.IntN(5) == 0 {
							v = live[rng.IntN(len(live))] // duplicate
						}
						s.AddVRP(v)
						ref.AddVRP(v)
						live = append(live, v)
						continue
					}
					v := removeOne()
					s.RemoveVRP(v)
					ref.RemoveVRP(v)
				}
				check("a sync before End of Data")
				s.RebuildIndex()
				ref.rebuildIndex()
				check("a sync's End of Data")
			default:
				s.RebuildIndex()
				ref.rebuildIndex()
				check("RebuildIndex")
			}
		}
	}
}

// The same on a large realistic set: 750k VRPs, the first 100k routes.
func TestFindCoveringMatchesReferenceSynthetic(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two 750k-VRP indexes")
	}
	sy := synth()
	s, ref := NewVRPStore(), newRefStore()
	s.ReplaceAll(slices.Clone(sy.VRPs), 1, 1)
	ref.ReplaceAll(slices.Clone(sy.VRPs))
	for _, p := range sy.Routes[:100_000] {
		if got, want := s.FindCovering(p), ref.FindCovering(p); !slices.Equal(got, want) {
			t.Fatalf("FindCovering(%s)\n got  %v\n want %v", p, got, want)
		}
	}
}

// On a warm store, FindCovering does not allocate. The first lookup under a
// nested VRP prefix builds that prefix's list once; later ones share it.
func TestFindCoveringDoesNotAllocate(t *testing.T) {
	sy := storetest.NewSynth(50_000, 20_000, 3)
	s := NewVRPStore()
	s.ReplaceAll(sy.VRPs, 1, 1)
	covered := 0
	for _, p := range sy.Routes { // warm
		if len(s.FindCovering(p)) > 1 {
			covered++
		}
	}
	if covered == 0 {
		t.Fatal("no route has more than one covering VRP; the test would not exercise nested lists")
	}
	allocs := testing.AllocsPerRun(5, func() {
		for _, p := range sy.Routes {
			s.FindCovering(p)
		}
	})
	if allocs != 0 {
		t.Fatalf("FindCovering allocated %v times per %d lookups on a warm store, want 0", allocs, len(sy.Routes))
	}
}

// Lookups racing each other (building the same nested list) and the RTR
// writer (adding, removing, rebuilding) see consistent results. Run with
// -race.
func TestFindCoveringConcurrentWithWriter(t *testing.T) {
	sy := storetest.NewSynth(20_000, 5_000, 4)
	s := NewVRPStore()
	s.ReplaceAll(slices.Clone(sy.VRPs), 1, 1)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				for _, p := range sy.Routes {
					for _, v := range s.FindCovering(p) {
						if !v.Prefix.Contains(p.Addr()) || v.Prefix.Bits() > p.Bits() {
							t.Errorf("FindCovering(%s) returned %s, which does not cover it", p, v.Prefix)
							return
						}
					}
				}
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}
	for i := 0; i < 30; i++ {
		v := sy.VRPs[i*7]
		s.RemoveVRP(v)
		s.AddVRP(v)
		s.RebuildIndex()
	}
	close(stop)
	wg.Wait()
}

// A FindCovering result held across index rebuilds, as a route holds its
// MatchedVRPs, keeps only its own VRPs alive, not the index it came from.
func TestFindCoveringResultDoesNotPinIndex(t *testing.T) {
	sy := storetest.NewSynth(200_000, 1000, 5)
	s := NewVRPStore()
	var held [][]types.VRP
	var m0, m1 runtime.MemStats
	for gen := 0; gen < 12; gen++ {
		s.ReplaceAll(slices.Clone(sy.VRPs), uint32(gen), 1)
		for _, p := range sy.Routes[:50] {
			if l := s.FindCovering(p); l != nil {
				held = append(held, l)
			}
		}
		if gen == 1 {
			runtime.GC()
			runtime.ReadMemStats(&m0)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	runtime.KeepAlive(held)
	// One 200k-VRP index's VRP array is about 8 MB; ten pinned would be 80.
	if grew := int64(m1.HeapAlloc) - int64(m0.HeapAlloc); grew > 4<<20 {
		t.Fatalf("heap grew %d MiB over 10 rebuilds while holding %d results: old indexes are pinned", grew>>20, len(held))
	}
}
