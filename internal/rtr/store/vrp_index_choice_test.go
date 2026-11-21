package store

import (
	"net/netip"
	"runtime"
	"slices"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// mapIndex is the alternative design to vrpIndex's BART table, kept to
// benchmark against it: probe a map keyed by netip.Prefix at each VRP prefix
// length present, longest first. Same entries, same results; vrpIndex was
// chosen because its single longest-prefix-match lookup is about 4x faster
// (see BenchmarkCoveringIndex), with no difference in build time.
type mapIndex struct {
	byPrefix     map[netip.Prefix]*covEntry
	lens4, lens6 []int // VRP prefix lengths present, longest first
}

func newMapIndex(vrps []types.VRP) *mapIndex {
	keys, entries := buildEntries(vrps, nil)
	ix := &mapIndex{byPrefix: make(map[netip.Prefix]*covEntry, len(keys))}
	var seen4, seen6 [129]bool
	for i, p := range keys {
		ix.byPrefix[p] = entries[i]
		if p.Addr().Is4() {
			seen4[p.Bits()] = true
		} else {
			seen6[p.Bits()] = true
		}
	}
	for l := 128; l >= 0; l-- {
		if seen4[l] {
			ix.lens4 = append(ix.lens4, l)
		}
		if seen6[l] {
			ix.lens6 = append(ix.lens6, l)
		}
	}
	return ix
}

func (ix *mapIndex) covering(prefix netip.Prefix) []types.VRP {
	addr, bits := prefix.Addr(), prefix.Bits()
	lens := ix.lens6
	if addr.Is4() {
		lens = ix.lens4
	}
	for _, l := range lens {
		if l > bits {
			continue
		}
		if c, err := addr.Prefix(l); err == nil {
			if e, ok := ix.byPrefix[c]; ok {
				return e.covering()
			}
		}
	}
	return nil
}

// BenchmarkCoveringIndex compares the two index designs on the same 750k
// synthetic VRPs: lookup per route prefix (warm), full build, and the heap
// each retains.
//
//	go test -run '^$' -bench CoveringIndex -benchmem ./internal/rtr/store/
func BenchmarkCoveringIndex(b *testing.B) {
	sy := synth()
	type index interface {
		covering(netip.Prefix) []types.VRP
	}
	builders := []struct {
		name  string
		build func([]types.VRP) index
	}{
		{"bart", func(v []types.VRP) index { return newVRPIndex(v, nil) }},
		{"map", func(v []types.VRP) index { return newMapIndex(v) }},
	}
	for _, bl := range builders {
		ix := bl.build(sy.VRPs)
		for _, p := range sy.Routes { // warm the nested lists
			ix.covering(p)
		}
		b.Run("lookup/"+bl.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ix.covering(sy.Routes[i%len(sy.Routes)])
			}
		})
	}
	for _, bl := range builders {
		b.Run("build/"+bl.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				bl.build(sy.VRPs)
			}
		})
	}
}

// TestIndexRetainedHeap logs the heap each index design keeps for 750k VRPs,
// beside the old string-keyed index's.
func TestIndexRetainedHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 750k-VRP indexes")
	}
	sy := synth()
	retained := func(build func() any) float64 {
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		ix := build()
		runtime.GC()
		runtime.ReadMemStats(&m1)
		runtime.KeepAlive(ix)
		return float64(int64(m1.HeapAlloc)-int64(m0.HeapAlloc)) / (1 << 20)
	}
	old := retained(func() any { r := newRefStore(); r.ReplaceAll(sy.VRPs); return r.byPrefix })
	bt := retained(func() any { return newVRPIndex(sy.VRPs, nil) })
	mp := retained(func() any { return newMapIndex(sy.VRPs) })
	t.Logf("retained heap for %d VRPs: old string-keyed %.0f MiB, BART %.0f MiB, map %.0f MiB (before any nested list is built)",
		len(sy.VRPs), old, bt, mp)
	oldStore := retained(func() any { r := newRefStore(); r.ReplaceAll(slices.Clone(sy.VRPs)); return r })
	newStore := retained(func() any { s := NewVRPStore(); s.ReplaceAll(sy.VRPs, 1, 1); return s })
	t.Logf("whole store: old (VRP slice + string index) %.0f MiB, new (keyed VRP set + BART index) %.0f MiB",
		oldStore, newStore)
}

// TestCoveringListSize reports the index's memory beyond the VRPs themselves:
// the nested lists built for the prefixes 1M routes hit.
func TestCoveringListSize(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 750k-VRP index")
	}
	sy := synth()
	keys, entries := buildEntries(sy.VRPs, nil)
	ix := &vrpIndex{}
	for i, p := range keys {
		ix.t.Insert(p, entries[i])
	}
	routeCopies := 0 // what the old FindCovering copied into routes
	for _, p := range sy.Routes {
		routeCopies += len(ix.covering(p))
	}
	nested, built := 0, 0
	for _, e := range entries {
		if e.parent != nil {
			nested++
			if l := e.full.Load(); l != nil {
				built += len(*l)
			}
		}
	}
	t.Logf("%d VRPs, %d prefixes (%d nested); nested lists built for 1M routes: %d VRP entries (%.2f per VRP); "+
		"the old per-route copies for the same routes: %d entries",
		len(sy.VRPs), len(keys), nested, built, float64(built)/float64(len(sy.VRPs)), routeCopies)
}
