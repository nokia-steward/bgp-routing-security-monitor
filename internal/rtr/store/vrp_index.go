package store

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// covEntry is one distinct VRP prefix in the index: its own VRPs, in store
// order, and the nearest shorter VRP prefix containing it.
//
// The VRPs covering a route are those of its longest covering VRP prefix and
// of every ancestor of that prefix (covering prefixes nest), shortest first.
// An entry with no parent hands out own as is; one with ancestors builds that
// list the first time a lookup needs it and keeps it in full. Nothing is
// modified after that, so lookups share these slices without copying and
// without holding a lock once they have them.
type covEntry struct {
	own    []types.VRP
	parent *covEntry
	full   atomic.Pointer[[]types.VRP]
}

// covering returns the VRPs covering any prefix whose longest covering VRP
// prefix is e's.
func (e *covEntry) covering() []types.VRP {
	if e.parent == nil {
		return e.own
	}
	if l := e.full.Load(); l != nil {
		return *l
	}
	var chain [129]*covEntry // a prefix has at most 128 ancestors
	n, total := 0, 0
	for c := e; c != nil; c = c.parent {
		chain[n] = c
		n++
		total += len(c.own)
	}
	l := make([]types.VRP, 0, total)
	for i := n - 1; i >= 0; i-- {
		l = append(l, chain[i].own...)
	}
	// Concurrent lookups may each build it; they build the same list and
	// the first one stored is kept.
	if !e.full.CompareAndSwap(nil, &l) {
		return *e.full.Load()
	}
	return l
}

// buildEntries groups the VRPs by prefix and links each prefix to its nearest
// ancestor. It returns the prefixes and their entries. order gives each VRP's
// place in store order, which orders a prefix's VRPs; nil means vrps is in
// store order.
//
// Only masked VRP prefixes are indexed. Lookups are by masked prefix, so a VRP
// whose prefix has host bits set never covered anything; it never did with
// the string-keyed index either.
func buildEntries(vrps []types.VRP, order []uint64) ([]netip.Prefix, []*covEntry) {
	// Sort compact keys rather than the VRPs, or indices into them: the
	// comparisons then read contiguous memory, which is most of the cost.
	type sortKey struct {
		hi, lo    uint64
		ord       uint64
		idx       int32
		fam, bits uint8
	}
	sk := make([]sortKey, 0, len(vrps))
	for i, v := range vrps {
		if !v.Prefix.IsValid() || v.Prefix != v.Prefix.Masked() {
			continue
		}
		a := v.Prefix.Addr()
		b := a.As16()
		fam := uint8(6)
		if a.Is4() {
			fam = 4
		}
		ord := uint64(i)
		if order != nil {
			ord = order[i]
		}
		sk = append(sk, sortKey{
			hi: binary.BigEndian.Uint64(b[:8]), lo: binary.BigEndian.Uint64(b[8:]),
			ord: ord, idx: int32(i), fam: fam, bits: uint8(v.Prefix.Bits()),
		})
	}
	// Family, address, then shorter first: a prefix's ancestors sort before
	// it, and the ones still open form a stack (prefixes nest or are
	// disjoint). Ties by store order keep each prefix's VRPs in it.
	slices.SortFunc(sk, func(a, b sortKey) int {
		switch {
		case a.fam != b.fam:
			return int(a.fam) - int(b.fam)
		case a.hi != b.hi:
			return cmp.Compare(a.hi, b.hi)
		case a.lo != b.lo:
			return cmp.Compare(a.lo, b.lo)
		case a.bits != b.bits:
			return int(a.bits) - int(b.bits)
		}
		return cmp.Compare(a.ord, b.ord)
	})
	same := func(a, b sortKey) bool { return a.fam == b.fam && a.hi == b.hi && a.lo == b.lo && a.bits == b.bits }
	n := 0 // distinct prefixes
	for k := range sk {
		if k == 0 || !same(sk[k], sk[k-1]) {
			n++
		}
	}
	keys := make([]netip.Prefix, 0, n)
	entries := make([]*covEntry, 0, n)
	slab := make([]covEntry, n) // one allocation for every entry
	var stack []int
	for i := 0; i < len(sk); {
		p := vrps[sk[i].idx].Prefix
		j := i + 1
		for j < len(sk) && same(sk[j], sk[i]) {
			j++
		}
		for len(stack) > 0 {
			top := keys[stack[len(stack)-1]]
			if top.Bits() < p.Bits() && top.Contains(p.Addr()) {
				break
			}
			stack = stack[:len(stack)-1]
		}
		e := &slab[len(keys)]
		// Each prefix gets its own exact-size slice, not a window on one
		// shared array: routes keep the slices FindCovering returns, and a
		// window would keep that whole array alive as long as any did.
		e.own = make([]types.VRP, j-i)
		for k := i; k < j; k++ {
			e.own[k-i] = vrps[sk[k].idx]
		}
		if len(stack) > 0 {
			e.parent = entries[stack[len(stack)-1]]
		}
		stack = append(stack, len(keys))
		keys = append(keys, p)
		entries = append(entries, e)
		i = j
	}
	return keys, entries
}

// vrpIndex finds the VRPs covering a prefix with one longest-prefix-match
// lookup in a BART table of the VRP prefixes.
type vrpIndex struct {
	t bart.Table[*covEntry]
}

func newVRPIndex(vrps []types.VRP, order []uint64) *vrpIndex {
	keys, entries := buildEntries(vrps, order)
	ix := &vrpIndex{}
	for i, p := range keys {
		ix.t.Insert(p, entries[i])
	}
	return ix
}

// covering returns the VRPs whose prefix is equal to or less specific than
// prefix, shortest prefix first and, within a prefix, in store order; nil if
// none. The slice is shared: callers must not modify it.
func (ix *vrpIndex) covering(prefix netip.Prefix) []types.VRP {
	if !prefix.IsValid() {
		return nil
	}
	_, e, ok := ix.t.LookupPrefixLPM(prefix)
	if !ok {
		return nil
	}
	return e.covering()
}
