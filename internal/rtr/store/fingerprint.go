package store

import (
	"fmt"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Fingerprint identifies a set of VRPs and ASPA records independently of
// order: two sets with the same records have the same fingerprint, however
// and in whatever order they were built. It is the sum, modulo 2^64 in each
// of two independent lanes, of a 128-bit hash of every record, so it is
// kept up to date in O(1) per record added or removed (Add, Sub) and costs
// 16 bytes per owner.
//
// A sum of hashes is a multiset hash (AdHash): for data that is not built
// to collide, two different sets share a fingerprint with probability about
// 2^-64 per comparison or less. RTR data is not adversarial here: a cache
// that wanted to fool a monitor would not need a hash collision.
type Fingerprint struct{ A, B uint64 }

// Add returns f with the record hashed as h added.
func (f Fingerprint) Add(h Fingerprint) Fingerprint { return Fingerprint{f.A + h.A, f.B + h.B} }

// Sub returns f with the record hashed as h removed.
func (f Fingerprint) Sub(h Fingerprint) Fingerprint { return Fingerprint{f.A - h.A, f.B - h.B} }

// String is the fingerprint as 32 hex digits, as the data_fingerprint
// field of a sync record writes it.
func (f Fingerprint) String() string { return fmt.Sprintf("%016x%016x", f.A, f.B) }

// mix64 is the splitmix64 finalizer: a bijection on 64 bits whose output
// bits each depend on every input bit.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// Seeds per lane and per record kind, so a VRP and an ASPA record never
// hash alike, and the two lanes are independent.
const (
	seedVRPA  = 0x9e3779b97f4a7c15
	seedVRPB  = 0xc2b2ae3d27d4eb4f
	seedASPAA = 0x165667b19e3779f9
	seedASPAB = 0x27d4eb2f165667c5
)

// hash3 folds three words into one lane's hash.
func hash3(seed, a, b, c uint64) uint64 {
	h := mix64(seed ^ a)
	h = mix64(h ^ b)
	return mix64(h ^ c)
}

// VRPHash is a VRP's contribution to a fingerprint.
func VRPHash(v types.VRP) Fingerprint {
	addr := v.Prefix.Addr().As16()
	var hi, lo uint64
	for i := range 8 {
		hi = hi<<8 | uint64(addr[i])
		lo = lo<<8 | uint64(addr[8+i])
	}
	var is4 uint64
	if v.Prefix.Addr().Is4() {
		is4 = 1
	}
	meta := is4<<48 | uint64(uint8(v.Prefix.Bits()))<<40 | uint64(v.MaxLength)<<32 | uint64(v.ASN)
	return Fingerprint{hash3(seedVRPA, hi, lo, meta), hash3(seedVRPB, hi, lo, meta)}
}

// ASPAHash is an ASPA record's contribution to a fingerprint: its customer
// and its provider set, sorted and without duplicates (as the store keeps
// it).
func ASPAHash(customer uint32, providers []uint32) Fingerprint {
	a, b := mix64(seedASPAA^uint64(customer)), mix64(seedASPAB^uint64(customer))
	for _, p := range providers {
		a = mix64(a ^ uint64(p))
		b = mix64(b ^ uint64(p) ^ seedASPAA)
	}
	n := uint64(len(providers))
	return Fingerprint{mix64(a ^ n), mix64(b ^ n<<32)}
}
