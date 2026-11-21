// Package storetest generates synthetic RPKI data for tests and benchmarks.
package storetest

import (
	"math/rand/v2"
	"net/netip"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Synth is a deterministic synthetic VRP set and a set of route prefixes and
// origins to validate against it, shaped loosely like the global RPKI: ROA
// prefixes mostly /24 (IPv4) and /48 or /32 (IPv6), with a tail of shorter
// ones down to /8 and /19, some with more-specific ROAs under them, maxLength
// usually the prefix length and sometimes longer; routes mostly under a ROA,
// usually from its AS, the rest anywhere.
type Synth struct {
	VRPs    []types.VRP
	Routes  []netip.Prefix
	Origins []uint32 // Origins[i] originates Routes[i]
}

// NewSynth generates nVRP VRPs (about a fifth IPv6) and nRoute routes.
func NewSynth(nVRP, nRoute int, seed uint64) *Synth {
	rng := rand.New(rand.NewPCG(seed, 0x5eed))
	s := &Synth{}
	asn := func() uint32 { return randASN(rng) }
	v4 := func(bits int) netip.Prefix { return randV4(rng, bits) }
	v6 := func(bits int) netip.Prefix { return randV6(rng, bits) }
	// ROA prefix lengths, roughly as published: mostly /24 and /48.
	roaBits4 := func() int {
		switch r := rng.IntN(100); {
		case r < 55:
			return 24
		case r < 70:
			return 22 + rng.IntN(2)
		case r < 80:
			return 20 + rng.IntN(2)
		case r < 97:
			return 16 + rng.IntN(4)
		default:
			// Short ROAs are for large allocations: mostly /12 to /15,
			// a /8 to /11 only now and then.
			if rng.IntN(20) == 0 {
				return 8 + rng.IntN(4)
			}
			return 12 + rng.IntN(4)
		}
	}
	roaBits6 := func() int {
		switch r := rng.IntN(100); {
		case r < 45:
			return 48
		case r < 70:
			return 32
		case r < 85:
			return 29 + rng.IntN(3)
		default:
			return 33 + rng.IntN(15)
		}
	}
	maxLen := func(p netip.Prefix, limit int) uint8 {
		switch r := rng.IntN(10); {
		case r < 6:
			return uint8(p.Bits())
		case r < 9:
			return uint8(limit)
		default:
			return uint8(p.Bits() + rng.IntN(limit-p.Bits()+1))
		}
	}
	for len(s.VRPs) < nVRP {
		var p netip.Prefix
		limit := 24
		if rng.IntN(5) == 0 {
			p, limit = v6(roaBits6()), 48
		} else {
			p = v4(roaBits4())
		}
		as := asn()
		s.VRPs = append(s.VRPs, types.VRP{Prefix: p, ASN: as, MaxLength: maxLen(p, limit)})
		// Some ROAs have more-specifics, from the same AS or another.
		if rng.IntN(4) == 0 && p.Bits() < limit {
			for n := 1 + rng.IntN(3); n > 0 && len(s.VRPs) < nVRP; n-- {
				sub := subprefix(rng, p, p.Bits()+1+rng.IntN(limit-p.Bits()))
				if rng.IntN(3) == 0 {
					as = asn()
				}
				s.VRPs = append(s.VRPs, types.VRP{Prefix: sub, ASN: as, MaxLength: maxLen(sub, limit)})
			}
		}
		// The odd duplicate, as when two ROAs say the same thing.
		if rng.IntN(200) == 0 && len(s.VRPs) < nVRP {
			s.VRPs = append(s.VRPs, s.VRPs[len(s.VRPs)-1])
		}
	}
	s.addRoutes(rng, nRoute)
	return s
}

// addRoutes draws routes until there are nRoute.
func (s *Synth) addRoutes(rng *rand.Rand, nRoute int) {
	for len(s.Routes) < nRoute {
		if len(s.VRPs) > 0 && rng.IntN(5) < 3 {
			v := s.VRPs[rng.IntN(len(s.VRPs))]
			limit := 24
			if !v.Prefix.Addr().Is4() {
				limit = 48
			}
			limit = max(limit, v.Prefix.Bits())
			bits := v.Prefix.Bits() + rng.IntN(limit-v.Prefix.Bits()+1)
			o := v.ASN
			if rng.IntN(7) == 0 {
				o = randASN(rng)
			}
			s.Routes = append(s.Routes, subprefix(rng, v.Prefix.Masked(), bits))
			s.Origins = append(s.Origins, o)
			continue
		}
		if rng.IntN(5) == 0 {
			s.Routes = append(s.Routes, randV6(rng, 32+rng.IntN(17)))
		} else {
			s.Routes = append(s.Routes, randV4(rng, 16+rng.IntN(9)))
		}
		s.Origins = append(s.Origins, randASN(rng))
	}
}

func randASN(rng *rand.Rand) uint32 { return 1 + rng.Uint32N(80_000) }

func randV4(rng *rand.Rand, bits int) netip.Prefix {
	a := netip.AddrFrom4([4]byte{byte(1 + rng.IntN(222)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
	p, _ := a.Prefix(bits)
	return p
}

func randV6(rng *rand.Rand, bits int) netip.Prefix {
	var b [16]byte
	b[0], b[1] = 0x20, byte(rng.IntN(16))
	for i := 2; i < 8; i++ {
		b[i] = byte(rng.IntN(256))
	}
	p, _ := netip.AddrFrom16(b).Prefix(bits)
	return p
}

// subprefix returns a random prefix of the given length inside p.
func subprefix(rng *rand.Rand, p netip.Prefix, bits int) netip.Prefix {
	b := p.Addr().As16()
	for i := p.Bits(); i < bits; i++ {
		bit := i
		if p.Addr().Is4() {
			bit += 96
		}
		if rng.IntN(2) == 1 {
			b[bit/8] |= 0x80 >> (bit % 8)
		}
	}
	a := netip.AddrFrom16(b)
	if p.Addr().Is4() {
		a = a.Unmap()
	}
	out, _ := a.Prefix(bits)
	return out
}
