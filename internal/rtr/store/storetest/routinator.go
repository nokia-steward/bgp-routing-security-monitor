package storetest

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// RealVRPsPath is where a Routinator /json export can be placed to run the
// store benchmarks on real data. It is gitignored; benchmarks skip it if
// absent.
const RealVRPsPath = "testdata/vrps-real.json"

// LoadRoutinatorJSON reads a Routinator /json export ({"roas": [{"asn":
// "AS13335", "prefix": "1.0.0.0/24", "maxLength": 24, ...}]}) into VRPs, in
// file order.
func LoadRoutinatorJSON(path string) ([]types.VRP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var doc struct {
		ROAs []struct {
			ASN       string `json:"asn"`
			Prefix    string `json:"prefix"`
			MaxLength int    `json:"maxLength"`
		} `json:"roas"`
	}
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	vrps := make([]types.VRP, 0, len(doc.ROAs))
	for i, r := range doc.ROAs {
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			return nil, fmt.Errorf("%s: roa %d: %w", path, i, err)
		}
		asn, err := strconv.ParseUint(strings.TrimPrefix(r.ASN, "AS"), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%s: roa %d: asn %q: %w", path, i, r.ASN, err)
		}
		vrps = append(vrps, types.VRP{Prefix: p, ASN: uint32(asn), MaxLength: uint8(r.MaxLength)})
	}
	return vrps, nil
}

// NewSynthFrom pairs the given VRPs with nRoute synthetic routes drawn as for
// NewSynth: mostly under a VRP, usually from its AS, the rest anywhere.
func NewSynthFrom(vrps []types.VRP, nRoute int, seed uint64) *Synth {
	s := NewSynth(0, 0, seed)
	s.VRPs = vrps
	rng := rand.New(rand.NewPCG(seed, 0x5eed))
	s.addRoutes(rng, nRoute)
	return s
}
