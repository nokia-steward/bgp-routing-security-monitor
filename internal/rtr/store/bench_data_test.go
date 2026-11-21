package store

import (
	"os"
	"sync"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store/storetest"
)

// About the size of the global VRP set in 2026.
const benchVRPs, benchRoutes = 750_000, 1_000_000

var (
	benchSynthOnce sync.Once
	benchSynth     *storetest.Synth
	benchRealOnce  sync.Once
	benchReal      *storetest.Synth
	benchRealErr   error
)

// synth is the synthetic benchmark set: 750k VRPs and 1M routes.
func synth() *storetest.Synth {
	benchSynthOnce.Do(func() { benchSynth = storetest.NewSynth(benchVRPs, benchRoutes, 1) })
	return benchSynth
}

type dataset struct {
	name string
	*storetest.Synth
}

// datasets returns the synthetic set and, if testdata/vrps-real.json (a
// Routinator /json export, gitignored) is present, the real VRPs with 1M
// synthetic routes drawn over them.
func datasets(tb testing.TB) []dataset {
	out := []dataset{{"synthetic", synth()}}
	if _, err := os.Stat(storetest.RealVRPsPath); err != nil {
		return out
	}
	benchRealOnce.Do(func() {
		vrps, err := storetest.LoadRoutinatorJSON(storetest.RealVRPsPath)
		if err != nil {
			benchRealErr = err
			return
		}
		benchReal = storetest.NewSynthFrom(vrps, benchRoutes, 1)
	})
	if benchRealErr != nil {
		tb.Fatal(benchRealErr)
	}
	return append(out, dataset{"real", benchReal})
}
