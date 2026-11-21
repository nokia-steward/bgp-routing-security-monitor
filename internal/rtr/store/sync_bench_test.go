package store

import (
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// BenchmarkWithdrawSync applies an incremental RTR sync that withdraws 8,882
// VRPs the way the RTR client does (RemoveVRP for each, then SetSerial and
// RebuildIndex at End of Data) while four readers look up routes as
// validation does. It reports the sync's wall time, how many index rebuilds
// it caused, and the longest any single FindCovering call took during it.
// RAVEN_WITHDRAW_N overrides the count.
//
//	go test -run '^$' -bench WithdrawSync -benchtime 1x ./internal/rtr/store/
func BenchmarkWithdrawSync(b *testing.B) {
	n := 8882
	if v, err := strconv.Atoi(os.Getenv("RAVEN_WITHDRAW_N")); err == nil {
		n = v
	}
	for _, ds := range datasets(b) {
		b.Run(ds.name, func(b *testing.B) {
			withdraw := make([]types.VRP, n)
			for i := range withdraw {
				withdraw[i] = ds.VRPs[i*(len(ds.VRPs)/n)]
			}
			var wall, maxStall time.Duration
			var rebuilds uint64
			var lookups int64
			for it := 0; it < b.N; it++ {
				b.StopTimer()
				s := NewVRPStore()
				s.ReplaceAll(slices.Clone(ds.VRPs), 1, 1)
				for _, p := range ds.Routes { // warm
					s.FindCovering(p)
				}
				r0 := rebuildsOf(s)
				var stop atomic.Bool
				var wg sync.WaitGroup
				stalls := make([]time.Duration, 4)
				counts := make([]int64, 4)
				for g := range stalls {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for i := g * 997; !stop.Load(); i++ {
							t := time.Now()
							s.FindCovering(ds.Routes[i%len(ds.Routes)])
							stalls[g] = max(stalls[g], time.Since(t))
							counts[g]++
						}
					}()
				}
				b.StartTimer()

				start := time.Now()
				for _, v := range withdraw {
					s.RemoveVRP(v)
				}
				s.SetSerial(2, 1)
				s.RebuildIndex()
				wall += time.Since(start)

				b.StopTimer()
				stop.Store(true)
				wg.Wait()
				rebuilds += rebuildsOf(s) - r0
				for g := range stalls {
					maxStall = max(maxStall, stalls[g])
					lookups += counts[g]
				}
			}
			b.ReportMetric(float64(wall.Milliseconds())/float64(b.N), "wall-ms")
			b.ReportMetric(float64(rebuilds)/float64(b.N), "rebuilds")
			b.ReportMetric(float64(maxStall.Microseconds())/1000, "max-stall-ms")
			b.ReportMetric(float64(lookups)/float64(b.N), "lookups")
			b.ReportMetric(0, "ns/op")
		})
	}
}

// BenchmarkFindCoveringDuringRebuild measures lookup latency while the index
// is being rebuilt back to back on another goroutine, as during End of Data:
// mean (ns/op), the 99.9th percentile and the maximum single lookup.
//
//	go test -run '^$' -bench FindCoveringDuringRebuild ./internal/rtr/store/
func BenchmarkFindCoveringDuringRebuild(b *testing.B) {
	for _, ds := range datasets(b) {
		b.Run(ds.name, func(b *testing.B) {
			s := NewVRPStore()
			s.ReplaceAll(slices.Clone(ds.VRPs), 1, 1)
			for _, p := range ds.Routes {
				s.FindCovering(p)
			}
			var stop atomic.Bool
			done := make(chan uint64)
			go func() {
				r0 := s.Rebuilds()
				for !stop.Load() {
					s.RebuildIndex()
				}
				done <- s.Rebuilds() - r0
			}()
			lat := make([]time.Duration, b.N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				t := time.Now()
				s.FindCovering(ds.Routes[i%len(ds.Routes)])
				lat[i] = time.Since(t)
			}
			b.StopTimer()
			stop.Store(true)
			rebuilds := <-done
			slices.Sort(lat)
			b.ReportMetric(float64(lat[len(lat)*999/1000].Microseconds()), "p99.9-µs")
			b.ReportMetric(float64(lat[len(lat)-1].Microseconds())/1000, "max-ms")
			b.ReportMetric(float64(rebuilds), "rebuilds")
		})
	}
}
