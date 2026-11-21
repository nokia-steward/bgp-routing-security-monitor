package routetable

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

const benchPeers = 115

// benchRoutes builds n pre-policy routes spread across benchPeers peers, all
// with the same posture. One posture is the worst case for the posture index,
// the largest of the three.
func benchRoutes(n int) []*types.Route {
	routes := make([]*types.Route, n)
	for i := range routes {
		routes[i] = &types.Route{
			PeerAddr:        netip.AddrFrom4([4]byte{192, 0, 2, byte(i % benchPeers)}),
			Prefix:          netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32),
			ASPath:          []uint32{64500, uint32(65000 + i%1000)},
			RIBType:         types.AdjRIBInPre,
			SecurityPosture: types.PostureOriginOnly,
			OwnerSession:    benchSession,
		}
	}
	return routes
}

// benchSession is the BMP session the bench routes arrive on, so peer-downs
// take the same path as a live session's.
const benchSession = 1

func buildTable(routes []*types.Route) *Table {
	tbl := New()
	for _, r := range routes {
		tbl.Insert(r)
	}
	return tbl
}

var benchSizes = []int{25_000, 50_000, 100_000}

// BenchmarkInsert measures building a table of n routes from empty.
func BenchmarkInsert(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			routes := benchRoutes(n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buildTable(routes)
			}
		})
	}
}

// BenchmarkWithdrawAllFromPeer measures one peer going down in a table of n
// routes; the peer holds about n/115 of them.
func BenchmarkWithdrawAllFromPeer(b *testing.B) {
	peer := netip.AddrFrom4([4]byte{192, 0, 2, 7})
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			routes := benchRoutes(n)
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				tbl := buildTable(routes)
				b.StartTimer()
				tbl.WithdrawAllFromPeer(types.PeerRef{Addr: peer}, benchSession, types.AdjRIBInPre)
			}
		})
	}
}

// Index maintenance must cost O(1) per route. It used to scan a slice of
// every key under the same posture or origin on each insert and removal,
// which made building a table, and draining it peer by peer, quadratic: 100k
// routes took 12.8s to insert, and one large peer going down at 1M routes
// held the posture-index lock for an estimated 15-20s.
//
// Growing the table 8x should grow the time about 8x; quadratic cost grows
// it about 64x. The threshold sits between the two with room for timing
// noise on either side.
func TestIndexMaintenanceScalesLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-based; skipped in -short mode")
	}
	const (
		small     = 10_000
		factor    = 8
		threshold = 24.0
	)

	cycle := func(routes []*types.Route) time.Duration {
		best := time.Duration(1<<63 - 1)
		for rep := 0; rep < 3; rep++ {
			start := time.Now()
			tbl := buildTable(routes)
			for p := 0; p < benchPeers; p++ {
				tbl.WithdrawAllFromPeer(types.PeerRef{Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(p)})}, benchSession, types.AdjRIBInPre)
			}
			if d := time.Since(start); d < best {
				best = d
			}
			if tbl.Count() != 0 {
				t.Fatalf("table not empty after withdrawing every peer: %d routes left", tbl.Count())
			}
		}
		return best
	}

	base := cycle(benchRoutes(small))
	large := cycle(benchRoutes(factor * small))
	ratio := float64(large) / float64(base)
	t.Logf("insert + withdraw-every-peer: %d routes %v, %d routes %v, ratio %.1fx", small, base, factor*small, large, ratio)
	if ratio > threshold {
		t.Errorf("%dx the routes took %.1fx as long; want about %dx. Index maintenance is not O(1) per route.",
			factor, ratio, factor)
	}
}
