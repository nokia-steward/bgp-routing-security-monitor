package routetable

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// BenchmarkTableBytesPerRoute reports the heap a table keeps per route:
// 1M routes from 4 peers (a BMP feed's shape), with all indexes, after GC.
// The route objects themselves are included.
//
//	go test -run '^$' -bench TableBytesPerRoute -benchtime 1x ./internal/routetable/
func BenchmarkTableBytesPerRoute(b *testing.B) {
	const n = 1_000_000
	peers := []netip.Addr{
		netip.MustParseAddr("80.81.194.180"), netip.MustParseAddr("80.81.194.181"),
		netip.MustParseAddr("206.82.106.254"), netip.MustParseAddr("2001:7f8::1"),
	}
	for it := 0; it < b.N; it++ {
		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		t := New()
		for i := 0; i < n; i++ {
			t.Insert(&types.Route{
				PeerAddr:        peers[i%len(peers)],
				Prefix:          netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0}), 24),
				ASPath:          []uint32{64500, uint32(64501 + i%5000)},
				RIBType:         types.AdjRIBInPre,
				SecurityPosture: types.PostureUnverified,
				OwnerSession:    1,
			})
		}
		runtime.GC()
		runtime.ReadMemStats(&m1)
		b.ReportMetric(float64(m1.HeapAlloc-m0.HeapAlloc)/n, "bytes/route")
		runtime.KeepAlive(t)
	}
	b.ReportMetric(0, "ns/op")
}
