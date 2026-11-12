package telemetry

import (
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// The settle window: SettleUnknown until every compared cache has an
// interval, then twice the slowest cache's median interval_since, at least
// SettleFloor; --compare-settle replaces it.
func TestCrossCacheSettleWindow(t *testing.T) {
	cc := NewCrossCache(nil, 0, nil, nil)
	a, _ := cc.Add("a", store.NewVRPStore(), store.NewASPAStore())
	b, _ := cc.Add("b", store.NewVRPStore(), store.NewASPAStore())
	a.Synced(2)
	b.Synced(2)
	sync := func(cache string, interval time.Duration) {
		cc.ObserveSync(SessionEvent{Cache: cache, EventType: EventSync, IntervalSince: interval}, nil)
	}
	if got := cc.Settle(); got != SettleUnknown {
		t.Errorf("no intervals: settle %v, want %v", got, SettleUnknown)
	}
	sync("a", time.Minute)
	if got := cc.Settle(); got != SettleUnknown {
		t.Errorf("one cache's interval known: settle %v, want %v", got, SettleUnknown)
	}
	sync("b", 2*time.Minute)
	if got := cc.Settle(); got != SettleFloor {
		t.Errorf("intervals of 1m and 2m: settle %v, want the floor %v", got, SettleFloor)
	}
	// b's median of 10m, 10m, 2m and 30m is 10m: settle 20m. One slow poll
	// does not move it.
	for _, d := range []time.Duration{10 * time.Minute, 10 * time.Minute, 30 * time.Minute} {
		sync("b", d)
	}
	if got := cc.Settle(); got != 20*time.Minute {
		t.Errorf("b's median 10m: settle %v, want 20m", got)
	}
	// A cache out of the comparison does not count.
	b.Disconnected()
	c, _ := cc.Add("c", store.NewVRPStore(), store.NewASPAStore())
	c.Synced(2)
	sync("c", time.Minute)
	if got := cc.Settle(); got != SettleFloor {
		t.Errorf("b disconnected: settle %v, want %v", got, SettleFloor)
	}
	if got := NewCrossCache(nil, 3*time.Second, nil, nil).Settle(); got != 3*time.Second {
		t.Errorf("override: settle %v, want 3s", got)
	}
}

// keyOf and prefix round-trip IPv4 and IPv6 VRPs, host bits included.
func TestVRPKeyRoundTrip(t *testing.T) {
	for _, s := range []string{"10.0.19.136/24", "192.0.2.0/24", "2001:db8::/32", "::ffff:10.0.0.0/104", "0.0.0.0/0", "::/0"} {
		p := netip.MustParsePrefix(s)
		k := keyOf(types.VRP{Prefix: p, ASN: 64500, MaxLength: 33})
		if got := k.prefix(); got != p {
			t.Errorf("%s round-trips to %s", p, got)
		}
	}
}

// genBenchVRPs returns n distinct VRPs, three quarters IPv4 /24s and one
// quarter IPv6 /48s, about the mix of today's global RPKI.
func genBenchVRPs(n int) []types.VRP {
	out := make([]types.VRP, n)
	for i := range out {
		if i%4 == 3 {
			var b [16]byte
			b[0], b[1], b[2], b[3] = 0x20, 0x01, byte(i>>16), byte(i>>8)
			b[4], b[5] = byte(i), 0x01
			out[i] = types.VRP{Prefix: netip.PrefixFrom(netip.AddrFrom16(b), 48), ASN: uint32(64512 + i%1000), MaxLength: 48}
			continue
		}
		a := netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0})
		out[i] = types.VRP{Prefix: netip.PrefixFrom(a, 24), ASN: uint32(64512 + i%1000), MaxLength: 24}
	}
	return out
}

func heapMB() float64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapAlloc) / (1 << 20)
}

// Memory one cache costs rtr monitor at 1M VRPs: its VRPStore as the RTR
// client fills it (the VRP multiset and the published index), and the
// comparison's own set of the same VRPs. Run with -benchtime=1x.
func BenchmarkCrossCacheMemoryPerCache(b *testing.B) {
	const n = 1_000_000
	vrps := genBenchVRPs(n)
	var storeMB, setMB float64
	for range b.N {
		before := heapMB()
		vs := store.NewVRPStore()
		for _, v := range vrps {
			vs.AddVRP(v)
		}
		vs.RebuildIndex()
		mid := heapMB()
		cc := NewCrossCache(nil, 0, nil, nil)
		m, _ := cc.Add("c", vs, store.NewASPAStore())
		m.Update(store.FullDelta(), 1)
		after := heapMB()
		if len(m.vrps) != n {
			b.Fatalf("comparison set holds %d VRPs, want %d", len(m.vrps), n)
		}
		storeMB, setMB = mid-before, after-mid
		runtime.KeepAlive(vs)
		runtime.KeepAlive(m)
	}
	b.ReportMetric(storeMB, "store-MB/cache")
	b.ReportMetric(setMB, "compare-MB/cache")
	b.ReportMetric(storeMB+setMB, "MB/cache")
}

// A VRP announced twice stays held until withdrawn twice, as in the
// VRPStore.
func TestCrossCacheDuplicateVRP(t *testing.T) {
	cc := NewCrossCache(nil, 0, nil, nil)
	m, _ := cc.Add("a", store.NewVRPStore(), store.NewASPAStore())
	v := types.VRP{Prefix: netip.MustParsePrefix("192.0.2.0/24"), ASN: 64500, MaxLength: 24}
	m.Update(&store.Delta{VRPAnnounced: []types.VRP{v, v}}, 1)
	m.Update(&store.Delta{VRPWithdrawn: []types.VRP{v}}, 2)
	if _, ok := m.vrps[keyOf(v)]; !ok {
		t.Fatal("VRP announced twice and withdrawn once is gone")
	}
	m.Update(&store.Delta{VRPWithdrawn: []types.VRP{v}}, 3)
	if _, ok := m.vrps[keyOf(v)]; ok {
		t.Fatal("VRP withdrawn twice still held")
	}
}
