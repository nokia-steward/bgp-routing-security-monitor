package routetable

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// ownerIndexSize returns the number of routes in the owner index and fails
// the test if it holds an empty set or a route the table does not.
func ownerIndexSize(t *testing.T, tbl *Table) int {
	t.Helper()
	n := 0
	for i := range tbl.shards {
		s := &tbl.shards[i]
		for k, set := range s.owned {
			if len(set) == 0 {
				t.Errorf("owner index keeps an empty set for %+v", k)
			}
			for r := range set {
				if s.routes[r.Key()] != r {
					t.Errorf("owner index lists %s from %s, which the table no longer holds", r.Prefix, r.PeerAddr)
				}
				if k.session != r.OwnerSession || k.peer != r.Peer() {
					t.Errorf("route %s indexed under %+v, owned by session %d", r.Prefix, k, r.OwnerSession)
				}
			}
			n += len(set)
		}
	}
	return n
}

func ownedRoute(peer netip.Addr, i int, session uint64) *types.Route {
	return &types.Route{
		PeerAddr:     peer,
		Prefix:       netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 3, byte(i), 0}), 24),
		ASPath:       []uint32{64501, 65000 + uint32(i%7)},
		RIBType:      types.AdjRIBInPre,
		OwnerSession: session,
	}
}

// The owner index holds exactly the table's routes through overwrites,
// re-inserts of the same pointer (as RevalidateAll used to do), single withdrawals,
// detached withdraw-alls and stale eviction: an entry left behind would
// grow memory without bound on a long-running daemon.
func TestOwnerIndexTracksTableExactly(t *testing.T) {
	tbl := New()
	p := netip.MustParseAddr("192.0.2.1")
	q := netip.MustParseAddr("192.0.2.2")
	check := func(when string) {
		t.Helper()
		if got, want := ownerIndexSize(t, tbl), int(tbl.Count()); got != want {
			t.Errorf("%s: owner index holds %d routes, table %d", when, got, want)
		}
	}

	var restored []*types.Route
	for i := 0; i < 50; i++ {
		restored = append(restored, ownedRoute(q, i, 0))
	}
	tbl.Restore(restored)
	for i := 0; i < 100; i++ {
		tbl.Insert(ownedRoute(p, i, 1))
	}
	check("after inserts")

	for i := 0; i < 60; i++ {
		tbl.Insert(ownedRoute(p, i, 2)) // newer session takes over 0..59
	}
	check("after overwrites")

	for _, r := range tbl.GetByPeer(p) {
		r.SecurityPosture = types.PostureOriginInvalid
		tbl.Insert(r) // re-insert of the stored pointer, as RevalidateAll used to
	}
	check("after same-pointer re-inserts")

	tbl.WithdrawFromSession(types.RouteKey{Peer: types.PeerRef{Addr: p}, Prefix: ownedRoute(p, 70, 0).Prefix}, 1) // owned by 1: removed
	tbl.WithdrawFromSession(types.RouteKey{Peer: types.PeerRef{Addr: p}, Prefix: ownedRoute(p, 10, 0).Prefix}, 1) // owned by 2: kept
	check("after single withdrawals")

	rm := tbl.DetachSession(1)
	tbl.Insert(ownedRoute(p, 80, 2)) // re-announced while the removal is pending
	if got := rm.Apply(); got != 38 {
		t.Errorf("session 1's end removed %d routes, want 38 (60..99 less 70 and 80)", got)
	}
	if r := tbl.Get(types.RouteKey{Peer: types.PeerRef{Addr: p}, Prefix: ownedRoute(p, 80, 0).Prefix}); r == nil || r.OwnerSession != 2 {
		t.Errorf("route 80 = %+v, want session 2's re-announcement kept", r)
	}
	check("after session end")

	if got := tbl.WithdrawAllFromPeer(types.PeerRef{Addr: q}, 2, types.AdjRIBInPre); got != 50 {
		t.Errorf("peer-down of %s removed %d routes, want its 50 unowned ones", q, got)
	}
	tbl.Restore([]*types.Route{ownedRoute(q, 1, 0)})
	if got := tbl.EvictStale(); got != 1 {
		t.Errorf("EvictStale removed %d routes, want 1", got)
	}
	check("after peer down and eviction")
	if got := tbl.WithdrawAllFromPeer(types.PeerRef{Addr: p}, 2, types.AdjRIBInPre); got != 61 {
		t.Errorf("peer-down of %s removed %d routes, want 61", p, got)
	}
	check("when empty")
	for i := range tbl.shards {
		if n := len(tbl.shards[i].owned); n != 0 {
			t.Fatalf("shard %d keeps %d owner index entries for an empty table", i, n)
		}
	}
}

// buildBenchTable fills a table the shape of a production one: peers each
// carrying the same prefixes, many origin ASNs, and a realistic posture mix.
// The first owned routes belong to session 1, the rest to session 2.
func buildBenchTable(total, owned int) *Table {
	const peers = 10
	postures := []types.SecurityPosture{
		types.PostureUnverified, types.PostureUnverified, types.PostureUnverified,
		types.PostureUnverified, types.PostureUnverified, types.PostureOriginOnly,
		types.PostureOriginOnly, types.PostureOriginOnly, types.PostureOriginOnly,
		types.PostureOriginInvalid,
	}
	tbl := New()
	perPeer := total / peers
	n := 0
	for pi := 0; pi < peers; pi++ {
		peer := netip.AddrFrom4([4]byte{192, 0, 2, byte(pi + 1)})
		for i := 0; i < perPeer; i++ {
			session := uint64(2)
			if n < owned {
				session = 1
			}
			tbl.Insert(&types.Route{
				PeerAddr:        peer,
				Prefix:          netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0}), 24),
				ASPath:          []uint32{64501, 1 + uint32(i%70_000)},
				RIBType:         types.AdjRIBInPre,
				SecurityPosture: postures[i%len(postures)],
				OwnerSession:    session,
			})
			n++
		}
	}
	return tbl
}

// heapAlloc returns live heap bytes after a full collection.
func heapAlloc() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// BenchmarkSessionEndCleanup measures the end of a BMP session that owns
// owned of a table's total routes, as ingestLoop runs it: DetachSession
// inline, then Step(256) chunks (server.removalChunk).
// detach-ms and max-chunk-ms are how long ingest waits at worst; total-ms is
// the whole removal. The owned=10k case shows the cost does not depend on
// the size of the rest of the table. index-B/route is the owner index's
// share of the live heap.
//
//	go test -run '^$' -bench SessionEndCleanup -benchtime 3x ./internal/routetable/
func BenchmarkSessionEndCleanup(b *testing.B) {
	for _, tc := range []struct{ total, owned int }{
		{1_000_000, 1_000_000},
		{1_000_000, 10_000},
	} {
		b.Run(fmt.Sprintf("table=%d/owned=%d", tc.total, tc.owned), func(b *testing.B) {
			var detach, maxChunk, total time.Duration
			for it := 0; it < b.N; it++ {
				b.StopTimer()
				tbl := buildBenchTable(tc.total, tc.owned)
				if it == 0 {
					// Drop the owner index from one table to weigh it, then
					// time a fresh one.
					with := heapAlloc()
					for i := range tbl.shards {
						tbl.shards[i].owned = nil
					}
					without := heapAlloc()
					runtime.KeepAlive(tbl) // else the whole table is collected too
					b.ReportMetric(float64(int64(with)-int64(without))/float64(tc.total), "index-B/route")
					tbl = nil
					runtime.GC()
					tbl = buildBenchTable(tc.total, tc.owned)
				}
				b.StartTimer()

				start := time.Now()
				rm := tbl.DetachSession(1)
				detach += time.Since(start)
				removed := 0
				for {
					c := time.Now()
					n, done := rm.Step(256)
					maxChunk = max(maxChunk, time.Since(c))
					removed += n
					if done {
						break
					}
				}
				total += time.Since(start)
				if removed != tc.owned {
					b.Fatalf("removed %d routes, want %d", removed, tc.owned)
				}
			}
			ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
			b.ReportMetric(ms(detach)/float64(b.N), "detach-ms")
			b.ReportMetric(ms(maxChunk), "max-chunk-ms")
			b.ReportMetric(ms(total)/float64(b.N), "total-ms")
			b.ReportMetric(0, "ns/op") // dominated by setup; see total-ms
		})
	}
}
