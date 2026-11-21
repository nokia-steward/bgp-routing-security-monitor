package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store/storetest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// BenchmarkIngestDuringSessionEnd measures what a large session end costs
// ingest. A table holds owned routes of session A on one peer; ingestLoop is
// sent A's session end, then a burst of routes from session B, and the
// burst's ingest rate is compared with the same burst without the session
// end. With reannounce, B's burst re-announces A's first routes, as a router
// does after a takeover, and those are then skipped by the removal; without
// it, B's routes are on another peer and every one of A's must be removed.
//
// burst-µs/route is the burst's ingest cost; cleanup-ms is when A's
// remaining routes were all gone, measured from the start of the burst.
//
//	go test -run '^$' -bench IngestDuringSessionEnd -benchtime 3x ./internal/server/
func BenchmarkIngestDuringSessionEnd(b *testing.B) {
	const owned, burst = 1_000_000, 200_000
	peerA := netip.MustParseAddr("192.0.2.1")
	for _, reannounce := range []bool{false, true} {
		for _, withEnd := range []bool{false, true} {
			name := fmt.Sprintf("owned=%d/burst=%d/reannounce=%t/session_end=%t", owned, burst, reannounce, withEnd)
			b.Run(name, func(b *testing.B) {
				peerB := netip.MustParseAddr("192.0.2.2")
				if reannounce {
					peerB = peerA
				}
				want := uint64(owned + burst) // routes left once done
				switch {
				case withEnd:
					want = burst
				case reannounce:
					want = owned
				}
				var burstTime, cleanupTime time.Duration
				for it := 0; it < b.N; it++ {
					b.StopTimer()
					s, err := New(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
					if err != nil {
						b.Fatal(err)
					}
					fillSession(s, sessA, peerA, owned)
					close(s.rtrReady)
					ctx, cancel := context.WithCancel(context.Background())
					go s.ingestLoop(ctx)
					b.StartTimer()

					start := time.Now()
					if withEnd {
						sessionEnd(s, sessA)
					}
					for i := 0; i < burst; i++ {
						s.ingestCh <- types.IngestEvent{Route: benchRoute(peerB, i, 0), Session: sessB}
					}
					lastKey := types.RouteKey{Peer: types.PeerRef{Addr: peerB}, Prefix: benchRoute(peerB, burst-1, 0).Prefix}
					for r := s.table.Get(lastKey); r == nil || r.OwnerSession != sessB; r = s.table.Get(lastKey) {
						time.Sleep(100 * time.Microsecond)
					}
					burstTime += time.Since(start)
					for s.table.Count() != want {
						time.Sleep(100 * time.Microsecond)
					}
					cleanupTime += time.Since(start)

					b.StopTimer()
					cancel()
				}
				b.ReportMetric(float64(burstTime.Microseconds())/float64(b.N)/burst, "burst-µs/route")
				if withEnd {
					b.ReportMetric(float64(cleanupTime.Milliseconds())/float64(b.N), "cleanup-ms")
				}
				b.ReportMetric(0, "ns/op") // includes setup; see the metrics above
			})
		}
	}
}

var benchPostures = []types.SecurityPosture{
	types.PostureUnverified, types.PostureUnverified, types.PostureUnverified,
	types.PostureUnverified, types.PostureUnverified, types.PostureOriginOnly,
	types.PostureOriginOnly, types.PostureOriginOnly, types.PostureOriginOnly,
	types.PostureOriginInvalid,
}

// benchRoute is the i-th route of a production-shaped table: distinct /24s,
// about 70k origin ASNs, and a realistic posture mix.
func benchRoute(peer netip.Addr, i int, session uint64) *types.Route {
	return &types.Route{
		PeerAddr:        peer,
		Prefix:          netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0}), 24),
		ASPath:          []uint32{64501, 1 + uint32(i%70_000)},
		RIBType:         types.AdjRIBInPre,
		SecurityPosture: benchPostures[i%len(benchPostures)],
		OwnerSession:    session,
	}
}

func fillSession(s *Server, session uint64, peer netip.Addr, n int) {
	for i := 0; i < n; i++ {
		s.table.Insert(benchRoute(peer, i, session))
	}
}

// vrpsCovering covers every benchRoute prefix with VRPs for an AS no bench
// route originates, so each route is ROV-invalid; with no VRPs at all each
// is not-found. Switching between the two changes every route's posture.
var vrpsCovering = func() []types.VRP {
	var out []types.VRP
	for o := 1; o <= 255; o++ {
		out = append(out, types.VRP{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(o), 0, 0, 0}), 8), ASN: 64999, MaxLength: 24})
	}
	return out
}()

// newBenchServer returns a server validating on ingest, as in production,
// whose table holds n routes of session A validated against vrpsCovering.
func newBenchServer(b *testing.B, n int) *Server {
	b.Helper()
	s, err := New(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	s.cfg.Validation.ROV = true
	s.vrpStore.ReplaceAll(vrpsCovering, 1, 1)
	fillValidated(s, netip.MustParseAddr("192.0.2.1"), sessA, n)
	return s
}

// BenchmarkRevalidationPass measures one revalidation pass over a table of
// routes, run the way ingestLoop runs it, in revalidateChunk chunks, with no
// ingest competing. With change=false the stores are as they were when the
// routes were validated (an RTR update that touched none of them); with
// change=true every route's posture changes. pass-ms is the whole pass and
// max-chunk-ms the longest any ingest event could wait on it.
//
//	go test -run '^$' -bench RevalidationPass -benchtime 3x ./internal/server/
func BenchmarkRevalidationPass(b *testing.B) {
	const n = 1_000_000
	for _, change := range []bool{false, true} {
		b.Run(fmt.Sprintf("routes=%d/change=%t", n, change), func(b *testing.B) {
			var pass, maxChunk time.Duration
			for it := 0; it < b.N; it++ {
				b.StopTimer()
				s := newBenchServer(b, n)
				if change {
					s.vrpStore.ReplaceAll(nil, 2, 1)
				}
				b.StartTimer()

				start := time.Now()
				rv := s.engine.NewRevalidation()
				for {
					c := time.Now()
					done := rv.Step(revalidateChunk)
					maxChunk = max(maxChunk, time.Since(c))
					if done {
						break
					}
				}
				pass += time.Since(start)
				want := 0
				if change {
					want = n
				}
				if rv.Checked != n || rv.Changed != want {
					b.Fatalf("pass checked %d and changed %d routes, want %d and %d", rv.Checked, rv.Changed, n, want)
				}
			}
			b.ReportMetric(float64(pass.Microseconds())/1000/float64(b.N), "pass-ms")
			b.ReportMetric(float64(maxChunk.Microseconds())/1000, "max-chunk-ms")
			b.ReportMetric(0, "ns/op") // includes setup; see the metrics above
		})
	}
}

// BenchmarkIngestDuringRevalidation measures what a revalidation pass costs
// ingest: a burst of routes from session B on another peer is sent while a
// pass that changes every one of the table's routes runs, and its ingest
// rate is compared with the same burst and no pass. burst-µs/route is the
// burst's ingest cost; pass-ms is when the pass finished, from the start of
// the burst.
//
//	go test -run '^$' -bench IngestDuringRevalidation -benchtime 3x ./internal/server/
func BenchmarkIngestDuringRevalidation(b *testing.B) {
	const n, burst = 1_000_000, 200_000
	for _, revalidate := range []bool{false, true} {
		b.Run(fmt.Sprintf("routes=%d/burst=%d/revalidating=%t", n, burst, revalidate), func(b *testing.B) {
			var burstTime, passTime time.Duration
			for it := 0; it < b.N; it++ {
				b.StopTimer()
				s := newBenchServer(b, n)
				s.vrpStore.ReplaceAll(nil, 2, 1)
				close(s.rtrReady)
				ctx, cancel := context.WithCancel(context.Background())
				go s.ingestLoop(ctx)
				peerB := netip.MustParseAddr("192.0.2.2")
				b.StartTimer()

				start := time.Now()
				if revalidate {
					s.RequestRevalidation()
				}
				for i := 0; i < burst; i++ {
					s.ingestCh <- types.IngestEvent{Route: benchRoute(peerB, i, 0), Session: sessB}
				}
				lastKey := types.RouteKey{Peer: types.PeerRef{Addr: peerB}, Prefix: benchRoute(peerB, burst-1, 0).Prefix}
				for s.table.Get(lastKey) == nil {
					time.Sleep(100 * time.Microsecond)
				}
				burstTime += time.Since(start)
				for revalidate && s.revalidationPasses.Load() == 0 {
					time.Sleep(100 * time.Microsecond)
				}
				passTime += time.Since(start)

				b.StopTimer()
				cancel()
			}
			b.ReportMetric(float64(burstTime.Microseconds())/float64(b.N)/burst, "burst-µs/route")
			if revalidate {
				b.ReportMetric(float64(passTime.Milliseconds())/float64(b.N), "pass-ms")
			}
			b.ReportMetric(0, "ns/op") // includes setup; see the metrics above
		})
	}
}

// BenchmarkIngestRoute is the per-route BMP ingest path (ingestRoute:
// validate, insert, notify) against a warm store of 750k synthetic VRPs. The
// table fills to 1M routes, then announcements replace earlier ones.
//
//	go test -run '^$' -bench IngestRoute -benchmem ./internal/server/
func BenchmarkIngestRoute(b *testing.B) {
	sy := storetest.NewSynth(750_000, 1_000_000, 1)
	s, err := New(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	s.cfg.Validation.ROV = true
	s.vrpStore.ReplaceAll(sy.VRPs, 1, 1)
	peer := netip.MustParseAddr("192.0.2.1")
	routes := make([]types.Route, len(sy.Routes))
	for i, p := range sy.Routes {
		routes[i] = types.Route{PeerAddr: peer, PeerASN: 64501, Prefix: p,
			ASPath: []uint32{64501, sy.Origins[i]}, RIBType: types.AdjRIBInPre}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ingestRoute(routes[i%len(routes)], sessA, uint64(i))
	}
}
