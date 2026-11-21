package server

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// fillValidated puts n routes from peer, owned by session, in the table,
// validated against the current stores as ingest would.
func fillValidated(s *Server, peer netip.Addr, session uint64, n int) {
	for i := 0; i < n; i++ {
		r := benchRoute(peer, i, session)
		s.engine.ValidateRoute(r)
		s.table.Insert(r)
	}
}

var (
	vrpsMatching = []types.VRP{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), ASN: 64501, MaxLength: 32}}
	vrpsOther    = []types.VRP{{Prefix: netip.MustParsePrefix("0.0.0.0/0"), ASN: 64999, MaxLength: 32}}
)

// RTR updates arriving during a pass are coalesced: the request channel holds
// one at most, and however many arrive while a pass runs, one follow-up pass
// runs after it (needed: the routes already checked saw the old data).
func TestRTRUpdatesDuringRevalidationCoalesce(t *testing.T) {
	t.Run("request channel", func(t *testing.T) {
		// No ingest loop running: a request must only be queued for it.
		// RTR updates used to revalidate on the RTR goroutine, as a second
		// writer of the table.
		s := newTestServer(t)
		s.vrpStore.ReplaceAll(vrpsMatching, 1, 1)
		peer := netip.MustParseAddr("192.0.2.1")
		fillValidated(s, peer, sessA, 100)
		before := lookup2(s, peer, 0)
		s.vrpStore.ReplaceAll(vrpsOther, 2, 1)
		for range 5 {
			s.RequestRevalidation() // never blocks
		}
		if n := len(s.revalidateCh); n != 1 {
			t.Errorf("%d revalidation requests queued, want 1", n)
		}
		if after := lookup2(s, peer, 0); after != before {
			t.Error("RequestRevalidation changed the table itself; only ingestLoop may write it")
		}
	})

	t.Run("state machine", func(t *testing.T) {
		s := newTestServer(t)
		fillValidated(s, netip.MustParseAddr("192.0.2.1"), sessA, 2000)
		// An RTR update as ingestLoop sees it: a request, then its signal.
		update := func() {
			s.RequestRevalidation()
			<-s.revalidateCh
			s.startRevalidation()
		}
		update()
		s.stepBackground()
		update() // two RTR updates during the pass
		update()
		for s.revalidating.Load() {
			s.stepBackground()
		}
		if got := s.revalidationPasses.Load(); got != 2 {
			t.Errorf("%d passes ran, want 2: the first and one follow-up", got)
		}
	})

	t.Run("ingest loop", func(t *testing.T) {
		s := newTestServer(t)
		fillValidated(s, netip.MustParseAddr("192.0.2.1"), sessA, 50_000)
		// Two RTR updates arrive after the first pass's first chunk, so
		// certainly during it: the pass has about 200 chunks.
		chunks := 0
		s.testAfterChunk = func() {
			if chunks++; chunks == 1 {
				s.RequestRevalidation()
				s.RequestRevalidation()
			}
		}
		s.RequestRevalidation()
		startLoop(t, s)
		// A follow-up starts inline as a pass ends, so once none is in
		// progress the count is final.
		waitUntil(t, "the passes to finish", func() bool {
			return s.revalidationPasses.Load() >= 2 && !s.revalidating.Load()
		})
		drain(t, s)
		if got := s.revalidationPasses.Load(); got != 2 {
			t.Errorf("%d passes ran, want 2: the first and one follow-up", got)
		}
	})
}

// A revalidation pass runs a chunk at a time between ingest events, and
// waiting events go first: events that arrive during the pass are all
// applied before the pass goes on. They are sent from inside the pass, after
// its first chunk, and the pass's progress is read as each is applied, so the
// check is about order, not time.
func TestRevalidationDoesNotHoldUpIngest(t *testing.T) {
	s := newTestServer(t)
	s.vrpStore.ReplaceAll(vrpsMatching, 1, 1)
	const n = 400 * revalidateChunk
	fillValidated(s, netip.MustParseAddr("192.0.2.1"), sessA, n)
	s.vrpStore.ReplaceAll(vrpsOther, 2, 1)

	later := netip.MustParseAddr("192.0.2.2")
	const events = 3
	chunks := 0
	s.testAfterChunk = func() {
		if chunks++; chunks == 1 {
			announce(s, sessB, later, seq(0, events)...)
		}
	}
	checkedAtEvent := make(chan int, events) // -1: no pass in progress
	s.testAfterEvent = func(ev types.IngestEvent) {
		if ev.Route != nil && ev.Route.PeerAddr == later {
			checked := -1
			if s.revalidation != nil {
				checked = s.revalidation.Checked
			}
			checkedAtEvent <- checked
		}
	}
	s.RequestRevalidation()
	startLoop(t, s)

	for i := 0; i < events; i++ {
		select {
		case checked := <-checkedAtEvent:
			if checked < 0 || checked > revalidateChunk {
				t.Errorf("route %d of %d sent after the pass's first chunk was applied with %d of %d routes checked "+
					"(-1: pass already over), want all applied before the second %d-route chunk",
					i+1, events, checked, n, revalidateChunk)
			}
		case <-time.After(testWaitBound):
			t.Fatal("a route sent during the pass was never applied")
		}
	}
	drain(t, s)
	if got := s.revalidationPasses.Load(); got != 1 {
		t.Errorf("%d passes ran, want 1", got)
	}
}

// startLoop starts ingestLoop with RTR ready; it stops when the test ends.
// Set any test hooks before calling it.
func startLoop(t *testing.T, s *Server) {
	t.Helper()
	close(s.rtrReady)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.ingestLoop(ctx)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWaitBound)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		runtime.Gosched()
	}
}

// Concurrent ingest and RTR updates, under -race: BMP announcements,
// withdrawals and peer-downs stream in while RTR updates flip the VRPs and
// request revalidation, and readers read routes throughout. Readers never
// see a route whose posture disagrees with its own ROV and ASPA results, and
// afterwards the table holds exactly what ingest left, validated against the
// final VRPs, with every index consistent.
func TestConcurrentIngestAndRTRUpdates(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Validation.ROV = true // validate on ingest, as in production
	s.vrpStore.ReplaceAll(vrpsMatching, 1, 1)
	close(s.rtrReady)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.ingestLoop(ctx)

	const peers, prefixes, ops = 4, 300, 30_000
	peer := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}) }
	session := func(i int) uint64 { return uint64(10 + i) }
	type mkey struct{ peer, idx int }
	model := map[mkey]bool{}

	var rtrWG, readWG sync.WaitGroup
	stopRTR, stopReaders := make(chan struct{}), make(chan struct{})

	rtrWG.Add(1)
	go func() { // RTR updates
		defer rtrWG.Done()
		for serial := uint32(2); ; serial++ {
			select {
			case <-stopRTR:
				return
			default:
			}
			if serial%2 == 0 {
				s.vrpStore.ReplaceAll(vrpsOther, serial, 1)
			} else {
				s.vrpStore.ReplaceAll(vrpsMatching, serial, 1)
			}
			s.RequestRevalidation()
			time.Sleep(time.Millisecond)
		}
	}()

	var torn int
	readWG.Add(1)
	go func() { // API / metrics readers
		defer readWG.Done()
		for {
			select {
			case <-stopReaders:
				return
			default:
			}
			for _, r := range s.table.All() {
				if r.SecurityPosture != types.ComputePosture(r.ROV.State, r.ASPA.State) {
					torn++
				}
			}
			s.table.CountByPosture()
		}
	}()

	rng := rand.New(rand.NewPCG(1, 2))
	for range ops { // BMP ingest, applied in this order
		p, i := rng.IntN(peers), rng.IntN(prefixes)
		switch n := rng.IntN(100); {
		case n < 60:
			s.ingestCh <- types.IngestEvent{Route: benchRoute(peer(p), i, 0), Session: session(p)}
			model[mkey{p, i}] = true
		case n < 99:
			s.ingestCh <- types.IngestEvent{
				Withdrawal: &types.Withdrawal{PeerAddr: peer(p), Prefix: benchRoute(peer(p), i, 0).Prefix},
				Session:    session(p),
			}
			delete(model, mkey{p, i})
		default:
			peerDown(s, session(p), peer(p))
			for k := range model {
				if k.peer == p {
					delete(model, k)
				}
			}
		}
	}
	// Updates every millisecond keep a follow-up pass queued, so stop them
	// before waiting for ingest to go idle; readers keep reading meanwhile.
	close(stopRTR)
	rtrWG.Wait()
	drain(t, s)
	close(stopReaders)
	readWG.Wait()
	if torn != 0 {
		t.Errorf("readers saw %d routes with a posture that disagrees with their own ROV/ASPA results", torn)
	}

	// A last update, then everything must match it.
	s.vrpStore.ReplaceAll(vrpsOther, 1_000_000, 1)
	passes := s.revalidationPasses.Load()
	s.RequestRevalidation()
	waitUntil(t, "a pass after the last update", func() bool {
		return s.revalidationPasses.Load() > passes && !s.revalidating.Load()
	})
	drain(t, s)

	if got := int(s.table.Count()); got != len(model) {
		t.Errorf("table holds %d routes, ingest left %d", got, len(model))
	}
	for k := range model {
		r := lookup2(s, peer(k.peer), k.idx)
		if r == nil {
			t.Errorf("route %d of peer %d is missing", k.idx, k.peer)
			continue
		}
		if r.OwnerSession != session(k.peer) {
			t.Errorf("route %d of peer %d owned by session %d, want %d", k.idx, k.peer, r.OwnerSession, session(k.peer))
		}
		if _, changed := s.engine.Revalidated(r); changed {
			t.Errorf("route %d of peer %d not validated against the final VRPs (posture %s)", k.idx, k.peer, r.SecurityPosture)
		}
	}
	var indexed uint64
	for p, n := range s.table.CountByPosture() {
		indexed += n
		for _, r := range s.table.GetByPosture(p) {
			if r.SecurityPosture != p {
				t.Errorf("posture index lists a %s route under %s", r.SecurityPosture, p)
			}
		}
	}
	if indexed != s.table.Count() {
		t.Errorf("posture index lists %d routes, table holds %d", indexed, s.table.Count())
	}
	for p := 0; p < peers; p++ {
		want := 0
		for k := range model {
			if k.peer == p {
				want++
			}
		}
		if got := s.table.WithdrawSession(session(p)); got != want {
			t.Errorf("session %d's owner index held %d routes, want %d", session(p), got, want)
		}
	}
}

// lookup2 returns benchRoute(peer, i)'s route in the table, or nil.
func lookup2(s *Server, peer netip.Addr, i int) *types.Route {
	r := benchRoute(peer, i, 0)
	return s.table.Get(types.RouteKey{Peer: types.PeerRef{Addr: peer}, Prefix: r.Prefix, RIBType: r.RIBType})
}

// Stale eviction is applied by ingestLoop like a withdraw-all, not by the
// eviction timer's goroutine: it removes the restored routes no live session
// has confirmed and keeps those that one has.
func TestStaleEvictionGoesThroughIngestLoop(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.1")

	t.Run("request only", func(t *testing.T) {
		s := newTestServer(t)
		restore(s, peer, seq(0, 5)...)
		for range 3 {
			s.RequestStaleEviction() // never blocks
		}
		if n := len(s.evictCh); n != 1 {
			t.Errorf("%d eviction requests queued, want 1", n)
		}
		if got := s.table.Count(); got != 5 {
			t.Errorf("table holds %d routes after a request with no ingest loop, want 5 untouched", got)
		}
	})

	t.Run("ingest loop", func(t *testing.T) {
		s := startIngest(t)
		restore(s, peer, seq(0, 10)...)
		announce(s, sessB, peer, seq(0, 4)...) // live confirmations
		drain(t, s)
		s.RequestStaleEviction()
		waitUntil(t, "eviction", func() bool { return s.table.Count() == 4 })
		drain(t, s)
		for i := 0; i < 10; i++ {
			r := lookup(s, peer, i)
			switch {
			case i < 4 && (r == nil || r.OwnerSession != sessB || r.Stale):
				t.Errorf("confirmed route %d = %+v after eviction, want session B's", i, r)
			case i >= 4 && r != nil:
				t.Errorf("unconfirmed route %d survived eviction", i)
			}
		}
		if got := s.table.WithdrawSession(sessB); got != 4 {
			t.Errorf("session B's owner index held %d routes, want 4", got)
		}
	})
}
