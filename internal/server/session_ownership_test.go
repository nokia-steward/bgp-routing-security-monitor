package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// These tests replay what br1.nyc did in production: it gave up on RAVEN's
// BMP station, opened a new session while the old socket stayed open, and
// re-announced its table. When the stale session finally closed, its
// withdraw-all removed the routes the new session had just installed.

const (
	sessA uint64 = 1 // the stale session
	sessB uint64 = 2 // the router's replacement session
)

func startIngest(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t)
	close(s.rtrReady)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.ingestLoop(ctx)
	return s
}

func announce(s *Server, session uint64, peer netip.Addr, idx ...int) {
	for _, i := range idx {
		s.ingestCh <- types.IngestEvent{Route: testRoute(peer, i, types.PostureOriginOnly), Session: session}
	}
}

func peerDown(s *Server, session uint64, peer netip.Addr) {
	s.ingestCh <- types.IngestEvent{
		Withdrawal: &types.Withdrawal{PeerAddr: peer, WithdrawAll: true},
		Session:    session,
	}
}

func sessionEnd(s *Server, session uint64) {
	s.ingestCh <- types.IngestEvent{Withdrawal: &types.Withdrawal{SessionEnd: true}, Session: session}
}

// lookup returns the route testRoute(peer, i) in the table, or nil.
func lookup(s *Server, peer netip.Addr, i int) *types.Route {
	r := testRoute(peer, i, "")
	return s.table.Get(types.RouteKey{Peer: types.PeerRef{Addr: peer}, Prefix: r.Prefix, RIBType: r.RIBType})
}

func seq(from, to int) []int {
	var out []int
	for i := from; i < to; i++ {
		out = append(out, i)
	}
	return out
}

func TestStaleSessionEndKeepsRoutesReannouncedByNewSession(t *testing.T) {
	s := startIngest(t)
	peer := netip.MustParseAddr("192.0.2.1")
	const n = 30

	announce(s, sessA, peer, seq(0, n)...)
	drain(t, s)
	for i := 0; i < n; i++ {
		if r := lookup(s, peer, i); r == nil || r.OwnerSession != sessA {
			t.Fatalf("route %d = %+v after session A's announcement, want it owned by A", i, r)
		}
	}

	announce(s, sessB, peer, seq(0, n)...)
	sessionEnd(s, sessA)
	drain(t, s)

	if got := s.table.Count(); got != n {
		t.Errorf("table count = %d after the stale session ended, want %d", got, n)
	}
	for i := 0; i < n; i++ {
		r := lookup(s, peer, i)
		if r == nil {
			t.Errorf("route %d was removed by the stale session's withdraw-all", i)
			continue
		}
		if r.OwnerSession != sessB {
			t.Errorf("route %d owned by session %d, want %d", i, r.OwnerSession, sessB)
		}
	}
}

func TestSessionEndWithoutSuccessorRemovesItsRoutes(t *testing.T) {
	s := startIngest(t)
	p := netip.MustParseAddr("192.0.2.1")
	q := netip.MustParseAddr("192.0.2.2")
	other := netip.MustParseAddr("192.0.2.3") // a peer on another router's session
	const sessOther uint64 = 9

	announce(s, sessA, p, seq(0, 20)...)
	announce(s, sessA, q, seq(0, 5)...)
	announce(s, sessOther, other, seq(0, 3)...)
	drain(t, s)
	if got := s.table.Count(); got != 28 {
		t.Fatalf("table count = %d before session end, want 28", got)
	}

	sessionEnd(s, sessA)
	drain(t, s)

	if got := s.table.Count(); got != 3 {
		t.Errorf("table count = %d after session A ended, want 3 (the other session's routes)", got)
	}
	for _, peer := range []netip.Addr{p, q} {
		if got := s.table.GetByPeer(peer); len(got) != 0 {
			t.Errorf("%d routes from %s remain after its session ended, want 0", len(got), peer)
		}
	}
	if got := s.table.GetByPeer(other); len(got) != 3 {
		t.Errorf("%d routes from %s remain, want 3: another session's routes must not be touched", len(got), other)
	}
}

func TestPeerDownRemovesOnlyRoutesOwnedByItsSession(t *testing.T) {
	s := startIngest(t)
	p := netip.MustParseAddr("192.0.2.1")
	q := netip.MustParseAddr("192.0.2.2")

	// Session A installed 0..9 for P; session B has re-announced 0..4 so
	// far, and also carries peer Q.
	announce(s, sessA, p, seq(0, 10)...)
	announce(s, sessB, p, seq(0, 5)...)
	announce(s, sessB, q, seq(0, 4)...)
	drain(t, s)

	peerDown(s, sessB, p)
	drain(t, s)

	for i := 0; i < 5; i++ {
		if r := lookup(s, p, i); r != nil {
			t.Errorf("B-owned route %d for %s survived B's peer-down", i, p)
		}
	}
	for i := 5; i < 10; i++ {
		if r := lookup(s, p, i); r == nil || r.OwnerSession != sessA {
			t.Errorf("A-owned route %d for %s = %+v after B's peer-down, want it kept, owned by A", i, p, r)
		}
	}
	if got := s.table.GetByPeer(q); len(got) != 4 {
		t.Errorf("%d routes for %s after peer-down of %s, want 4", len(got), q, p)
	}

	// The A-owned leftovers go when A ends.
	sessionEnd(s, sessA)
	drain(t, s)
	if got := s.table.GetByPeer(p); len(got) != 0 {
		t.Errorf("%d routes for %s after A ended too, want 0", len(got), p)
	}
}

func TestStaleSessionEndRemovesOnlyRoutesNotReannounced(t *testing.T) {
	s := startIngest(t)
	peer := netip.MustParseAddr("192.0.2.1")
	const n = 20

	announce(s, sessA, peer, seq(0, n)...)
	var even []int
	for i := 0; i < n; i += 2 {
		even = append(even, i)
	}
	announce(s, sessB, peer, even...)
	sessionEnd(s, sessA)
	drain(t, s)

	for i := 0; i < n; i++ {
		r := lookup(s, peer, i)
		switch {
		case i%2 == 0 && (r == nil || r.OwnerSession != sessB):
			t.Errorf("re-announced route %d = %+v, want it kept, owned by B", i, r)
		case i%2 == 1 && r != nil:
			t.Errorf("route %d was never re-announced by B but survived A's end (owner %d)", i, r.OwnerSession)
		}
	}
	if got := s.table.Count(); got != n/2 {
		t.Errorf("table count = %d, want %d", got, n/2)
	}
}

// A single-prefix withdrawal still queued from the stale session must not
// remove the newer session's announcement of that prefix; the newer session
// may withdraw a route the stale one still owns.
func TestLateWithdrawalFromStaleSessionKeepsNewerRoute(t *testing.T) {
	s := startIngest(t)
	peer := netip.MustParseAddr("192.0.2.1")
	withdraw := func(session uint64, i int) {
		s.ingestCh <- types.IngestEvent{
			Withdrawal: &types.Withdrawal{PeerAddr: peer, Prefix: testRoute(peer, i, "").Prefix},
			Session:    session,
		}
	}

	announce(s, sessA, peer, 0, 1)
	announce(s, sessB, peer, 0)
	withdraw(sessA, 0)
	withdraw(sessB, 1)
	drain(t, s)

	if r := lookup(s, peer, 0); r == nil || r.OwnerSession != sessB {
		t.Errorf("route 0 = %+v after the stale session withdrew it, want B's route kept", r)
	}
	if r := lookup(s, peer, 1); r != nil {
		t.Errorf("route 1 = %+v after the newer session withdrew it, want it removed", r)
	}
}

// restore puts routes testRoute(peer, i) in the table as a snapshot restore
// does: stale, and owned by no session.
func restore(s *Server, peer netip.Addr, idx ...int) {
	var routes []*types.Route
	for _, i := range idx {
		routes = append(routes, testRoute(peer, i, types.PostureOriginOnly))
	}
	s.table.Restore(routes)
}

// The listener stops a superseded session from sending, but an event it had
// already handed over can still reach ingest behind the newer session's
// announcements. Applied, it would take the route back from the newer
// session, and the stale session's end would then remove it.
func TestLateEventFromSupersededSessionDoesNotReclaimRoute(t *testing.T) {
	s := startIngest(t)
	peer := netip.MustParseAddr("192.0.2.1")
	restore(s, peer, 9) // unowned; a late peer-down from A would remove it

	announce(s, sessA, peer, 0, 1)
	s.ingestCh <- types.IngestEvent{Session: sessA, Superseded: true}
	announce(s, sessB, peer, 0)
	announce(s, sessA, peer, 0) // late: was blocked in a send at takeover
	peerDown(s, sessA, peer)    // late as well
	sessionEnd(s, sessA)
	drain(t, s)

	if r := lookup(s, peer, 0); r == nil || r.OwnerSession != sessB {
		t.Errorf("route 0 = %+v, want it kept, owned by B: the late announcement must not reclaim it", r)
	}
	if r := lookup(s, peer, 1); r != nil {
		t.Errorf("route 1 = %+v, want it removed by A's session end", r)
	}
	if r := lookup(s, peer, 9); r == nil {
		t.Error("unowned route 9 was removed by a peer-down sent after A was superseded")
	}
	if n := len(s.retired); n != 0 {
		t.Errorf("%d superseded sessions still tracked after their session ends, want 0", n)
	}
}

func TestPeerDownAlsoRemovesUnownedRoutesOfThatPeer(t *testing.T) {
	s := startIngest(t)
	p := netip.MustParseAddr("192.0.2.1")
	q := netip.MustParseAddr("192.0.2.2")
	restore(s, p, seq(0, 10)...)
	restore(s, q, seq(0, 4)...)
	announce(s, sessB, p, seq(0, 3)...) // confirms 0..2; 3..9 stay unowned
	drain(t, s)

	peerDown(s, sessB, p)
	drain(t, s)

	if got := s.table.GetByPeer(p); len(got) != 0 {
		t.Errorf("%d routes for %s after its peer-down, want 0 (owned and unowned alike)", len(got), p)
	}
	if got := s.table.GetByPeer(q); len(got) != 4 {
		t.Errorf("%d unowned routes for %s after peer-down of %s, want 4", len(got), q, p)
	}
}

func TestSessionEndLeavesUnownedRoutes(t *testing.T) {
	s := startIngest(t)
	peer := netip.MustParseAddr("192.0.2.1")
	restore(s, peer, seq(0, 10)...)
	announce(s, sessB, peer, seq(0, 3)...)
	drain(t, s)

	sessionEnd(s, sessB)
	drain(t, s)

	for i := 0; i < 3; i++ {
		if r := lookup(s, peer, i); r != nil {
			t.Errorf("B-owned route %d survived B's session end", i)
		}
	}
	for i := 3; i < 10; i++ {
		if r := lookup(s, peer, i); r == nil || r.OwnerSession != 0 || !r.Stale {
			t.Errorf("unowned route %d = %+v after B's session end, want it kept for stale eviction", i, r)
		}
	}
}

// A large withdraw-all is removed a chunk at a time, not in one go, and
// waiting events go first: events that arrive while the removal is under way
// are all applied before the next chunk. As in
// TestRevalidationDoesNotHoldUpIngest, they are sent from inside the removal
// and its progress read as each is applied: order, not time.
func TestLargeSessionEndDoesNotHoldUpLaterEvents(t *testing.T) {
	s := newTestServer(t)
	p := netip.MustParseAddr("192.0.2.1")
	later := netip.MustParseAddr("192.0.2.2")
	const n = 400 * removalChunk
	for i := 0; i < n; i++ {
		// No origin or posture: keeps setup off those indexes.
		s.table.Insert(&types.Route{
			PeerAddr:     p,
			Prefix:       netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32),
			OwnerSession: sessA,
		})
	}
	const events = 3
	chunks := 0
	s.testAfterChunk = func() {
		if chunks++; chunks == 1 {
			announce(s, sessB, later, seq(0, events)...)
		}
	}
	removedAtEvent := make(chan int, events) // -1: no removal in progress
	s.testAfterEvent = func(ev types.IngestEvent) {
		if ev.Route != nil && ev.Route.PeerAddr == later {
			removed := -1
			if len(s.removals) > 0 {
				removed = s.removals[0].removed
			}
			removedAtEvent <- removed
		}
	}
	sessionEnd(s, sessA)
	startLoop(t, s)

	for i := 0; i < events; i++ {
		select {
		case removed := <-removedAtEvent:
			if removed < 0 || removed > removalChunk {
				t.Errorf("route %d of %d sent after the removal's first chunk was applied with %d of %d routes removed "+
					"(-1: removal already over), want all applied before the second %d-route chunk",
					i+1, events, removed, n, removalChunk)
			}
		case <-time.After(testWaitBound):
			t.Fatal("a route sent during the removal was never applied")
		}
	}
	drain(t, s)
	if got := s.table.Count(); got != events {
		t.Errorf("table count = %d after the removal finished, want %d", got, events)
	}
}
