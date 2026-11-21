package routetable

import (
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// revalidatedCopy is what revalidation hands Replace: a new object with the
// same identity and new validation results.
func revalidatedCopy(r *types.Route, p types.SecurityPosture) *types.Route {
	cp := *r
	cp.SecurityPosture = p
	return &cp
}

// A posture change applied through Replace leaves the key listed under the
// new posture only, every time, keeps the origin and owner indexes as they
// were, and leaves the route the table held before untouched for readers
// still holding it.
func TestReplacePostureChangeIsIndexedOnce(t *testing.T) {
	tbl := New()
	r := ownedRoute(netip.MustParseAddr("192.0.2.1"), 1, 3)
	r.SecurityPosture = types.PostureSecured
	tbl.Insert(r)
	key := types.RouteKey{Peer: types.PeerRef{Addr: r.PeerAddr}, Prefix: r.Prefix, RIBType: r.RIBType}

	cur := r
	flips := []types.SecurityPosture{
		types.PosturePathSuspect, types.PostureSecured, types.PostureOriginInvalid,
		types.PostureSecured, types.PosturePathSuspect,
	}
	for i, p := range flips {
		prev, prevPosture := cur, cur.SecurityPosture
		cur = revalidatedCopy(cur, p)
		if !tbl.Replace(prev, cur) {
			t.Fatalf("flip %d: Replace refused the route the table holds", i+1)
		}
		if got := postureListings(tbl, key); len(got) != 1 || got[0] != p {
			t.Fatalf("after flip %d to %s: key listed under %v, want only [%s]", i+1, p, got, p)
		}
		if got := asnListings(tbl, key); len(got) != 1 || got[0] != r.OriginASN() {
			t.Fatalf("after flip %d: key listed under origins %v, want only [%d]", i+1, got, r.OriginASN())
		}
		if prev.SecurityPosture != prevPosture {
			t.Fatalf("flip %d changed the replaced route in place: %s, want %s", i+1, prev.SecurityPosture, prevPosture)
		}
		if tbl.Get(key) != cur {
			t.Fatalf("flip %d: table does not hold the new route", i+1)
		}
		if got := ownerIndexSize(t, tbl); got != 1 {
			t.Fatalf("flip %d: owner index holds %d routes, want 1", i+1, got)
		}
	}

	tbl.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: key.Peer.Addr}, Prefix: key.Prefix})
	if got := postureListings(tbl, key); len(got) != 0 {
		t.Errorf("after withdrawal: key still listed under postures %v", got)
	}
	if n := len(tbl.postureIdx); n != 0 {
		t.Errorf("posture index keeps %d entries for an empty table", n)
	}
	if got := ownerIndexSize(t, tbl); got != 0 {
		t.Errorf("owner index holds %d routes for an empty table", got)
	}
}

// Replace applies only to the very route the table still holds and still
// indexes. A route withdrawn, re-announced, or detached by a pending
// withdraw-all since revalidation read it is left alone.
func TestReplaceSkipsRoutesNoLongerCurrent(t *testing.T) {
	tbl := New()
	p := netip.MustParseAddr("192.0.2.1")

	withdrawn := ownedRoute(p, 1, 1)
	tbl.Insert(withdrawn)
	tbl.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: p}, Prefix: withdrawn.Prefix})
	if tbl.Replace(withdrawn, revalidatedCopy(withdrawn, types.PostureOriginInvalid)) {
		t.Error("Replace brought a withdrawn route back")
	}

	old := ownedRoute(p, 2, 1)
	tbl.Insert(old)
	newer := ownedRoute(p, 2, 2) // a newer session's announcement
	tbl.Insert(newer)
	if tbl.Replace(old, revalidatedCopy(old, types.PostureOriginInvalid)) {
		t.Error("Replace swapped a stale route over a newer announcement")
	}
	if got := tbl.Get(types.RouteKey{Peer: types.PeerRef{Addr: p}, Prefix: newer.Prefix}); got != newer {
		t.Errorf("table holds %+v, want the newer announcement", got)
	}

	detached := ownedRoute(p, 3, 1)
	tbl.Insert(detached)
	rm := tbl.DetachSession(1)
	if tbl.Replace(detached, revalidatedCopy(detached, types.PostureOriginInvalid)) {
		t.Error("Replace swapped a route a pending session end had detached")
	}
	if got := rm.Apply(); got != 1 {
		t.Errorf("session end removed %d routes, want 1: the detached route must still go", got)
	}

	if got, want := ownerIndexSize(t, tbl), int(tbl.Count()); got != want || want != 1 {
		t.Errorf("owner index holds %d routes, table %d; want 1 and 1 (the newer route)", got, want)
	}
	if got := tbl.CountByPosture()[types.PostureOriginInvalid]; got != 0 {
		t.Errorf("%d routes indexed under a posture only refused replacements had", got)
	}
}

// A Scan returns every route exactly once, a bounded batch at a time.
func TestScanVisitsEveryRouteOnce(t *testing.T) {
	tbl := New()
	const n = 5000
	for i := 0; i < n; i++ {
		r := ownedRoute(netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 7)}), i, 1)
		r.Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		tbl.Insert(r)
	}
	seen := make(map[*types.Route]bool, n)
	sc := tbl.NewScan()
	for {
		batch := sc.Next(100)
		if len(batch) > 100 {
			t.Fatalf("Next(100) returned %d routes", len(batch))
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			if seen[r] {
				t.Fatalf("route %s from %s returned twice", r.Prefix, r.PeerAddr)
			}
			seen[r] = true
		}
	}
	if len(seen) != n {
		t.Errorf("scan returned %d routes, want %d", len(seen), n)
	}
}

// Stale eviction runs apart from ingest. A restored route that a live BMP
// message confirms between eviction's scan and its removal must stay.
func TestEvictStaleKeepsRouteConfirmedAfterScan(t *testing.T) {
	tbl := New()
	p := netip.MustParseAddr("192.0.2.1")
	tbl.Restore([]*types.Route{ownedRoute(p, 1, 0), ownedRoute(p, 2, 0)})

	keys := tbl.staleKeys()
	confirmed := ownedRoute(p, 1, 5) // live announcement, Stale false
	tbl.Insert(confirmed)
	if got := tbl.evictStale(keys); got != 1 {
		t.Errorf("evicted %d routes, want 1 (the unconfirmed one)", got)
	}
	if got := tbl.Get(types.RouteKey{Peer: types.PeerRef{Addr: p}, Prefix: confirmed.Prefix}); got != confirmed {
		t.Errorf("confirmed route = %+v after eviction, want it kept", got)
	}
	if got, want := ownerIndexSize(t, tbl), int(tbl.Count()); got != want || want != 1 {
		t.Errorf("owner index holds %d routes, table %d; want 1 and 1", got, want)
	}
}
