package rtr

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Each sync that changes the data hands onUpdate a Delta: Full when the
// stores were rebuilt (Reset Query, Cache Reset, a new session ID), and
// otherwise exactly the VRPs announced and withdrawn and the ASPA customers
// whose provider set changed.
func TestSyncDeltas(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	deltas := make(chan *store.Delta, 16)
	tc.SetOnUpdate(func(d *store.Delta) { deltas <- d })
	tc.start(t)
	next := func(what string) *store.Delta {
		t.Helper()
		select {
		case d := <-deltas:
			return d
		case <-time.After(5 * time.Second):
			t.Fatalf("no delta for %s", what)
			return nil
		}
	}
	serialQuery := func(conn *rtrtest.Conn, serial uint32) {
		t.Helper()
		conn.Send(rtrtest.SerialNotify(2, 7, serial))
		if q := cache.Next(5 * time.Second); q.Type != rtrtest.PDUSerialQuery {
			t.Fatalf("query type %d after Serial Notify, want a Serial Query", q.Type)
		}
	}

	conn, _ := fullSync(t, cache, 2, 1, 600, 600, 7200)
	if d := next("the first sync"); !d.Full {
		t.Fatalf("first sync (Reset Query) delta = %+v, want Full", d)
	}

	added := netip.MustParsePrefix("198.51.100.0/24")
	serialQuery(conn, 2)
	conn.Send(rtrtest.CacheResponse(2, 7),
		rtrtest.IPv4Prefix(2, true, added, 24, 65001),
		rtrtest.IPv4Prefix(2, false, testPrefix, 24, 65000),
		rtrtest.ASPA(true, 64500, 64501, 64502),
		rtrtest.EndOfData(2, 7, 2, 600, 600, 7200))
	d := next("the incremental sync")
	wantAdd := []types.VRP{{Prefix: added, MaxLength: 24, ASN: 65001}}
	wantDel := []types.VRP{{Prefix: testPrefix, MaxLength: 24, ASN: 65000}}
	if d.Full || !slices.Equal(d.VRPAnnounced, wantAdd) || !slices.Equal(d.VRPWithdrawn, wantDel) ||
		!slices.Equal(d.ASPACustomers, []uint32{64500}) {
		t.Fatalf("incremental delta = %+v, want announced %v, withdrawn %v, ASPA [64500]", d, wantAdd, wantDel)
	}

	// Re-announcing the record as it is changes nothing.
	serialQuery(conn, 3)
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.ASPA(true, 64500, 64501, 64502),
		rtrtest.EndOfData(2, 7, 3, 600, 600, 7200))
	if d := next("the no-op ASPA sync"); !d.Empty() {
		t.Fatalf("delta for an unchanged ASPA record = %+v, want empty", d)
	}

	// An announcement replaces the customer's provider set (8210bis
	// §5.12): fewer providers is a change to it. (Before #66 the client
	// added them to the set, so this changed nothing.)
	serialQuery(conn, 4)
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.ASPA(true, 64500, 64501),
		rtrtest.EndOfData(2, 7, 4, 600, 600, 7200))
	if d := next("the ASPA replacement"); d.Full || !slices.Equal(d.ASPACustomers, []uint32{64500}) {
		t.Fatalf("delta for a replaced ASPA record = %+v, want ASPA [64500]", d)
	}

	// A different session ID: the stores no longer match what the delta
	// would describe.
	serialQuery(conn, 5)
	conn.Send(rtrtest.CacheResponse(2, 8), rtrtest.IPv4Prefix(2, true, testPrefix, 24, 65000),
		rtrtest.EndOfData(2, 8, 5, 600, 600, 7200))
	if d := next("the session-ID change"); !d.Full {
		t.Fatalf("delta after a session-ID change = %+v, want Full", d)
	}

	// Cache Reset: the client re-syncs from scratch.
	serialQuery(conn, 6)
	conn.Send(rtrtest.CacheReset(2))
	if q := cache.Next(5 * time.Second); q.Type != rtrtest.PDUResetQuery {
		t.Fatalf("query type %d after Cache Reset, want a Reset Query", q.Type)
	}
	conn.Send(rtrtest.CacheResponse(2, 8), rtrtest.IPv4Prefix(2, true, testPrefix, 24, 65000),
		rtrtest.EndOfData(2, 8, 6, 600, 600, 7200))
	if d := next("the Cache Reset sync"); !d.Full {
		t.Fatalf("delta after Cache Reset = %+v, want Full", d)
	}
}

func TestDeltaMerge(t *testing.T) {
	v := func(p string, asn uint32) types.VRP {
		return types.VRP{Prefix: netip.MustParsePrefix(p), MaxLength: 24, ASN: asn}
	}
	d := &store.Delta{VRPAnnounced: []types.VRP{v("192.0.2.0/24", 1)}, ASPACustomers: []uint32{5, 9}}
	d.Merge(&store.Delta{VRPWithdrawn: []types.VRP{v("198.51.100.0/24", 2)}, ASPACustomers: []uint32{3, 9}})
	if d.Full || len(d.VRPAnnounced) != 1 || len(d.VRPWithdrawn) != 1 || !slices.Equal(d.ASPACustomers, []uint32{3, 5, 9}) {
		t.Fatalf("merged delta = %+v", d)
	}
	if got := d.VRPPrefixes(); len(got) != 2 {
		t.Fatalf("VRPPrefixes = %v, want 2 distinct prefixes", got)
	}
	d.Merge(store.FullDelta())
	if !d.Full || len(d.VRPAnnounced) != 0 || len(d.ASPACustomers) != 0 {
		t.Fatalf("merging a Full delta gave %+v, want Full with no detail", d)
	}
	d.Merge(&store.Delta{ASPACustomers: []uint32{1}})
	if !d.Full || len(d.ASPACustomers) != 0 {
		t.Fatalf("merging into a Full delta gave %+v, want it to stay Full", d)
	}
}

// waitCount waits until the client has applied a sync's PDUs to the store.
func waitCount(t *testing.T, s *store.VRPStore, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.Count() != want {
		if time.Now().After(deadline) {
			t.Fatalf("store holds %d VRPs, want %d", s.Count(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// Changes apply at End of Data: while a sync's PDUs are arriving, lookups see
// the previous set whole, for an incremental sync and for a full one (built
// aside: the store's counts do not dip either). The delta is handed to onUpdate only once
// the new set is what lookups see.
func TestLookupsSeePreviousSetUntilEndOfData(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	vrps := tc.vrpStore
	a := netip.MustParsePrefix("198.51.100.0/24")
	b := netip.MustParsePrefix("203.0.113.0/24")
	seenAtUpdate := make(chan []types.VRP, 4)
	prefixPDUs := make(chan struct{}, 16)
	tc.pduHook = func(typ uint8) {
		if typ == PDUIPv4Prefix {
			prefixPDUs <- struct{}{}
		}
	}
	tc.SetOnUpdate(func(*store.Delta) { seenAtUpdate <- vrps.FindCovering(b) })
	tc.start(t)
	has := func(p netip.Prefix) bool { return len(vrps.FindCovering(p)) > 0 }

	conn, _ := fullSync(t, cache, 2, 1, 600, 600, 7200) // testPrefix
	<-seenAtUpdate
	if !has(testPrefix) {
		t.Fatal("first sync not published")
	}

	conn.Send(rtrtest.SerialNotify(2, 7, 2))
	cache.Next(5 * time.Second)
	conn.Send(rtrtest.CacheResponse(2, 7),
		rtrtest.IPv4Prefix(2, false, testPrefix, 24, 65000),
		rtrtest.IPv4Prefix(2, true, a, 24, 65001),
		rtrtest.IPv4Prefix(2, true, b, 24, 65002))
	waitCount(t, vrps, 2)
	if !has(testPrefix) || has(a) || has(b) {
		t.Fatalf("mid-sync lookups see testPrefix=%v a=%v b=%v, want the previous set (true false false)",
			has(testPrefix), has(a), has(b))
	}
	conn.Send(rtrtest.EndOfData(2, 7, 2, 600, 600, 7200))
	if got := <-seenAtUpdate; len(got) != 1 || got[0].ASN != 65002 {
		t.Fatalf("at onUpdate FindCovering(b) = %v: the delta was handed off before its set was published", got)
	}
	if has(testPrefix) || !has(a) {
		t.Fatal("after End of Data lookups do not see the sync")
	}

	// A full sync: Cache Reset, Reset Query, then a Cache Response and the
	// snapshot, built aside until its End of Data.
	for len(prefixPDUs) > 0 {
		<-prefixPDUs
	}
	conn.Send(rtrtest.SerialNotify(2, 7, 3))
	cache.Next(5 * time.Second)
	conn.Send(rtrtest.CacheReset(2))
	cache.Next(5 * time.Second)
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.IPv4Prefix(2, true, testPrefix, 24, 65000))
	select {
	case <-prefixPDUs:
	case <-time.After(5 * time.Second):
		t.Fatal("the full sync's prefix PDU was not applied")
	}
	if vrps.Count() != 2 {
		t.Errorf("mid-full-sync the store counts %d VRPs, want the previous 2", vrps.Count())
	}
	if !has(a) || !has(b) || has(testPrefix) {
		t.Fatalf("mid-full-sync lookups see a=%v b=%v testPrefix=%v, want the previous set (true true false)",
			has(a), has(b), has(testPrefix))
	}
	conn.Send(rtrtest.EndOfData(2, 7, 3, 600, 600, 7200))
	<-seenAtUpdate
	if has(a) || has(b) || !has(testPrefix) {
		t.Fatal("after the full sync's End of Data lookups do not see its snapshot")
	}
}

// A sync withdrawing 10,000 VRPs rebuilds the index once, at End of Data.
func TestLargeWithdrawalRebuildsOnce(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	updates := make(chan struct{}, 4)
	tc.SetOnUpdate(func(*store.Delta) { updates <- struct{}{} })
	tc.start(t)
	const n = 10_000
	prefix := func(i int) netip.Prefix {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
	}
	q := cache.Next(5 * time.Second)
	pdus := [][]byte{rtrtest.CacheResponse(2, 7)}
	for i := 0; i < n; i++ {
		pdus = append(pdus, rtrtest.IPv4Prefix(2, true, prefix(i), 24, 65000))
	}
	q.Conn.Send(append(pdus, rtrtest.EndOfData(2, 7, 1, 600, 600, 7200))...)
	<-updates
	if got := tc.vrpStore.Count(); got != n {
		t.Fatalf("store holds %d VRPs after the full sync, want %d", got, n)
	}

	before := tc.vrpStore.Rebuilds()
	q.Conn.Send(rtrtest.SerialNotify(2, 7, 2))
	cache.Next(5 * time.Second)
	pdus = [][]byte{rtrtest.CacheResponse(2, 7)}
	for i := 0; i < n; i++ {
		pdus = append(pdus, rtrtest.IPv4Prefix(2, false, prefix(i), 24, 65000))
	}
	q.Conn.Send(append(pdus, rtrtest.EndOfData(2, 7, 2, 600, 600, 7200))...)
	<-updates
	if got := tc.vrpStore.Rebuilds() - before; got != 1 {
		t.Errorf("withdrawing %d VRPs rebuilt the index %d times, want 1", n, got)
	}
	if got := tc.vrpStore.Count(); got != 0 {
		t.Errorf("store holds %d VRPs after withdrawing all, want 0", got)
	}
	if got := tc.vrpStore.FindCovering(prefix(42)); got != nil {
		t.Errorf("FindCovering after withdrawing all = %v, want none", got)
	}
}
