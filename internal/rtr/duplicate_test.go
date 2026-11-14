package rtr

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// fakeClock is a settable clock for the self-healing resync's rate limit.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newHealHarness is newHarness at version 2 with a fake clock for healResync.
func newHealHarness(t *testing.T) (*harness, *fakeClock) { return newHealHarnessAt(t, 2) }

// newHealHarnessAt is newHealHarness with client and cache at version.
func newHealHarnessAt(t *testing.T, version uint8) (*harness, *fakeClock) {
	h := newHarness(t, cacheAt(version), version, false)
	clk := &fakeClock{t: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	h.now = clk.now
	return h, clk
}

// resets counts the Reset Queries the cache has received.
func resets(h *harness) int {
	n := 0
	for _, q := range h.srv.Received() {
		if q.Type == rtrtest.PDUResetQuery {
			n++
		}
	}
	return n
}

// waitResets waits until the cache has received n Reset Queries.
func waitResets(t *testing.T, h *harness, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for resets(h) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d Reset Queries within 5s, want %d; events: %s", resets(h), n, h.summary())
		}
		time.Sleep(time.Millisecond)
	}
}

// heldSet is the VRP store's set, sorted, for comparing with what the cache
// holds.
func heldSet(h *harness) []types.VRP {
	got := h.vrpStore.All()
	slices.SortFunc(got, cmpVRP)
	return got
}

func vrpSet(vs ...[]rtrtest.VRP) []types.VRP {
	var out []types.VRP
	seen := map[types.VRP]bool{}
	for _, l := range vs {
		for _, v := range l {
			if x := toVRP(v); !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	slices.SortFunc(out, cmpVRP)
	return out
}

func cmpVRP(a, b types.VRP) int {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c
	}
	if a.Prefix.Bits() != b.Prefix.Bits() {
		return a.Prefix.Bits() - b.Prefix.Bits()
	}
	if a.ASN != b.ASN {
		return int(int64(a.ASN) - int64(b.ASN))
	}
	return int(a.MaxLength) - int(b.MaxLength)
}

// errorsOf returns the error events with code, in order.
func errorsOf(h *harness, code uint16) []telemetry.SessionEvent {
	var out []telemetry.SessionEvent
	for _, e := range h.eventsOf(telemetry.EventError) {
		if e.ErrorCode != nil && *e.ErrorCode == code {
			out = append(out, e)
		}
	}
	return out
}

func checkClientError(t *testing.T, e telemetry.SessionEvent, code uint16, count int, first string) {
	t.Helper()
	if e.ErrorOrigin != telemetry.ErrorOriginClient || e.ErrorCount != count || !strings.Contains(e.ErrorText, first) {
		t.Errorf("code %d error event %+v, want origin client, count %d, naming %s", code, e, count, first)
	}
}

// The Fort 1.7.0 pattern (NICMx/FORT-validator#204): the client holds S; a
// delta announces 2276 VRPs, 2255 of them already held and 21 new, and
// withdraws 2263, the 2255 re-announced and 8 others. The cache meant +21
// -8. With a count per VRP the store holds S + 21 - 8 at End of Data, not S
// - 2255 (as when the duplicate announcements were ignored and the
// withdrawals applied). The 2255 duplicates are one code 7 error event with
// error_count 2255 and count 2255 in raven_rtr_protocol_errors_total; a
// Reset Query follows on the same session, and its full sync leaves the
// same set.
func TestFortReannounceThenWithdraw(t *testing.T) {
	h, _ := newHealHarness(t)
	s := rtrtest.GenVRPs(0, 3000, 65001)
	h.srv.SetData(s, nil)
	before := rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.srv.Addr())
	h.start(t)
	h.synced(t)
	h.waitEvents(t, telemetry.EventSync, 1)

	added, gone, again := rtrtest.GenVRPs(10000, 21, 65002), s[2255:2263], s[:2255]
	h.srv.Advance(rtrtest.Delta{AnnounceVRPs: added, WithdrawVRPs: gone, Reannounce: again})
	h.srv.Notify()
	syncs := h.waitEvents(t, telemetry.EventSync, 2)
	want := vrpSet(s[:2255], s[2263:], added)
	if got := heldSet(h); !slices.Equal(got, want) {
		t.Fatalf("after the delta the store holds %d VRPs, want %d (S + 21 - 8)", len(got), len(want))
	}
	if sy := syncs[1]; sy.VRPAnnounced != 2276 || sy.VRPWithdrawn != 2263 || sy.VRPTotal != 3013 {
		t.Errorf("delta sync announced %d withdrawn %d total %d, want 2276, 2263, 3013", sy.VRPAnnounced, sy.VRPWithdrawn, sy.VRPTotal)
	}
	dups := errorsOf(h, 7)
	if len(dups) != 1 || len(errorsOf(h, 6)) != 0 {
		t.Fatalf("%d code 7 and %d code 6 error events, want 1 and 0; events: %s", len(dups), len(errorsOf(h, 6)), h.summary())
	}
	checkClientError(t, dups[0], 7, 2255, s[0].Prefix.String())
	if got := rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.srv.Addr()) - before; got != 2255 {
		t.Errorf("raven_rtr_protocol_errors_total rose by %v, want 2255", got)
	}

	// The self-healing resync: a Reset Query on the same session.
	waitResets(t, h, 2)
	syncs = h.waitEvents(t, telemetry.EventSync, 3)
	if syncs[2].SyncType != telemetry.SyncTypeFull {
		t.Errorf("sync after the resync is %s, want full", syncs[2].SyncType)
	}
	if got := heldSet(h); !slices.Equal(got, want) {
		t.Errorf("after the resync the store holds %d VRPs, want the same %d", len(got), len(want))
	}
	if n := len(h.eventsOf(telemetry.EventDisconnected, telemetry.EventConnected)); n != 1 {
		t.Errorf("%d connected/disconnected events, want the one connect: the resync is on the same session; events: %s", n, h.summary())
	}
}

// A withdrawal of a VRP, or of an ASPA customer, the cache does not hold is
// code 6: one error event per sync with the count, the stores unchanged,
// and a self-healing resync.
func TestWithdrawalOfUnknownRecord(t *testing.T) {
	h, _ := newHealHarness(t)
	s := rtrtest.GenVRPs(0, 5, 65001)
	h.srv.SetData(s, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501}}})
	h.start(t)
	h.synced(t)
	h.waitEvents(t, telemetry.EventSync, 1)

	unknown := rtrtest.GenVRPs(500, 1, 65009)
	h.srv.Advance(rtrtest.Delta{WithdrawVRPs: unknown, WithdrawASPAs: []uint32{64999}})
	h.srv.Notify()
	h.waitEvents(t, telemetry.EventSync, 2)
	if got := heldSet(h); !slices.Equal(got, vrpSet(s)) || !h.aspaStore.HasRecord(64500) || h.aspaStore.Count() != 1 {
		t.Errorf("stores changed by unknown withdrawals: %d VRPs, %d ASPA", len(got), h.aspaStore.Count())
	}
	unk := errorsOf(h, 6)
	if len(unk) != 1 || len(errorsOf(h, 7)) != 0 {
		t.Fatalf("%d code 6 and %d code 7 error events, want 1 and 0; events: %s", len(unk), len(errorsOf(h, 7)), h.summary())
	}
	checkClientError(t, unk[0], 6, 2, unknown[0].Prefix.String())
	waitResets(t, h, 2)
	h.waitEvents(t, telemetry.EventSync, 3)
	if got := heldSet(h); !slices.Equal(got, vrpSet(s)) {
		t.Errorf("after the resync the store holds %d VRPs, want %d", len(got), len(s))
	}
}

// A duplicate within a full sync counts once in the set (vrp_total) but is
// still a code 7 fault. A cache whose every answer is faulty is resynced at
// most once per 5 minutes: the resync's own faulty full sync does not set
// off another, and neither does a faulty delta within the 5 minutes; one
// after them does.
func TestSelfHealingResyncRateLimit(t *testing.T) {
	h, clk := newHealHarness(t)
	s := rtrtest.GenVRPs(0, 3, 65001)
	h.srv.SetData(s, nil)
	h.srv.RepeatInReset(s[:1], nil) // every full sync announces s[0] twice
	h.start(t)
	h.synced(t)
	if sy := h.waitEvents(t, telemetry.EventSync, 1)[0]; sy.VRPTotal != 3 || sy.VRPAnnounced != 4 {
		t.Errorf("full sync vrp_total %d vrp_announced %d, want 3 and 4", sy.VRPTotal, sy.VRPAnnounced)
	}
	waitResets(t, h, 2) // the first fault: resync
	h.waitEvents(t, telemetry.EventSync, 2)
	if n := len(errorsOf(h, 7)); n != 2 {
		t.Fatalf("%d code 7 events after the resync's full sync, want 2", n)
	}

	clk.advance(4 * time.Minute)
	h.srv.Advance(rtrtest.Delta{Reannounce: s[1:2]})
	h.srv.Notify()
	h.waitEvents(t, telemetry.EventSync, 3)
	h.srv.NoQuery(100*time.Millisecond, "a third Reset Query within 5 minutes of the resync")
	if r := resets(h); r != 2 {
		t.Fatalf("%d Reset Queries within the 5 minutes, want 2", r)
	}

	clk.advance(2 * time.Minute)
	h.srv.Advance(rtrtest.Delta{Reannounce: s[2:3]})
	h.srv.Notify()
	h.waitEvents(t, telemetry.EventSync, 4)
	waitResets(t, h, 3)
	if got := heldSet(h); !slices.Equal(got, vrpSet(s)) {
		t.Errorf("store holds %v, want %v", got, vrpSet(s))
	}
}

// A cache that follows the protocol raises no error and gets no resync.
func TestCorrectCacheNoFaults(t *testing.T) {
	h, _ := newHealHarness(t)
	s := rtrtest.GenVRPs(0, 20, 65001)
	h.srv.SetData(s, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501}}})
	before := rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.srv.Addr())
	h.start(t)
	h.synced(t)
	h.waitEvents(t, telemetry.EventSync, 1)
	for i, d := range []rtrtest.Delta{
		{AnnounceVRPs: rtrtest.GenVRPs(100, 5, 65002), WithdrawVRPs: s[:3]},
		{WithdrawVRPs: rtrtest.GenVRPs(100, 2, 65002), AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64502}}}},
		{WithdrawASPAs: []uint32{64500}},
	} {
		h.srv.Advance(d)
		h.srv.Notify()
		h.waitEvents(t, telemetry.EventSync, i+2)
	}
	h.srv.NoQuery(100*time.Millisecond, "a Reset Query from a client of a correct cache")
	if n, r := len(h.eventsOf(telemetry.EventError)), resets(h); n != 0 || r != 1 {
		t.Errorf("%d error events and %d Reset Queries, want 0 and 1; events: %s", n, r, h.summary())
	}
	if got := rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.srv.Addr()) - before; got != 0 {
		t.Errorf("raven_rtr_protocol_errors_total rose by %v, want 0", got)
	}
	if got := heldSet(h); !slices.Equal(got, vrpSet(s[3:], rtrtest.GenVRPs(102, 3, 65002))) {
		t.Errorf("store holds %d VRPs, want %d", len(got), 20-3+3)
	}
	// The net change is the PDUs received: every announcement added a
	// record, every withdrawal removed one. The one exception is delta 2's
	// ASPA announcement, which replaces AS64500's provider set (8210bis
	// §5.12): an announcement PDU, no record added.
	for i, sy := range h.eventsOf(telemetry.EventSync) {
		wantASPAAdded := sy.ASPAAnnounced
		if i == 2 {
			wantASPAAdded = 0
		}
		if sy.VRPAdded != sy.VRPAnnounced || sy.VRPRemoved != sy.VRPWithdrawn ||
			sy.ASPAAdded != wantASPAAdded || sy.ASPARemoved != sy.ASPAWithdrawn {
			t.Errorf("sync %d: VRPs announced/added %d/%d withdrawn/removed %d/%d, ASPA %d/%d %d/%d; want added %d",
				i, sy.VRPAnnounced, sy.VRPAdded, sy.VRPWithdrawn, sy.VRPRemoved,
				sy.ASPAAnnounced, sy.ASPAAdded, sy.ASPAWithdrawn, sy.ASPARemoved, wantASPAAdded)
		}
	}
}

// An ASPA announcement for a customer AS the cache already announced is not
// a duplicate: draft-ietf-sidrops-8210bis §5.12 makes it a replacement of
// the customer's provider set. It counts once, raises no error, and the
// providers it leaves out are gone (before #66 the client added the
// providers to the set, so they stayed). A withdrawal, with no provider
// list, removes the whole record (before, it removed only the providers
// listed: none).
func TestASPAReannouncementReplaces(t *testing.T) {
	h := newHarness(t, v2Cache(), 2, false)
	h.srv.SetData(nil, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501, 64502}}})
	h.srv.RepeatInReset(nil, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501}}})
	h.start(t)
	h.synced(t)

	providers := func() []uint32 {
		r := h.aspaStore.GetRecord(64500)
		if r == nil {
			return nil
		}
		var out []uint32
		for p := range r.Providers {
			out = append(out, p)
		}
		slices.Sort(out)
		return out
	}
	if got := providers(); !slices.Equal(got, []uint32{64501}) {
		t.Errorf("after a full sync announcing AS64500 twice, providers %v, want [64501] (the second replaces the first)", got)
	}
	if s := h.waitEvents(t, telemetry.EventSync, 1)[0]; s.ASPATotal != 1 {
		t.Errorf("aspa_total %d, want 1", s.ASPATotal)
	}

	h.srv.Advance(rtrtest.Delta{AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64503}}}})
	h.srv.Notify()
	h.synced(t)
	h.waitEvents(t, telemetry.EventSync, 2)
	if got := providers(); !slices.Equal(got, []uint32{64503}) {
		t.Errorf("after an incremental re-announcement, providers %v, want [64503]", got)
	}

	h.srv.Advance(rtrtest.Delta{WithdrawASPAs: []uint32{64500}})
	h.srv.Notify()
	h.synced(t)
	h.waitEvents(t, telemetry.EventSync, 3)
	if h.aspaStore.HasRecord(64500) || h.aspaStore.Count() != 0 {
		t.Errorf("after the withdrawal AS64500 still has a record: %v", providers())
	}
	if n := len(h.eventsOf(telemetry.EventError)); n != 0 {
		t.Errorf("%d error events, want none; events: %s", n, h.summary())
	}
}

// Two caches' clients share serve's stores. The same VRP from both is not a
// duplicate, counts once in the store and once in each cache's
// raven_rtr_vrp_count; one cache withdrawing it leaves it active for the
// other, and one cache's full sync does not drop the other's VRPs. (Before,
// the store counted the VRP from both twice, and a full sync cleared the
// whole store, the other cache's VRPs included, until that cache synced
// in full itself.)
func TestSharedStoreTwoCaches(t *testing.T) {
	a := newHarness(t, v2Cache(), 2, false)
	shared := rtrtest.GenVRPs(0, 2, 65001)
	onlyB := rtrtest.GenVRPs(100, 1, 65002)
	a.srv.SetData(shared, nil)
	bsrv := rtrtest.NewServer(t, v2Cache())
	bsrv.SetData(append(slices.Clone(shared), onlyB...), nil)
	b, err := NewClient(bsrv.Addr(), "tcp", nil, a.vrpStore, a.aspaStore, 2, a.log)
	if err != nil {
		t.Fatal(err)
	}
	b.unit = time.Millisecond
	bsynced := make(chan struct{}, 1)
	b.SetOnSync(func() {
		select {
		case bsynced <- struct{}{}:
		default:
		}
	})
	a.start(t)
	a.synced(t)
	bh := &harness{Client: b}
	bh.start(t)
	select {
	case <-bsynced:
	case <-time.After(5 * time.Second):
		t.Fatal("cache B did not sync")
	}

	if got := a.vrpStore.Count(); got != 3 {
		t.Errorf("shared store holds %d VRPs, want 3 distinct", got)
	}
	if ga, gb := rtrtest.Gauge("raven_rtr_vrp_count", a.srv.Addr()), rtrtest.Gauge("raven_rtr_vrp_count", bsrv.Addr()); ga != 2 || gb != 3 {
		t.Errorf("raven_rtr_vrp_count A %v B %v, want 2 and 3", ga, gb)
	}
	if n := len(a.eventsOf(telemetry.EventError)); n != 0 {
		t.Errorf("cache A recorded %d errors: the same VRP from another cache is not a duplicate", n)
	}

	// A withdraws shared[0]: B still has it.
	a.srv.Advance(rtrtest.Delta{WithdrawVRPs: shared[:1]})
	a.srv.Notify()
	a.synced(t)
	a.waitEvents(t, telemetry.EventSync, 2)
	if !slices.Contains(a.vrpStore.All(), toVRP(shared[0])) {
		t.Errorf("after A withdrew %v, it left the store; B still has it", shared[0])
	}
	if ga := rtrtest.Gauge("raven_rtr_vrp_count", a.srv.Addr()); ga != 1 {
		t.Errorf("raven_rtr_vrp_count A %v, want 1", ga)
	}
	// A's Cache Reset makes it sync in full: B's VRPs stay.
	a.srv.Session().Send(rtrtest.CacheReset(2))
	a.synced(t)
	if s := a.waitEvents(t, telemetry.EventSync, 3)[2]; s.SyncType != telemetry.SyncTypeFull {
		t.Fatalf("A's sync after Cache Reset is %s, want full", s.SyncType)
	}
	if got := a.vrpStore.All(); !slices.Contains(got, toVRP(onlyB[0])) || !slices.Contains(got, toVRP(shared[1])) {
		t.Errorf("after A's full sync the store holds %v, want B's VRPs still", got)
	}
}

func toVRP(v rtrtest.VRP) types.VRP {
	return types.VRP{Prefix: v.Prefix, MaxLength: v.MaxLen, ASN: v.ASN}
}
