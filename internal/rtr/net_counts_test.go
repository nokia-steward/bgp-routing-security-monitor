package rtr

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// scoreAfterWarmup scores sy with a detector warmed up on 200 ordinary
// incremental syncs of this cache: about added VRPs added and removed
// removed per sync (each within ±30%), at sy's interval and duration, and
// sy's totals. It returns the anomaly, if any.
func scoreAfterWarmup(sy telemetry.SessionEvent, added, removed int) *telemetry.AnomalyEvent {
	d := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	r := rand.New(rand.NewPCG(1, 2))
	jitter := func(n int) int { return n + r.IntN(n*6/10+1) - n*3/10 }
	at := sy.Timestamp.Add(-201 * time.Minute)
	for range 200 {
		a, w := jitter(added), jitter(removed)
		ev := telemetry.SessionEvent{
			Timestamp: at, Cache: sy.Cache, EventType: telemetry.EventSync, SyncType: telemetry.SyncTypeIncremental,
			VRPTotal: sy.VRPTotal, ASPATotal: sy.ASPATotal,
			VRPAnnounced: a, VRPWithdrawn: w, VRPAdded: a, VRPRemoved: w,
			IntervalSince: sy.IntervalSince, SyncDuration: sy.SyncDuration,
		}
		if a := d.ObserveSyncTotals(ev.Cache, ev.Timestamp, telemetry.SyncMetrics(ev), telemetry.TotalsOf(ev)); a != nil {
			panic("warm-up sync tripped: " + a.Trigger)
		}
		at = at.Add(time.Minute)
	}
	return d.ObserveSyncTotals(sy.Cache, sy.Timestamp, telemetry.SyncMetrics(sy), telemetry.TotalsOf(sy))
}

// A cache that announces a record it holds, without withdrawing it, sends a
// duplicate announcement (code 7). The PDU counts include it; the net change
// does not: vrp_added counts only the record that is new, and vrp_removed
// is the withdrawal of another record, unaffected. The self-healing full
// sync returns the same set, so its net change is 0.
func TestRepeatWithoutWithdrawNetCounts(t *testing.T) {
	h, _ := newHealHarness(t)
	s := rtrtest.GenVRPs(0, 10, 65001)
	h.srv.SetData(s, nil)
	h.start(t)
	h.synced(t)
	if sy := h.waitEvents(t, telemetry.EventSync, 1)[0]; sy.VRPAnnounced != 10 || sy.VRPAdded != 10 || sy.VRPRemoved != 0 {
		t.Fatalf("first full sync: announced %d added %d removed %d, want 10, 10, 0 (against an empty set)",
			sy.VRPAnnounced, sy.VRPAdded, sy.VRPRemoved)
	}
	fresh := rtrtest.GenVRPs(100, 1, 65002)[0]
	result := append(slices.Clone(s[:5]), s[6:]...)
	result = append(result, fresh)
	h.srv.AdvanceWire([]rtrtest.WirePDU{
		{Announce: true, VRP: s[0]}, // held: a duplicate, not withdrawn
		{Announce: true, VRP: fresh},
		{Announce: false, VRP: s[5]},
	}, result)
	h.srv.Notify()
	sy := h.waitEvents(t, telemetry.EventSync, 2)[1]
	if sy.VRPAnnounced != 2 || sy.VRPWithdrawn != 1 {
		t.Errorf("vrp_announced %d vrp_withdrawn %d, want 2 and 1 (the PDUs)", sy.VRPAnnounced, sy.VRPWithdrawn)
	}
	if sy.VRPAdded != 1 || sy.VRPRemoved != 1 {
		t.Errorf("vrp_added %d vrp_removed %d, want 1 and 1: the repeated record adds nothing", sy.VRPAdded, sy.VRPRemoved)
	}
	if dups := errorsOf(h, 7); len(dups) != 1 || dups[0].ErrorCount != 1 {
		t.Errorf("code 7 events %v, want one of count 1", dups)
	}
	waitResets(t, h, 2)
	if full := h.waitEvents(t, telemetry.EventSync, 3)[2]; full.SyncType != telemetry.SyncTypeFull ||
		full.VRPAnnounced != len(result) || full.VRPAdded != 0 || full.VRPRemoved != 0 {
		t.Errorf("resync: %s, announced %d added %d removed %d; want full, %d, 0, 0",
			full.SyncType, full.VRPAnnounced, full.VRPAdded, full.VRPRemoved, len(result))
	}
}

// A full sync's net change is against the cache's data before it: a
// Cache Reset that returns a changed set reports only the difference.
func TestFullSyncNetCountsAgainstPrevious(t *testing.T) {
	h, _ := newHealHarness(t)
	s := rtrtest.GenVRPs(0, 10, 65001)
	h.srv.SetData(s, []rtrtest.ASPASet{
		{Customer: 64500, Providers: []uint32{64501}},
		{Customer: 64510, Providers: []uint32{64511}},
	})
	h.start(t)
	h.synced(t)
	h.waitEvents(t, telemetry.EventSync, 1)

	// The cache's data changes and it resets the client: 3 VRPs gone, 2 new;
	// one customer gone, one new, one with a changed provider set.
	next := append(slices.Clone(s[3:]), rtrtest.GenVRPs(200, 2, 65003)...)
	h.srv.SetData(next, []rtrtest.ASPASet{
		{Customer: 64500, Providers: []uint32{64502}},
		{Customer: 64520, Providers: []uint32{64521}},
	})
	h.srv.Session().Send(rtrtest.CacheReset(2))
	sy := h.waitEvents(t, telemetry.EventSync, 2)[1]
	if sy.SyncType != telemetry.SyncTypeFull {
		t.Fatalf("sync after the Cache Reset is %s, want full", sy.SyncType)
	}
	if sy.VRPAnnounced != 9 || sy.VRPAdded != 2 || sy.VRPRemoved != 3 || sy.VRPTotal != 9 {
		t.Errorf("VRPs: announced %d added %d removed %d total %d, want 9, 2, 3, 9",
			sy.VRPAnnounced, sy.VRPAdded, sy.VRPRemoved, sy.VRPTotal)
	}
	if sy.ASPAAnnounced != 2 || sy.ASPAAdded != 1 || sy.ASPARemoved != 1 || sy.ASPATotal != 2 {
		t.Errorf("ASPA: announced %d added %d removed %d total %d, want 2, 1, 1, 2 (AS64500's new providers are neither)",
			sy.ASPAAnnounced, sy.ASPAAdded, sy.ASPARemoved, sy.ASPATotal)
	}
}
