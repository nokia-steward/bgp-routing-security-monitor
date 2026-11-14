package rtr

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// aspaContents is an ASPA store's records, sorted, for comparison.
func aspaContents(s *store.ASPAStore) []types.ASPARecord {
	recs := s.Snapshot()
	slices.SortFunc(recs, func(a, b types.ASPARecord) int { return cmp.Compare(a.CustomerASN, b.CustomerASN) })
	return recs
}

// fullSyncASPA is what a full sync of srv returns now: a fresh client's ASPA
// store after its first sync (a Reset Query), in a session of its own.
func fullSyncASPA(t *testing.T, srv *rtrtest.Server) []types.ASPARecord {
	t.Helper()
	aspas := store.NewASPAStore()
	c, err := NewClient(srv.Addr(), "tcp", nil, store.NewVRPStore(), aspas, 2, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	c.unit = time.Millisecond
	synced := make(chan struct{}, 1)
	c.SetOnSync(func() {
		select {
		case synced <- struct{}{}:
		default:
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Start(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		t.Fatal("reference full sync did not complete")
	}
	return aspaContents(aspas)
}

// ASPA drift: across a run of deltas that withdraw customers with no
// provider list (8210bis §5.12: a 12-byte PDU, as Routinator sends it) and
// re-announce customers with changed provider sets, the client's ASPA total
// and contents after each End of Data equal what a full sync of the same
// cache returns. Before #66 a withdrawal without providers removed nothing
// and a re-announcement added to the provider set, so the records drifted.
// An announcement then a withdrawal of the same customer in one delta is no
// fault: the record goes, with no error and no resync.
func TestASPADriftMatchesFullSync(t *testing.T) {
	if n := len(rtrtest.ASPA(false, 64510)); n != 12 {
		t.Fatalf("an ASPA withdrawal PDU is %d bytes, want 12 (header and customer AS, no providers)", n)
	}
	h, _ := newHealHarness(t)
	h.srv.SetData(rtrtest.GenVRPs(0, 3, 65001), []rtrtest.ASPASet{
		{Customer: 64500, Providers: []uint32{64501, 64502}},
		{Customer: 64510, Providers: []uint32{64511}},
		{Customer: 64520, Providers: []uint32{64521, 64522, 64523}},
		{Customer: 64530, Providers: []uint32{64531}},
	})
	h.start(t)
	h.synced(t)
	h.waitEvents(t, telemetry.EventSync, 1)
	session := h.srv.Session() // the client's; reference syncs open others
	check := func(step string) {
		t.Helper()
		got, want := aspaContents(h.aspaStore), fullSyncASPA(t, h.srv)
		if !slices.EqualFunc(got, want, func(a, b types.ASPARecord) bool {
			return a.CustomerASN == b.CustomerASN && slices.Equal(a.ProviderASNs, b.ProviderASNs)
		}) || h.aspaStore.Count() != len(want) {
			t.Errorf("%s: client holds %d ASPA records %v, a full sync returns %d %v",
				step, h.aspaStore.Count(), fmt.Sprint(got), len(want), fmt.Sprint(want))
		}
		if _, cached := h.srv.Counts(); cached != len(want) {
			t.Errorf("%s: the cache holds %d customers, its full sync %d", step, cached, len(want))
		}
	}
	check("initial full sync")
	prevVRPs, prevASPAs := h.vrpStore.OwnerCount(h.owner), aspaContents(h.aspaStore)

	for i, d := range []rtrtest.Delta{
		// The Routinator case: one customer withdrawn, no providers.
		{WithdrawASPAs: []uint32{64510}},
		{AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64502, 64503}}}},
		{AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64520, Providers: []uint32{64521}}, {Customer: 64540, Providers: []uint32{64541}}},
			WithdrawASPAs: []uint32{64530}},
		// Re-announced, then withdrawn, in one delta: removed.
		{AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64509}}, {Customer: 64540, Providers: []uint32{64541, 64542}}},
			WithdrawASPAs: []uint32{64500}},
		{AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64510, Providers: []uint32{64519}}}, WithdrawASPAs: []uint32{64520}},
	} {
		serial := h.srv.Advance(d)
		session.Send(rtrtest.SerialNotify(2, 7, serial))
		if sy := h.waitEvents(t, telemetry.EventSync, i+2)[i+1]; sy.Serial != serial || sy.SyncType != telemetry.SyncTypeIncremental {
			t.Fatalf("delta %d: sync %+v, want incremental at serial %d", i+1, sy, serial)
		}
		check(fmt.Sprintf("after delta %d", i+1))
		// The net change agrees with the data: the customers that came and
		// went, and for VRPs the total's change. A provider-set
		// replacement is neither added nor removed.
		sy := h.eventsOf(telemetry.EventSync)[i+1]
		nowASPAs := aspaContents(h.aspaStore)
		came, went := customerDiff(prevASPAs, nowASPAs)
		if sy.ASPAAdded != came || sy.ASPARemoved != went {
			t.Errorf("delta %d: aspa_added %d aspa_removed %d, want %d and %d (customers that came and went)",
				i+1, sy.ASPAAdded, sy.ASPARemoved, came, went)
		}
		if got := int(h.vrpStore.OwnerCount(h.owner)) - int(prevVRPs); sy.VRPAdded-sy.VRPRemoved != got {
			t.Errorf("delta %d: vrp_added - vrp_removed = %d, the VRP total changed by %d", i+1, sy.VRPAdded-sy.VRPRemoved, got)
		}
		prevVRPs, prevASPAs = h.vrpStore.OwnerCount(h.owner), nowASPAs
	}
	if h.aspaStore.HasRecord(64500) {
		t.Error("AS64500, announced then withdrawn in one delta, still has a record")
	}
	if n := len(h.eventsOf(telemetry.EventError)); n != 0 {
		t.Errorf("%d error events, want none: every PDU followed the protocol; events: %s", n, h.summary())
	}
	main := 0
	for _, q := range h.srv.Received() {
		if q.Type == rtrtest.PDUResetQuery && q.Conn == session {
			main++
		}
	}
	if main != 1 {
		t.Errorf("%d Reset Queries on the client's session, want 1 (no self-healing resync)", main)
	}
}

// customerDiff counts the customer ASes in now and not before, and in before
// and not now.
func customerDiff(before, now []types.ASPARecord) (came, went int) {
	has := func(recs []types.ASPARecord, c uint32) bool {
		return slices.ContainsFunc(recs, func(r types.ASPARecord) bool { return r.CustomerASN == c })
	}
	for _, r := range now {
		if !has(before, r.CustomerASN) {
			came++
		}
	}
	for _, r := range before {
		if !has(now, r.CustomerASN) {
			went++
		}
	}
	return came, went
}
