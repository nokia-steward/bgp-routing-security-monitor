package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// clockRun is rtr monitor (its client, recorder, detector and data tracker,
// as RunE wires them through handleRTREvent) against fake caches, on a
// synthetic clock: each sync record the clients emit is stamped with the
// clock before the monitor takes it in, so a day of syncs takes
// milliseconds. The sets, and so the fingerprints, are the clients' own.
type clockRun struct {
	t        *testing.T
	ndjson   *lockedBuffer
	rec      *telemetry.Recorder
	detector *telemetry.Detector
	cmp      *telemetry.CrossCache
	syncs    map[string]chan telemetry.SessionEvent
	now      time.Time
	quiet    *slog.Logger
}

// runClocked starts a monitor of srvs (several: compared) with
// --stale-threshold threshold (0 learns), and takes in each one's first
// sync at the clock's start.
func runClocked(t *testing.T, threshold time.Duration, srvs ...*rtrtest.Server) *clockRun {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := &clockRun{t: t, ndjson: &lockedBuffer{}, syncs: map[string]chan telemetry.SessionEvent{}, quiet: quiet,
		now: time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC), detector: telemetry.NewDetector(telemetry.DefaultAnomalyConfig())}
	r.rec = telemetry.NewRecorder(r.ndjson, 1024, quiet)
	var caches []string
	for _, s := range srvs {
		caches = append(caches, s.Addr())
		r.syncs[s.Addr()] = make(chan telemetry.SessionEvent, 1024)
	}
	set, err := newMonitorSet(caches, "tcp", "auto", 10*time.Minute, r.rec, quiet)
	if err != nil {
		t.Fatal(err)
	}
	r.cmp = set.cmp
	for _, c := range set.clients {
		c.SetReconnectBackoff(10*time.Millisecond, 10*time.Millisecond)
	}
	configureDataTracker(r.detector.Data(), threshold, set.cmp)
	go func() {
		for ev := range r.rec.Events() {
			switch ev.EventType {
			case telemetry.EventSync, telemetry.EventConnected, telemetry.EventDisconnected:
				r.syncs[ev.Cache] <- ev
			}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := set.start(ctx)
	t.Cleanup(func() {
		cancel()
		<-done
		r.rec.Close()
	})
	for _, s := range srvs {
		r.take(s, 0)
	}
	return r
}

// take waits for srv's next sync record, stamps it with the clock moved on
// by d, and hands it to the monitor, with the monitor's ticks in between.
// A disconnected record before it is taken in at the start of d, a
// connected one at its end: a reconnect is an outage lasting d.
func (r *clockRun) take(srv *rtrtest.Server, d time.Duration) telemetry.SessionEvent {
	r.t.Helper()
	var later []telemetry.SessionEvent
	for {
		select {
		case ev := <-r.syncs[srv.Addr()]:
			switch ev.EventType {
			case telemetry.EventDisconnected:
				ev.Timestamp = r.now
				handleRTREvent(r.rec, r.detector, r.cmp, ev, r.quiet)
				continue
			case telemetry.EventConnected:
				later = append(later, ev)
				continue
			}
			end := r.now.Add(d)
			for at := r.now.Add(dataTickEvery); at.Before(end); at = at.Add(dataTickEvery) {
				tickData(r.rec, r.detector.Data(), at, r.quiet)
			}
			r.now = end
			for _, c := range later {
				c.Timestamp = r.now
				handleRTREvent(r.rec, r.detector, r.cmp, c, r.quiet)
			}
			ev.Timestamp = r.now
			handleRTREvent(r.rec, r.detector, r.cmp, ev, r.quiet)
			return ev
		case <-time.After(5 * time.Second):
			r.t.Fatalf("%s: no sync within 5s; NDJSON:\n%s", srv.Addr(), r.ndjson)
			return telemetry.SessionEvent{}
		}
	}
}

// advance applies delta at srv (an empty one: a new serial, the same data),
// and takes in the sync, d after the last.
func (r *clockRun) advance(srv *rtrtest.Server, d time.Duration, delta rtrtest.Delta) telemetry.SessionEvent {
	r.t.Helper()
	srv.Advance(delta)
	srv.Notify()
	return r.take(srv, d)
}

// reconnect switches srv to another node's data at serial, drops the
// session, and takes in the full sync of the reconnect, d after the last.
func (r *clockRun) reconnect(srv *rtrtest.Server, d time.Duration, vrps []rtrtest.VRP, serial uint32) telemetry.SessionEvent {
	r.t.Helper()
	srv.SwitchNode(vrps, nil, serial)
	srv.Session().Close()
	ev := r.take(srv, d)
	if ev.SyncType != telemetry.SyncTypeFull || ev.Serial != serial {
		r.t.Fatalf("reconnect: %s sync at serial %d, want a full sync at %d", ev.SyncType, ev.Serial, serial)
	}
	return ev
}

// data returns the stale, stale_resolved and data_regressed records written,
// in order.
func (r *clockRun) data() []map[string]any {
	r.t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(r.ndjson.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			r.t.Fatalf("NDJSON %q: %v", line, err)
		}
		switch rec["event_type"] {
		case "stale", "stale_resolved", "data_regressed":
			out = append(out, rec)
		}
	}
	return out
}

// anomalies returns the triggers of the structural anomaly records.
func (r *clockRun) anomalies() []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(r.ndjson.String()), "\n") {
		var rec map[string]any
		_ = json.Unmarshal([]byte(line), &rec)
		if rec["event_type"] == "anomaly" && rec["category"] == "structural" {
			out = append(out, rec["trigger"].(string))
		}
	}
	return out
}

func recordTypes(recs []map[string]any) []string {
	var out []string
	for _, r := range recs {
		out = append(out, r["event_type"].(string))
	}
	return out
}

func durNS(v any) time.Duration { return time.Duration(v.(float64)) }

// gaps are the 5 Oct-shaped gaps between changes: 10 to 20 minutes.
var changeGaps = []time.Duration{10 * time.Minute, 12 * time.Minute, 14 * time.Minute, 16 * time.Minute, 18 * time.Minute, 20 * time.Minute}

// changeEvery makes n changes at srv, one VRP each from first, at gaps.
func (r *clockRun) changeEvery(srv *rtrtest.Server, first, n int) {
	for i := range n {
		r.advance(srv, changeGaps[i%len(changeGaps)], rtrtest.Delta{AnnounceVRPs: rtrtest.GenVRPs(first+i, 1, 65001)})
	}
}

// 5 Oct 2026, Routinator on AS38016: data changing every 10-20 minutes,
// then 90 minutes of syncs, every 10, with a new serial each time and no
// change. The threshold learned is 1h (4 x 15m median = 3 x 20m p90): stale
// at the first tick past it, 60m15s in (not at the 70-minute sync), once;
// resolved by the next change.
func TestStaleRoutinatorShaped(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(2))
	srv.SetData(rtrtest.GenVRPs(0, 100, 65001), nil)
	r := runClocked(t, 0, srv)
	r.changeEvery(srv, 1000, 96) // a day
	if thr, src, n := r.detector.Data().Threshold(srv.Addr()); thr != time.Hour || src != telemetry.ThresholdLearned || n != 96 {
		t.Fatalf("threshold after a day: %v (%s, %d gaps), want 1h learned from 96", thr, src, n)
	}
	for i := range 9 {
		ev := r.advance(srv, 10*time.Minute, rtrtest.Delta{})
		if !*ev.SerialChanged {
			t.Fatalf("sync %d: serial unchanged; the test wants new serials without new data", i)
		}
	}
	recs := r.data()
	if len(recs) != 1 || recs[0]["event_type"] != "stale" {
		t.Fatalf("90 minutes without a change: %v, want one stale", recordTypes(recs))
	}
	st := recs[0]
	if durNS(st["gap_ns"]) != time.Hour+dataTickEvery || durNS(st["expected_gap_ns"]) != time.Hour ||
		st["threshold_source"] != "learned" || st["syncs_without_change"] != 6.0 || st["gaps_learned"] != 96.0 {
		t.Errorf("stale record %v, want gap 1h00m15s, expected 1h learned from 96 gaps, 6 syncs without change", st)
	}
	if _, ok := st["scope"]; ok {
		t.Errorf("stale record with one cache has a scope: %v", st)
	}
	if got := r.anomalies(); !slices.Equal(got, []string{"data_stale"}) {
		t.Errorf("structural anomalies %v, want one data_stale", got)
	}

	r.advance(srv, 10*time.Minute, rtrtest.Delta{WithdrawVRPs: rtrtest.GenVRPs(0, 3, 65001)})
	recs = r.data()
	if len(recs) != 2 || recs[1]["event_type"] != "stale_resolved" {
		t.Fatalf("after a change: %v, want stale, stale_resolved", recordTypes(recs))
	}
	res := recs[1]
	if durNS(res["duration_ns"]) != 40*time.Minute-dataTickEvery || durNS(res["gap_ns"]) != 100*time.Minute ||
		res["vrp_removed"] != 3.0 || res["vrp_added"] != 0.0 || res["serial_after"] != float64(srv.Serial()) {
		t.Errorf("stale_resolved %v, want 39m45s stale, 100m unchanged, 3 removed", res)
	}
}

// The anycast-node stall, with real sets: a fresh node changing every 10-20
// minutes; a reconnect that lands on a stale node (new data to the monitor)
// and hourly syncs there (stale at the learned hour, once); within that
// session a change (resolved) undone 10 minutes later (data_regressed,
// incremental: the set it returns to was current for 3h, and the data is
// stale again at once); a reconnect to the fresh node (resolved); a
// reconnect back to the stale node at another serial (data_regressed, full,
// and stale again at once: that set is hours old).
func TestStaleAnycastShaped(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(2))
	base := rtrtest.GenVRPs(0, 100, 65001)
	srv.SetData(base, nil)
	r := runClocked(t, 0, srv)
	r.changeEvery(srv, 1000, 30)

	// The stale node: a lagging data set at a lower serial.
	stale := append(slices.Clone(base), rtrtest.GenVRPs(5000, 7, 65009)...)
	r.reconnect(srv, 5*time.Minute, stale, 3)
	for range 3 {
		r.advance(srv, time.Hour, rtrtest.Delta{})
	}
	recs := r.data()
	if got := recordTypes(recs); !slices.Equal(got, []string{"stale"}) {
		t.Fatalf("three hours on the stale node: %v, want one stale", got)
	}
	if durNS(recs[0]["gap_ns"]) != time.Hour+dataTickEvery {
		t.Errorf("stale %v: want 1h00m15s, the first tick past the learned 1h", recs[0])
	}

	// Within the session: a change, undone 10 minutes later.
	blip := rtrtest.GenVRPs(7000, 1, 65009)
	r.advance(srv, 10*time.Minute, rtrtest.Delta{AnnounceVRPs: blip})
	r.advance(srv, 10*time.Minute, rtrtest.Delta{WithdrawVRPs: blip})
	recs = r.data()
	if got := recordTypes(recs); !slices.Equal(got, []string{"stale", "stale_resolved", "data_regressed", "stale"}) {
		t.Fatalf("a change undone within the session: %v", got)
	}
	if reg := recs[2]; reg["sync_type"] != "incremental" || durNS(reg["ago_ns"]) != 10*time.Minute {
		t.Errorf("data_regressed %v, want incremental, that set last current 10m ago", reg)
	}

	// Reconnect to the fresh node: new data, resolved.
	fresh := append(slices.Clone(base), rtrtest.GenVRPs(1000, 40, 65001)...)
	r.reconnect(srv, 20*time.Minute, fresh, 9)
	// And back to the stale node, now at serial 4.
	r.reconnect(srv, 30*time.Minute, stale, 4)
	recs = r.data()
	if got := recordTypes(recs); !slices.Equal(got, []string{"stale", "stale_resolved", "data_regressed", "stale",
		"stale_resolved", "data_regressed", "stale"}) {
		t.Fatalf("records %v", got)
	}
	reg := recs[5]
	if reg["sync_type"] != "full" || reg["serial_before"] != 9.0 || reg["serial_after"] != 4.0 || durNS(reg["ago_ns"]) != 30*time.Minute {
		t.Errorf("data_regressed after a reconnect %v, want full, 9 -> 4, last current 30m ago", reg)
	}
	if again := recs[6]; again["last_change"] != reg["first_current"] {
		t.Errorf("stale again %v: its clock runs from the regressed set's first_current %v", again, reg["first_current"])
	}
	if n := rtrtest.CounterSum("raven_rtr_data_regressions_total", srv.Addr()); n != 2 {
		t.Errorf("raven_rtr_data_regressions_total %v, want 2", n)
	}
	if g := rtrtest.GaugeLabels("raven_rtr_stale", map[string]string{"cache": srv.Addr(), "cache_state": "connected"}); g != 1 {
		t.Errorf("raven_rtr_stale{cache_state=connected} %v, want 1", g)
	}
}

// DaKnObNET-like churn with real sets: every sync announces 23 VRPs and
// withdraws the 23 the previous one announced, so the cache toggles between
// two sets. Each was current for one 10-minute interval and stopped being
// current 10 minutes ago: data changes, never a data_regressed, never stale.
func TestChurnTogglingWithFakeCache(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(2))
	srv.SetData(rtrtest.GenVRPs(0, 100, 65001), nil)
	r := runClocked(t, 0, srv)
	r.changeEvery(srv, 1000, 30)
	a, b := rtrtest.GenVRPs(8000, 23, 65010), rtrtest.GenVRPs(9000, 23, 65010)
	r.advance(srv, 10*time.Minute, rtrtest.Delta{AnnounceVRPs: a})
	for i := range 40 {
		d := rtrtest.Delta{AnnounceVRPs: b, WithdrawVRPs: a}
		if i%2 == 1 {
			d = rtrtest.Delta{AnnounceVRPs: a, WithdrawVRPs: b}
		}
		if ev := r.advance(srv, 10*time.Minute, d); ev.VRPAdded != 23 || ev.VRPRemoved != 23 {
			t.Fatalf("sync %d: +%d -%d, want 23/23", i, ev.VRPAdded, ev.VRPRemoved)
		}
	}
	if recs := r.data(); len(recs) != 0 {
		t.Fatalf("toggling churn: %v, want no records", recordTypes(recs))
	}
}

// A reconnect to the same data at a lower serial (another node, the same
// data) is no change: the clock is not reset, and the data goes stale on
// time.
func TestReconnectSameDataKeepsClock(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(2))
	srv.SetData(rtrtest.GenVRPs(0, 100, 65001), nil)
	r := runClocked(t, time.Hour, srv)
	r.advance(srv, 10*time.Minute, rtrtest.Delta{AnnounceVRPs: rtrtest.GenVRPs(1000, 2, 65001)})
	same := append(rtrtest.GenVRPs(0, 100, 65001), rtrtest.GenVRPs(1000, 2, 65001)...)
	r.reconnect(srv, 40*time.Minute, same, 1)
	if recs := r.data(); len(recs) != 0 {
		t.Fatalf("reconnect to the same data: %v", recordTypes(recs))
	}
	if st, _ := r.detector.Data().Status(srv.Addr(), r.now); st.Age != 40*time.Minute {
		t.Errorf("data age after the reconnect %v, want 40m: the clock was reset", st.Age)
	}
	r.advance(srv, 30*time.Minute, rtrtest.Delta{})
	if recs := r.data(); len(recs) != 1 || recs[0]["event_type"] != "stale" || durNS(recs[0]["gap_ns"]) != time.Hour+dataTickEvery {
		t.Fatalf("1h after the last change: %v, want stale at 1h00m15s", recs)
	}
}

// Three caches compared, all stale together: one stale record per cache,
// scope upstream.
func TestStaleThreeCachesUpstream(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	for _, srv := range s {
		srv.SetData(baseVRPs, nil)
	}
	r := runClocked(t, time.Hour, s...)
	for range 7 {
		for i, srv := range s {
			d := time.Duration(0)
			if i == 0 {
				d = 10 * time.Minute
			}
			r.advance(srv, d, rtrtest.Delta{})
		}
	}
	recs := r.data()
	if len(recs) != 3 {
		t.Fatalf("records %v, want three stale", recs)
	}
	// Released together, in cache name order.
	var got, want []string
	for i, rec := range recs {
		got = append(got, rec["cache"].(string))
		want = append(want, s[i].Addr())
		if rec["event_type"] != "stale" || rec["scope"] != "upstream" || rec["timestamp"] != recs[0]["timestamp"] {
			t.Errorf("record %d: %v, want stale, scope upstream", i, rec)
		}
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("stale records for %v, want one for each of %v", got, want)
	}
}

// The values of threshold_source, scope, cache_state and resolution a live
// scenario does not reach are written by the same code;
// they are checked against the contract through RecordData.
func TestNDJSONStaleVariantsMatchContract(t *testing.T) {
	schema := loadSchema(t, ndjsonSchemaPath)
	now := time.Date(2026, 11, 12, 6, 49, 43, 0, time.UTC)
	for _, ev := range []telemetry.DataEvent{
		{Kind: telemetry.DataStale, Timestamp: now, Cache: "c:323", Serial: 3, LastChange: now.Add(-2 * time.Hour),
			Gap: 2 * time.Hour, ExpectedGap: time.Hour, SyncsWithoutChange: 2, ThresholdSource: telemetry.ThresholdLearned,
			GapsLearned: 231, Scope: telemetry.ScopeUpstream, CacheState: telemetry.CacheConnected},
		{Kind: telemetry.DataStale, Timestamp: now, Cache: "c:323", Serial: 3, LastChange: now.Add(-5 * time.Hour),
			Gap: 5 * time.Hour, ExpectedGap: 4 * time.Hour, ThresholdSource: telemetry.ThresholdDefault, Scope: telemetry.ScopeLocal,
			CacheState: telemetry.CacheDisconnected},
		{Kind: telemetry.DataStaleResolved, Timestamp: now, Cache: "c:323", StaleSince: now.Add(-time.Hour), Duration: time.Hour,
			LastChange: now.Add(-5 * time.Hour), Gap: 5 * time.Hour, SerialBefore: 3, SerialAfter: 0, SyncType: telemetry.SyncTypeFull,
			Resolution: telemetry.ResolvedReconnectNewData, VRPAdded: 5},
		{Kind: telemetry.DataStaleResolved, Timestamp: now, Cache: "c:323", StaleSince: now.Add(-time.Hour), Duration: time.Hour,
			LastChange: now.Add(-2 * time.Hour), Gap: 2 * time.Hour, SerialBefore: 3, SerialAfter: 4, SyncType: telemetry.SyncTypeIncremental,
			Resolution: telemetry.ResolvedDataChange, VRPRemoved: 1},
	} {
		var buf lockedBuffer
		telemetry.NewRecorder(&buf, 1, nil).RecordData(ev)
		line := strings.TrimSpace(buf.String())
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		if errs := schema.validate(v, schema.root, "stale"); len(errs) != 0 {
			t.Errorf("%v\n    %s", errs, line)
		}
	}
}

// The Routinator survey shape (ASPA Explorer, 15 Nov: disconnected 08:10 to
// 10:28, then a full sync at serial 0): a cache that goes away goes stale on
// the timer while its last data ages, as one episode with cache_state
// disconnected. A reconnect with new data ends it (reconnect_new_data); one
// with the same data does not, and a later change ends it (data_change).
func TestStaleWhileDisconnected(t *testing.T) {
	for _, newData := range []bool{true, false} {
		name := "reconnect with new data"
		if !newData {
			name = "reconnect with the same data"
		}
		t.Run(name, func(t *testing.T) {
			srv := rtrtest.NewServer(t, monitorCache(2))
			base := rtrtest.GenVRPs(0, 100, 65001)
			srv.SetData(base, nil)
			r := runClocked(t, 0, srv)
			r.changeEvery(srv, 1000, 30) // threshold 1h
			held := append(slices.Clone(base), rtrtest.GenVRPs(1000, 30, 65001)...)
			after := held
			if newData {
				after = append(slices.Clone(held), rtrtest.GenVRPs(4000, 5, 65001)...)
			}
			r.reconnect(srv, 75*time.Minute, after, 0)
			recs := r.data()
			if len(recs) == 0 || recs[0]["event_type"] != "stale" || recs[0]["cache_state"] != "disconnected" ||
				durNS(recs[0]["gap_ns"]) != time.Hour+dataTickEvery || recs[0]["syncs_without_change"] != 0.0 {
				t.Fatalf("75 minutes away: %v, want stale (disconnected) at 1h00m15s", recs)
			}
			if newData {
				if len(recs) != 2 || recs[1]["event_type"] != "stale_resolved" || recs[1]["resolution"] != "reconnect_new_data" ||
					recs[1]["sync_type"] != "full" {
					t.Fatalf("reconnect with new data: %v, want stale_resolved (reconnect_new_data)", recs)
				}
				return
			}
			if len(recs) != 1 {
				t.Fatalf("reconnect with the same data: %v, want the episode to go on", recordTypes(recs))
			}
			if g := rtrtest.GaugeLabels("raven_rtr_stale", map[string]string{"cache": srv.Addr(), "cache_state": "disconnected"}); g != 1 {
				t.Errorf("raven_rtr_stale{cache_state=disconnected} %v, want 1", g)
			}
			r.advance(srv, 10*time.Minute, rtrtest.Delta{AnnounceVRPs: rtrtest.GenVRPs(4000, 1, 65001)})
			recs = r.data()
			if len(recs) != 2 || recs[1]["event_type"] != "stale_resolved" || recs[1]["resolution"] != "data_change" {
				t.Fatalf("a change after the reconnect: %v, want one episode, stale_resolved (data_change)", recs)
			}
		})
	}
}
