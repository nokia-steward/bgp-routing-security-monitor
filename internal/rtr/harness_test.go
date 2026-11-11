package rtr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// Integration tests: the client against rtrtest.Server, a fake cache that
// answers on its own, with the telemetry the client records. As in the other
// tests, one second of an End of Data interval lasts a millisecond.

// harness is a client, the fake cache it talks to, and every telemetry
// event the client recorded.
type harness struct {
	*Client
	srv    *rtrtest.Server
	logs   *lockedBuffer
	ndjson *lockedBuffer
	syncs  chan struct{}

	mu     sync.Mutex
	events []telemetry.SessionEvent
	more   chan struct{} // signalled on each new event

	stopOnce sync.Once
	cancel   context.CancelFunc
	done     chan struct{}
}

func newHarness(t *testing.T, cfg rtrtest.ServerConfig, version uint8, pinned bool) *harness {
	t.Helper()
	srv := rtrtest.NewServer(t, cfg)
	h := &harness{
		srv:    srv,
		logs:   &lockedBuffer{},
		ndjson: &lockedBuffer{},
		syncs:  make(chan struct{}, 1),
		more:   make(chan struct{}, 1),
	}
	c, err := NewClient(srv.Addr(), "tcp", nil, store.NewVRPStore(), store.NewASPAStore(), version,
		slog.New(slog.NewTextHandler(h.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c.unit = time.Millisecond
	c.retryMin, c.retryMax = 10*time.Millisecond, 50*time.Millisecond
	c.SetVersionPinned(pinned)
	c.SetOnSync(func() {
		select {
		case h.syncs <- struct{}{}:
		default:
		}
	})
	rec := telemetry.NewRecorder(h.ndjson, 4096, slog.New(slog.DiscardHandler))
	c.SetTelemetry(rec)
	h.Client = c
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		for ev := range rec.Events() {
			h.mu.Lock()
			h.events = append(h.events, ev)
			h.mu.Unlock()
			select {
			case h.more <- struct{}{}:
			default:
			}
		}
	}()
	// Cleanups run last-registered first: the client (start) stops before
	// the recorder closes.
	t.Cleanup(func() {
		rec.Close()
		<-collected
	})
	return h
}

func (h *harness) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan struct{})
	go func() {
		defer close(h.done)
		h.Start(ctx)
	}()
	t.Cleanup(h.stop)
}

// stop stops the client and waits for Start to return.
func (h *harness) stop() {
	h.stopOnce.Do(func() {
		h.cancel()
		<-h.done
	})
}

// synced waits for a completed sync.
func (h *harness) synced(t *testing.T) {
	t.Helper()
	select {
	case <-h.syncs:
	case <-time.After(5 * time.Second):
		t.Fatalf("no sync within 5s; logs:\n%s", h.logs)
	}
}

// eventsOf returns the events recorded so far of the given types, all of
// them with none given.
func (h *harness) eventsOf(types ...telemetry.EventType) []telemetry.SessionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []telemetry.SessionEvent
	for _, ev := range h.events {
		if len(types) == 0 || slices.Contains(types, ev.EventType) {
			out = append(out, ev)
		}
	}
	return out
}

// waitEvents waits until at least n events of type typ have been recorded,
// and returns them.
func (h *harness) waitEvents(t *testing.T, typ telemetry.EventType, n int) []telemetry.SessionEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if evs := h.eventsOf(typ); len(evs) >= n {
			return evs
		}
		select {
		case <-h.more:
		case <-deadline:
			t.Fatalf("%d %s events within 5s, want %d; events: %s", len(h.eventsOf(typ)), typ, n, h.summary())
		}
	}
}

// summary lists the recorded events, for failure messages.
func (h *harness) summary() string {
	var parts []string
	for _, ev := range h.eventsOf() {
		s := string(ev.EventType)
		switch ev.EventType {
		case telemetry.EventDisconnected:
			s += "(" + ev.DisconnectReason + ")"
		case telemetry.EventVersionDowngrade:
			s += "(" + ev.DowngradeReason + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// queryVersions waits for at least n queries and returns the versions of
// all received so far.
func (h *harness) queryVersions(t *testing.T, n int) []uint8 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		qs := h.srv.Received()
		if len(qs) >= n {
			out := make([]uint8, len(qs))
			for i, q := range qs {
				out[i] = q.Version
			}
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d queries within 5s, want %d; events: %s", len(qs), n, h.summary())
		}
		h.srv.NextQuery(5 * time.Second)
	}
}

// checkOneDisconnectPerSession fails unless the session events alternate
// connected, disconnected, connected, ... : every session that connected
// ended with exactly one disconnected event.
func (h *harness) checkOneDisconnectPerSession(t *testing.T) {
	t.Helper()
	open := false
	for _, ev := range h.eventsOf(telemetry.EventConnected, telemetry.EventDisconnected) {
		switch {
		case ev.EventType == telemetry.EventConnected && open:
			t.Fatalf("connected with no disconnected for the session before: %s", h.summary())
		case ev.EventType == telemetry.EventDisconnected && !open:
			t.Fatalf("disconnected with no session open: %s", h.summary())
		}
		open = ev.EventType == telemetry.EventConnected
	}
}

func v2Cache() rtrtest.ServerConfig {
	return rtrtest.ServerConfig{MaxVersion: 2, Session: 7, Refresh: 3600, Retry: 600, Expire: 7200}
}

func cacheAt(max uint8) rtrtest.ServerConfig {
	cfg := v2Cache()
	cfg.MaxVersion = max
	return cfg
}

// Negotiation settles on the highest version the cache speaks, whichever
// way the cache turns a version down, and a pinned version never moves.
func TestVersionNegotiation(t *testing.T) {
	rst := cacheAt(1)
	rst.Unsupported = rtrtest.CloseRST
	fin := cacheAt(1)
	fin.Unsupported = rtrtest.CloseFIN
	echo0 := cacheAt(0)
	echo0.ErrorAtQueryVersion = true // the Error Report names the rejected version: step by step

	for _, tc := range []struct {
		name       string
		cache      rtrtest.ServerConfig
		start      uint8
		wantQuery  []uint8 // versions of the queries up to the sync
		wantDown   []string
		wantSessAt uint8
	}{
		{"v2 cache", v2Cache(), 2, []uint8{2}, nil, 2},
		{"v1-only cache, code 4", cacheAt(1), 2, []uint8{2, 1}, []string{"unsupported_version"}, 1},
		{"v0-only cache, code 4 at version 0", cacheAt(0), 2, []uint8{2, 0}, []string{"unsupported_version"}, 0},
		{"v0-only cache, code 4 at the rejected version", echo0, 2, []uint8{2, 1, 0},
			[]string{"unsupported_version", "unsupported_version"}, 0},
		{"v0-only cache, start at 1", cacheAt(0), 1, []uint8{1, 0}, []string{"unsupported_version"}, 0},
		{"RST before any response", rst, 2, []uint8{2, 1}, []string{"session_dropped"}, 1},
		{"FIN before any response", fin, 2, []uint8{2, 1}, []string{"session_dropped"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.cache, tc.start, false)
			h.start(t)
			h.synced(t)
			if got := h.queryVersions(t, len(tc.wantQuery)); !slices.Equal(got, tc.wantQuery) {
				t.Errorf("query versions %v, want %v", got, tc.wantQuery)
			}
			if got := h.ProtocolVersion(); got != tc.wantSessAt {
				t.Errorf("session at version %d, want %d", got, tc.wantSessAt)
			}
			if got := rtrtest.Gauge("raven_rtr_protocol_version", h.srv.Addr()); got != float64(tc.wantSessAt) {
				t.Errorf("raven_rtr_protocol_version = %v, want %d", got, tc.wantSessAt)
			}
			var reasons []string
			for i, ev := range h.eventsOf(telemetry.EventVersionDowngrade) {
				reasons = append(reasons, ev.DowngradeReason)
				if ev.ProtoVersion != tc.wantQuery[i] || ev.NextProtoVersion == nil || *ev.NextProtoVersion != tc.wantQuery[i+1] {
					t.Errorf("downgrade %d: %d -> %v, want %d -> %d", i, ev.ProtoVersion, ev.NextProtoVersion, tc.wantQuery[i], tc.wantQuery[i+1])
				}
			}
			if !slices.Equal(reasons, tc.wantDown) {
				t.Errorf("version_downgrade reasons %v, want %v; events: %s", reasons, tc.wantDown, h.summary())
			}
			// Negotiation is not a fault.
			if errs := h.eventsOf(telemetry.EventError); len(errs) != 0 {
				t.Errorf("error events %+v during negotiation, want none", errs)
			}
			// No further query: neither a reconnect nor (within this window)
			// another step.
			h.srv.NoQuery(100*time.Millisecond, "after the session settled")
		})
	}
}

// After a drop-triggered fallback whose lower version also drops, the client
// goes back to the version it was at, and does not lower it on a drop again
// until the cache answers something: one retry, then normal backoff at the
// original version.
func TestDropFallbackRetriesOnce(t *testing.T) {
	h := newHarness(t, v2Cache(), 2, false)
	h.srv.Then(rtrtest.CloseRST, rtrtest.CloseRST, rtrtest.CloseRST, rtrtest.CloseFIN)
	h.start(t)
	h.synced(t)
	if got, want := h.queryVersions(t, 5), []uint8{2, 1, 2, 2, 2}; !slices.Equal(got, want) {
		t.Errorf("query versions %v, want %v (one retry at 1, then back to 2)", got, want)
	}
	if got := h.ProtocolVersion(); got != 2 {
		t.Errorf("session at version %d, want 2", got)
	}
	if n := len(h.eventsOf(telemetry.EventVersionDowngrade)); n != 1 {
		t.Errorf("%d version_downgrade events, want 1; events: %s", n, h.summary())
	}
}

// A pinned version is never left: not on code 4, not on a dropped
// connection, not when the cache answers at another version. Code 4 at a
// pinned version is an error, not a negotiation step.
func TestPinnedVersionNeverFallsBack(t *testing.T) {
	rst := cacheAt(1)
	rst.Unsupported = rtrtest.CloseRST
	answersLower := cacheAt(1)
	answersLower.Unsupported = rtrtest.Answer // a Cache Response at version 1
	for _, tc := range []struct {
		name      string
		cache     rtrtest.ServerConfig
		wantError bool // error events for the rejections
	}{
		{"code 4", cacheAt(1), true},
		{"RST", rst, false},
		{"answers at version 1", answersLower, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.cache, 2, true)
			h.start(t)
			if got := h.queryVersions(t, 4); slices.ContainsFunc(got, func(v uint8) bool { return v != 2 }) {
				t.Errorf("query versions %v, want all 2", got)
			}
			h.stop()
			if n := len(h.eventsOf(telemetry.EventVersionDowngrade)); n != 0 {
				t.Errorf("%d version_downgrade events at a pinned version; events: %s", n, h.summary())
			}
			if n := len(h.eventsOf(telemetry.EventSync)); n != 0 {
				t.Errorf("%d syncs, want none at a version the cache does not speak", n)
			}
			if got := len(h.eventsOf(telemetry.EventError)) > 0; got != tc.wantError {
				t.Errorf("error events: %t, want %t; events: %s", got, tc.wantError, h.summary())
			}
			h.checkOneDisconnectPerSession(t)
		})
	}
}

// Pinned to 0 against a version 2 cache: the session opens and stays at 0,
// no code 4 is recorded and the client never re-probes a higher version.
func TestPinnedZeroNeverReprobes(t *testing.T) {
	h := newHarness(t, v2Cache(), 0, true)
	h.reprobeInterval = testReprobe
	h.start(t)
	h.synced(t)
	h.srv.NoQuery(3*testReprobe, "pinned at 0: no re-probe")
	if got := h.queryVersions(t, 1); !slices.Equal(got, []uint8{0}) {
		t.Errorf("query versions %v, want [0]", got)
	}
	if got := h.ProtocolVersion(); got != 0 {
		t.Errorf("session at %d, want 0", got)
	}
}

// Error Report code 2 (No Data Available) at startup is a cache still
// building its data: the client retries at the same version, and records
// cache_not_ready, not a downgrade or an error.
func TestNoDataAtStartupNeverDowngrades(t *testing.T) {
	h := newHarness(t, v2Cache(), 2, false)
	h.srv.Then(rtrtest.ReportError(rtrtest.CodeNoDataAvailable), rtrtest.ReportError(rtrtest.CodeNoDataAvailable),
		rtrtest.ReportError(rtrtest.CodeNoDataAvailable))
	h.start(t)
	h.synced(t)
	if got, want := h.queryVersions(t, 4), []uint8{2, 2, 2, 2}; !slices.Equal(got, want) {
		t.Errorf("query versions %v, want %v", got, want)
	}
	if n := len(h.eventsOf(telemetry.EventCacheNotReady)); n != 3 {
		t.Errorf("%d cache_not_ready events, want 3", n)
	}
	if n := len(h.eventsOf(telemetry.EventVersionDowngrade, telemetry.EventError)); n != 0 {
		t.Errorf("%d downgrade or error events, want none; events: %s", n, h.summary())
	}
	// The drop that follows each Error Report must not count as a
	// drop-before-response either.
	for _, ev := range h.eventsOf(telemetry.EventDisconnected) {
		if ev.DisconnectReason != "error_report" || ev.ErrorCode == nil || *ev.ErrorCode != 2 {
			t.Errorf("disconnected %+v, want reason error_report, code 2", ev)
		}
	}
}

// Code 4 on a session that is already established is not negotiation: an
// error event (which rtr monitor reports as an anomaly), not a
// version_downgrade.
func TestCode4AfterEstablishedIsAnError(t *testing.T) {
	h := newHarness(t, v2Cache(), 2, false)
	h.start(t)
	h.synced(t)
	h.srv.Session().Send(rtrtest.ErrorReport(2, rtrtest.CodeUnsupportedVersion, "Unsupported Protocol Version"))
	errs := h.waitEvents(t, telemetry.EventError, 1)
	if errs[0].ErrorCode == nil || *errs[0].ErrorCode != 4 || errs[0].ProtoVersion != 2 {
		t.Errorf("error event %+v, want code 4 at version 2", errs[0])
	}
	if n := len(h.eventsOf(telemetry.EventVersionDowngrade)); n != 0 {
		t.Errorf("version_downgrade after an established session; events: %s", h.summary())
	}
}

// Each way a session ends produces exactly one disconnected event, with
// its reason, before the next session's connected event.
func TestDisconnectReasons(t *testing.T) {
	for _, tc := range []struct {
		name     string
		end      func(h *harness)
		reason   string
		code     *uint16
		stall    bool // the first query goes unanswered instead
		shutdown bool
	}{
		{name: "eof", end: func(h *harness) { h.srv.Session().Close() }, reason: "eof"},
		{name: "reset", end: func(h *harness) { h.srv.Session().Reset() }, reason: "reset"},
		{name: "error report", end: func(h *harness) {
			h.srv.Session().Send(rtrtest.ErrorReport(2, 0, "Corrupt Data"))
		}, reason: "error_report", code: new(uint16)},
		{name: "timeout", stall: true, reason: "timeout"},
		{name: "shutdown", end: func(h *harness) { h.stop() }, reason: "shutdown", shutdown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, v2Cache(), 2, false)
			if tc.stall {
				h.srv.Then(rtrtest.Stall) // Retry 600 here: 600ms
			}
			h.start(t)
			if !tc.stall {
				h.synced(t)
				tc.end(h)
			}
			if !tc.shutdown {
				h.waitEvents(t, telemetry.EventConnected, 2) // reconnected
				h.synced(t)
			}
			ev := h.waitEvents(t, telemetry.EventDisconnected, 1)[0]
			if ev.DisconnectReason != tc.reason {
				t.Errorf("disconnect reason %q, want %q; events: %s", ev.DisconnectReason, tc.reason, h.summary())
			}
			switch {
			case tc.code == nil && ev.ErrorCode != nil:
				t.Errorf("error_code %d, want none", *ev.ErrorCode)
			case tc.code != nil && (ev.ErrorCode == nil || *ev.ErrorCode != *tc.code):
				t.Errorf("error_code %v, want %d", ev.ErrorCode, *tc.code)
			}
			if ev.ProtoVersion != 2 {
				t.Errorf("disconnected proto_version %d, want 2", ev.ProtoVersion)
			}
			h.stop()
			h.waitEvents(t, telemetry.EventDisconnected, len(h.eventsOf(telemetry.EventConnected)))
			h.checkOneDisconnectPerSession(t)
			if n := len(h.eventsOf(telemetry.EventDisconnected)); n != len(h.eventsOf(telemetry.EventConnected)) {
				t.Errorf("%d disconnected for %d sessions; events: %s", n, len(h.eventsOf(telemetry.EventConnected)), h.summary())
			}
		})
	}
}

// proto_version is in every NDJSON record the client writes, 0 included.
func TestProtoVersionAlwaysInNDJSON(t *testing.T) {
	for _, v := range []uint8{0, 1, 2} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			h := newHarness(t, v2Cache(), v, true)
			h.start(t)
			h.synced(t)
			h.srv.Session().Close() // a disconnected record too
			h.waitEvents(t, telemetry.EventConnected, 2)
			h.synced(t)
			h.stop()
			h.waitEvents(t, telemetry.EventDisconnected, 2)

			seen := map[string]bool{}
			for _, line := range strings.Split(strings.TrimSpace(h.ndjson.String()), "\n") {
				var rec map[string]any
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatalf("NDJSON %q: %v", line, err)
				}
				pv, ok := rec["proto_version"]
				if !ok {
					t.Errorf("record without proto_version: %s", line)
					continue
				}
				if pv != float64(v) {
					t.Errorf("proto_version %v, want %d: %s", pv, v, line)
				}
				seen[rec["event_type"].(string)] = true
			}
			for _, typ := range []string{"connected", "sync", "disconnected"} {
				if !seen[typ] {
					t.Errorf("no %s record in NDJSON:\n%s", typ, h.ndjson)
				}
			}
		})
	}
}

// A Serial Notify leads to a Serial Query for the client's serial, and the
// stores end up holding what the cache holds, delta after delta, including
// a burst of 1,200 VRPs.
func TestSerialNotifyAppliesDeltas(t *testing.T) {
	h := newHarness(t, v2Cache(), 2, false)
	initial := rtrtest.GenVRPs(0, 50, 65001)
	h.srv.SetData(initial, []rtrtest.ASPASet{
		{Customer: 64500, Providers: []uint32{64501, 64502}},
		{Customer: 64510, Providers: []uint32{64511}},
	})
	h.start(t)
	h.synced(t)

	for i, d := range []rtrtest.Delta{
		{AnnounceVRPs: rtrtest.GenVRPs(1000, 5, 65002), WithdrawVRPs: initial[:3],
			AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64520, Providers: []uint32{64521}}}, WithdrawASPAs: []uint32{64510}},
		{AnnounceVRPs: rtrtest.GenVRPs(5000, 1200, 65003)},
		{WithdrawVRPs: rtrtest.GenVRPs(5000, 600, 65003)},
	} {
		before := h.srv.Serial() // what the client synced to
		serial := h.srv.Advance(d)
		h.srv.Notify()
		q := h.srv.NextQuery(5 * time.Second)
		for q.Type != rtrtest.PDUSerialQuery { // skip the initial Reset Query
			q = h.srv.NextQuery(5 * time.Second)
		}
		if q.Serial != before || q.Session != 7 {
			t.Fatalf("delta %d: Serial Query for serial %d session %d, want serial %d session 7", i, q.Serial, q.Session, before)
		}
		h.synced(t)
		syncs := h.waitEvents(t, telemetry.EventSync, i+2)
		ev := syncs[len(syncs)-1]
		vrps, aspas := h.srv.Counts()
		if ev.Serial != serial || ev.SyncType != telemetry.SyncTypeIncremental ||
			ev.VRPAnnounced != len(d.AnnounceVRPs) || ev.VRPWithdrawn != len(d.WithdrawVRPs) ||
			ev.ASPAAnnounced != len(d.AnnounceASPAs) || ev.ASPAWithdrawn != len(d.WithdrawASPAs) {
			t.Errorf("delta %d: sync %+v, want serial %d and the delta's counts", i, ev, serial)
		}
		if got := int(h.vrpStore.Count()); got != vrps || ev.VRPTotal != vrps {
			t.Errorf("delta %d: VRP store %d (sync says %d), cache holds %d", i, got, ev.VRPTotal, vrps)
		}
		if got := h.aspaStore.Count(); got != aspas || ev.ASPATotal != aspas {
			t.Errorf("delta %d: ASPA store %d (sync says %d), cache holds %d", i, got, ev.ASPATotal, aspas)
		}
	}
}

// A Refresh Interval of 0 means "refresh now", clamped to 1 s: it must not
// silence polling (a cache that never notifies would leave the session
// quiet for the 3600 s default). The client keeps polling with Serial
// Queries, one per (clamped) second, never in a tight loop.
func TestRefreshZeroKeepsPolling(t *testing.T) {
	cfg := v2Cache()
	cfg.Refresh = 0
	h := newHarness(t, cfg, 2, false)
	h.unit = 20 * time.Millisecond // 1 s = 20ms, so Retry 600 = 12 s
	h.start(t)
	h.synced(t)
	var last time.Time
	for poll := 1; poll <= 4; poll++ {
		q := h.srv.NextQuery(2 * time.Second)
		if poll == 1 && q.Type == rtrtest.PDUResetQuery {
			last = q.At
			q = h.srv.NextQuery(2 * time.Second)
		}
		if q.Type != rtrtest.PDUSerialQuery || q.Serial != 0 {
			t.Fatalf("poll %d: query type %d serial %d, want a Serial Query for serial 0", poll, q.Type, q.Serial)
		}
		if gap := q.At.Sub(last); gap < 15*time.Millisecond {
			t.Errorf("poll %d came %v after the previous query, want about one clamped second (20ms)", poll, gap)
		}
		last = q.At
	}
	if strings.Count(h.logs.String(), "cache sent an out-of-range End of Data interval") == 0 {
		t.Errorf("no WARN for the clamped refresh 0; logs:\n%s", h.logs)
	}
}
