package rtr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// In these tests one second of an End of Data interval lasts a millisecond,
// so "refresh 200" polls after 200ms.

// lockedBuffer is a bytes.Buffer safe for a logger or recorder and the test
// to share.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type testClient struct {
	*Client
	logs    *lockedBuffer
	updates atomic.Int64  // onUpdate calls
	syncs   chan struct{} // one per onSync call
}

// newTestClient starts a client against cache at the given version.
func newTestClient(t *testing.T, cache *rtrtest.Cache, version uint8) *testClient {
	t.Helper()
	logs := &lockedBuffer{}
	c, err := NewClient(cache.Addr(), "tcp", nil, store.NewVRPStore(), store.NewASPAStore(), version,
		slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c.unit = time.Millisecond
	c.retryMin, c.retryMax = 10*time.Millisecond, 50*time.Millisecond
	tc := &testClient{Client: c, logs: logs, syncs: make(chan struct{}, 64)}
	c.SetOnUpdate(func(*store.Delta) { tc.updates.Add(1) })
	c.SetOnSync(func() { tc.syncs <- struct{}{} })
	return tc
}

func (tc *testClient) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tc.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// synced waits for the client to complete a sync.
func (tc *testClient) synced(t *testing.T) {
	t.Helper()
	select {
	case <-tc.syncs:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not complete a sync within 5s")
	}
}

var testPrefix = netip.MustParsePrefix("192.0.2.0/24")

// fullSync answers the client's Reset Query with one VRP and the given End of
// Data, and returns the connection and when the End of Data went out.
func fullSync(t *testing.T, cache *rtrtest.Cache, version uint8, serial, refresh, retry, expire uint32) (*rtrtest.Conn, time.Time) {
	t.Helper()
	q := cache.Next(5 * time.Second)
	if q.Type != rtrtest.PDUResetQuery {
		t.Fatalf("first query type %d, want a Reset Query", q.Type)
	}
	q.Conn.Send(rtrtest.CacheResponse(version, 7), rtrtest.IPv4Prefix(version, true, testPrefix, 24, 65000))
	sent := time.Now()
	q.Conn.Send(rtrtest.EndOfData(version, 7, serial, refresh, retry, expire))
	return q.Conn, sent
}

// A cache need not send Serial Notify. The client polls it with a Serial
// Query every Refresh Interval, timed from the last End of Data.
func TestPollsAtRefreshIntervalWithoutNotify(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.start(t)

	conn, eod := fullSync(t, cache, 2, 41, 200, 600, 7200)
	tc.synced(t)
	for poll := 1; poll <= 2; poll++ {
		q := cache.Next(2 * time.Second)
		if q.Type != rtrtest.PDUSerialQuery || q.Serial != 41 || q.Session != 7 {
			t.Fatalf("poll %d: got query type %d serial %d session %d, want a Serial Query for serial 41, session 7",
				poll, q.Type, q.Serial, q.Session)
		}
		if gap := q.At.Sub(eod); gap < 180*time.Millisecond || gap > 600*time.Millisecond {
			t.Errorf("poll %d came %v after the End of Data, want the 200ms refresh interval", poll, gap)
		}
		conn.Send(rtrtest.CacheResponse(2, 7))
		eod = time.Now()
		conn.Send(rtrtest.EndOfData(2, 7, 41, 200, 600, 7200))
		tc.synced(t)
	}
}

// A Serial Notify before the refresh timer fires is answered at once, and
// the timer restarts from that sync's End of Data. The poll the old timer
// would have sent never goes out, even when the cache is slow to answer and
// the old deadline passes while the notify's query is outstanding.
func TestNotifyBeforeRefreshResetsTimer(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.start(t)

	conn, first := fullSync(t, cache, 2, 1, 400, 2000, 7200)
	tc.synced(t)
	time.Sleep(150 * time.Millisecond)
	conn.Send(rtrtest.SerialNotify(2, 7, 2))
	q := cache.Next(time.Second)
	if q.Type != rtrtest.PDUSerialQuery || q.Serial != 1 {
		t.Fatalf("got query type %d serial %d after the notify, want a Serial Query from serial 1", q.Type, q.Serial)
	}
	// The first timer was due 400ms after the first sync. Answer only well
	// after that; no second query may go out meanwhile.
	cache.None(time.Until(first.Add(600*time.Millisecond)), "while the notify's query was outstanding")
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("198.51.100.0/24"), 24, 65001))
	eod := time.Now()
	conn.Send(rtrtest.EndOfData(2, 7, 2, 400, 2000, 7200))
	tc.synced(t)

	cache.None(time.Until(eod.Add(350*time.Millisecond)), "before this sync's refresh interval")
	q = cache.Next(time.Second)
	if q.Type != rtrtest.PDUSerialQuery || q.Serial != 2 {
		t.Fatalf("got query type %d serial %d, want the next poll from serial 2", q.Type, q.Serial)
	}
	if gap := q.At.Sub(eod); gap > 800*time.Millisecond {
		t.Errorf("next poll came %v after the End of Data, want the 400ms refresh interval", gap)
	}
}

// A poll that finds the serial unchanged completes a sync, which
// raven_rtr_last_sync_seconds records, but does not count as a serial change
// or call the update callback (which requests a revalidation pass in raven
// serve). The NDJSON sync event says serial_changed false.
func TestPollWithUnchangedSerial(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	events := &lockedBuffer{}
	tc.SetTelemetry(telemetry.NewRecorder(events, 16, slog.New(slog.DiscardHandler)))
	tc.start(t)

	conn, _ := fullSync(t, cache, 2, 9, 100, 600, 7200)
	tc.synced(t)
	if got := tc.updates.Load(); got != 1 {
		t.Fatalf("%d update callbacks after the first sync, want 1", got)
	}
	addr := cache.Addr()
	metrics.RTRLastSync.WithLabelValues(addr).Set(0)
	metrics.RTRLastSerialChange.WithLabelValues(addr).Set(0)

	q := cache.Next(2 * time.Second)
	if q.Type != rtrtest.PDUSerialQuery {
		t.Fatalf("got query type %d, want a poll", q.Type)
	}
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.EndOfData(2, 7, 9, 100, 600, 7200))
	tc.synced(t)

	if got := rtrtest.Gauge("raven_rtr_last_sync_seconds", addr); got <= 0 {
		t.Errorf("raven_rtr_last_sync_seconds = %v after the poll, want it set", got)
	}
	if got := rtrtest.Gauge("raven_rtr_last_serial_change_seconds", addr); got != 0 {
		t.Errorf("raven_rtr_last_serial_change_seconds = %v after a poll with an unchanged serial, want it untouched", got)
	}
	if got := tc.updates.Load(); got != 1 {
		t.Errorf("%d update callbacks after an unchanged poll, want still 1: it must not request revalidation", got)
	}

	var changed []bool
	for _, line := range strings.Split(strings.TrimSpace(events.String()), "\n") {
		var ev telemetry.SessionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad NDJSON line %q: %v", line, err)
		}
		if ev.EventType == telemetry.EventSync {
			if ev.SerialChanged == nil {
				t.Fatalf("sync event without serial_changed: %s", line)
			}
			changed = append(changed, *ev.SerialChanged)
		}
	}
	if len(changed) != 2 || !changed[0] || changed[1] {
		t.Errorf("sync events' serial_changed = %v, want [true false]", changed)
	}
}

// With no completed sync for the Expire Interval, the data is flagged
// expired (and kept); the next completed sync clears the flag.
func TestDataExpiresWithoutResponse(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.start(t)
	addr := cache.Addr()

	// Expire 600 (the RFC minimum); retry 5000 keeps the unanswered poll's
	// session open past it.
	conn, eod := fullSync(t, cache, 2, 3, 100, 5000, 600)
	tc.synced(t)
	if got := rtrtest.Gauge("raven_rtr_data_expired", addr); got != 0 {
		t.Fatalf("raven_rtr_data_expired = %v after a sync, want 0", got)
	}
	cache.Next(time.Second) // the poll, left unanswered

	deadline := time.Now().Add(3 * time.Second)
	for rtrtest.Gauge("raven_rtr_data_expired", addr) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("raven_rtr_data_expired did not become 1 after the expire interval")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if since := time.Since(eod); since < 590*time.Millisecond {
		t.Errorf("data flagged expired %v after the last sync, want no earlier than the 600ms expire interval", since)
	}
	if !strings.Contains(tc.logs.String(), "level=ERROR msg=\"RTR data expired") {
		t.Errorf("no ERROR logged for expired data; logs:\n%s", tc.logs)
	}
	if n := tc.vrpStore.Count(); n != 1 {
		t.Errorf("VRP store holds %d VRPs after expiry, want the 1 received: expiry must not clear it", n)
	}

	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.EndOfData(2, 7, 3, 100, 5000, 600))
	tc.synced(t)
	if got := rtrtest.Gauge("raven_rtr_data_expired", addr); got != 0 {
		t.Errorf("raven_rtr_data_expired = %v after a sync, want 0 again", got)
	}
}

// Error Report code 2 (No Data Available) is a cache still starting up, not
// a version problem: the client reconnects at the same version.
func TestNoDataAvailableKeepsVersion(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.start(t)

	q := cache.Next(5 * time.Second)
	if q.Version != 2 {
		t.Fatalf("first Reset Query at version %d, want 2", q.Version)
	}
	q.Conn.Send(rtrtest.ErrorReport(2, 2, "Running initial validation"))

	q = cache.Next(5 * time.Second)
	if q.Type != rtrtest.PDUResetQuery || q.Version != 2 {
		t.Fatalf("after No Data Available: query type %d at version %d, want a Reset Query at version 2", q.Type, q.Version)
	}
	q.Conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.EndOfData(2, 7, 1, 3600, 600, 7200))
	tc.synced(t)
	if got := rtrtest.Gauge("raven_rtr_protocol_version", cache.Addr()); got != 2 {
		t.Errorf("raven_rtr_protocol_version = %v, want 2", got)
	}
	if strings.Contains(tc.logs.String(), "downgrad") || strings.Contains(tc.logs.String(), "falling back") {
		t.Errorf("logged a version downgrade for No Data Available; logs:\n%s", tc.logs)
	}
}

// Error Report code 4 (Unsupported Protocol Version) at version 2: the
// client reconnects at version 1 and stays there across reconnects, clears
// the ASPA store (version 1 carries no ASPA, so anything held is stale) and
// warns that ASPA validation is unavailable.
func TestUnsupportedVersionDowngradesAndClearsASPA(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.aspaStore.AddProvider(64500, 64501) // left over from an earlier v2 session
	tc.start(t)

	q := cache.Next(5 * time.Second)
	if q.Version != 2 {
		t.Fatalf("first Reset Query at version %d, want 2", q.Version)
	}
	q.Conn.Send(rtrtest.ErrorReport(1, 4, "Unsupported Protocol Version"))

	for attempt := 1; attempt <= 2; attempt++ {
		q = cache.Next(5 * time.Second)
		if q.Type != rtrtest.PDUResetQuery || q.Version != 1 {
			t.Fatalf("session %d after the downgrade: query type %d at version %d, want a Reset Query at version 1",
				attempt, q.Type, q.Version)
		}
		q.Conn.Send(rtrtest.CacheResponse(1, 7), rtrtest.IPv4Prefix(1, true, testPrefix, 24, 65000),
			rtrtest.EndOfData(1, 7, 1, 3600, 600, 7200))
		tc.synced(t)
		if n := tc.aspaStore.Count(); n != 0 {
			t.Errorf("ASPA store holds %d records on a version 1 session, want 0", n)
		}
		if got := rtrtest.Gauge("raven_rtr_protocol_version", cache.Addr()); got != 1 {
			t.Errorf("raven_rtr_protocol_version = %v, want 1", got)
		}
		q.Conn.Close() // the next session must start at version 1 too
	}
	if !strings.Contains(tc.logs.String(), "level=WARN msg=\"RTR session below protocol version 2: ASPA validation is unavailable\"") {
		t.Errorf("no WARN that ASPA validation is unavailable; logs:\n%s", tc.logs)
	}
}

// rtr.expire-interval is clamped to RFC 8210's 600-172800 s; zero or less
// is unset.
func TestExpireOverrideClamp(t *testing.T) {
	for _, tc := range []struct {
		in      int
		want    uint32
		clamped bool
	}{
		{0, 0, false}, {-5, 0, false}, {1, 600, true}, {599, 600, true}, {600, 600, false},
		{3600, 3600, false}, {172800, 172800, false}, {172801, 172800, true}, {1 << 40, 172800, true},
	} {
		if got, clamped := ExpireOverride(tc.in); got != tc.want || clamped != tc.clamped {
			t.Errorf("ExpireOverride(%d) = %d, %v; want %d, %v", tc.in, got, clamped, tc.want, tc.clamped)
		}
	}
}

// Set, rtr.expire-interval replaces the cache's Expire Interval: data from a
// cache saying 172800 expires after the configured 600. Unset, the cache's
// 172800 holds and the data does not expire then. It used to be read and
// never used.
func TestExpireOverrideReplacesCacheInterval(t *testing.T) {
	for _, override := range []uint32{600, 0} {
		cache := rtrtest.NewCache(t)
		tc := newTestClient(t, cache, 2)
		tc.SetExpireOverride(override)
		tc.start(t)
		addr := cache.Addr()

		_, eod := fullSync(t, cache, 2, 3, 100, 5000, 172800)
		tc.synced(t)
		cache.Next(time.Second) // the poll, left unanswered

		deadline := eod.Add(1500 * time.Millisecond)
		expired := false
		for time.Now().Before(deadline) && !expired {
			expired = rtrtest.Gauge("raven_rtr_data_expired", addr) == 1
			time.Sleep(5 * time.Millisecond)
		}
		if override != 0 && !expired {
			t.Errorf("override %d: data not expired 1.5s after the sync (600ms interval)", override)
		}
		if override != 0 && time.Since(eod) < 590*time.Millisecond {
			t.Errorf("override %d: expired %v after the sync, before the 600ms interval", override, time.Since(eod))
		}
		if override == 0 && expired {
			t.Error("unset: data expired within 1.5s, though the cache said 172800")
		}
		if !strings.Contains(tc.logs.String(), fmt.Sprintf("expire_effective=%d", map[bool]uint32{true: 600, false: 172800}[override != 0])) {
			t.Errorf("override %d: sync log lacks the effective expire:\n%s", override, tc.logs)
		}
	}
}
