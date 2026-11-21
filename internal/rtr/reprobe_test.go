package rtr

import (
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

const testReprobe = 300 * time.Millisecond

// downgradeToV1 has the cache turn down version 2 and serves the version 1
// session that follows; it returns that session's connection.
func downgradeToV1(t *testing.T, cache *rtrtest.Cache, tc *testClient) *rtrtest.Conn {
	t.Helper()
	q := cache.Next(5 * time.Second)
	if q.Type != rtrtest.PDUResetQuery || q.Version != 2 {
		t.Fatalf("first query type %d at version %d, want a Reset Query at version 2", q.Type, q.Version)
	}
	q.Conn.Send(rtrtest.ErrorReport(1, 4, "Unsupported Protocol Version"))
	q = cache.Next(5 * time.Second)
	if q.Type != rtrtest.PDUResetQuery || q.Version != 1 {
		t.Fatalf("after the downgrade: query type %d at version %d, want a Reset Query at version 1", q.Type, q.Version)
	}
	// Refresh 3600 (3.6s here) keeps polls out of the test.
	q.Conn.Send(rtrtest.CacheResponse(1, 7), rtrtest.IPv4Prefix(1, true, testPrefix, 24, 65000),
		rtrtest.EndOfData(1, 7, 1, 3600, 600, 7200))
	tc.synced(t)
	return q.Conn
}

// nextProbe waits for a version re-probe: a Reset Query at version 2 on a
// connection other than the running session's.
func nextProbe(t *testing.T, cache *rtrtest.Cache, session *rtrtest.Conn, after time.Time) rtrtest.Query {
	t.Helper()
	q := cache.Next(3 * time.Second)
	if q.Type != rtrtest.PDUResetQuery || q.Version != 2 || q.Conn == session {
		t.Fatalf("got query type %d at version %d (same connection as the session: %t), want a version 2 re-probe on a new connection",
			q.Type, q.Version, q.Conn == session)
	}
	if gap := q.At.Sub(after); gap < testReprobe-50*time.Millisecond {
		t.Errorf("re-probe came %v after the previous downgrade decision, want no sooner than the %v interval", gap, testReprobe)
	}
	return q
}

// After a code-4 downgrade the client keeps its version 1 session, and once
// per re-probe interval checks on a separate connection whether the cache now
// takes version 2. A cache that still says no leaves the session alone and
// the client downgraded for another interval.
func TestVersionReprobeKeepsV1OnlyCacheDowngraded(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.reprobeInterval = testReprobe
	tc.start(t)

	downgraded := time.Now()
	session := downgradeToV1(t, cache, tc)
	for probe := 1; probe <= 2; probe++ {
		q := nextProbe(t, cache, session, downgraded)
		downgraded = time.Now()
		q.Conn.Send(rtrtest.ErrorReport(1, 4, "Unsupported Protocol Version"))
	}
	// The version 1 session was never torn down: every query since was a
	// probe, and no further version 1 Reset Query arrived.
	if got := rtrtest.Gauge("raven_rtr_protocol_version", cache.Addr()); got != 1 {
		t.Errorf("raven_rtr_protocol_version = %v, want still 1", got)
	}
	logs := tc.logs.String()
	if !strings.Contains(logs, "level=INFO msg=\"re-probing RTR protocol version\"") {
		t.Errorf("no INFO for the re-probe; logs:\n%s", logs)
	}
	if !strings.Contains(logs, "level=WARN msg=\"cache still does not support the configured RTR protocol version; staying downgraded\"") {
		t.Errorf("no WARN that the client stays downgraded; logs:\n%s", logs)
	}
}

// A cache that has become version 2 capable answers the next re-probe; the
// client then reconnects at version 2 and syncs ASPA data again.
func TestVersionReprobeUpgradesWhenCacheGainsV2(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.reprobeInterval = testReprobe
	tc.start(t)

	downgraded := time.Now()
	session := downgradeToV1(t, cache, tc)
	q := nextProbe(t, cache, session, downgraded)
	downgraded = time.Now()
	q.Conn.Send(rtrtest.ErrorReport(1, 4, "Unsupported Protocol Version"))

	// The cache is upgraded. The next probe gets a version 2 answer.
	q = nextProbe(t, cache, session, downgraded)
	q.Conn.Send(rtrtest.CacheResponse(2, 8))

	q = cache.Next(3 * time.Second)
	if q.Type != rtrtest.PDUResetQuery || q.Version != 2 || q.Conn == session {
		t.Fatalf("after a successful re-probe: query type %d at version %d, want a new session's Reset Query at version 2", q.Type, q.Version)
	}
	q.Conn.Send(rtrtest.CacheResponse(2, 8), rtrtest.IPv4Prefix(2, true, testPrefix, 24, 65000),
		rtrtest.ASPA(true, 64500, 64501, 64502), rtrtest.EndOfData(2, 8, 1, 3600, 600, 7200))
	tc.synced(t)

	if got := rtrtest.Gauge("raven_rtr_protocol_version", cache.Addr()); got != 2 {
		t.Errorf("raven_rtr_protocol_version = %v after the upgrade, want 2", got)
	}
	if !tc.aspaStore.HasProvider(64500, 64502) {
		t.Errorf("ASPA store has no record for AS64500 after syncing at version 2 (holds %d records)", tc.aspaStore.Count())
	}
	if !strings.Contains(tc.logs.String(), "upgrading") {
		t.Errorf("no log of the upgrade; logs:\n%s", tc.logs)
	}
	// Back at the configured version: no more re-probes.
	cache.None(2*testReprobe, "after the upgrade")
}
