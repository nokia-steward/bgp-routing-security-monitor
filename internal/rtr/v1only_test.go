package rtr

import (
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

// A cache that speaks only version 1, as StayRTR in the Loc-RIB lab does,
// rejects the version 2 Reset Query with Error Report code 4 (Unsupported
// Protocol Version) and closes the connection. The client must settle on
// version 1, keep that one session, and re-probe version 2 once per interval
// on a separate connection, never reconnecting in a loop. The Error Report's
// own PDU version varies by cache, so both are covered.
func TestV1OnlyCacheSettlesOnV1WithoutLooping(t *testing.T) {
	for _, tc := range []struct {
		name      string
		errorPDUv uint8 // the version field of the cache's Error Report
	}{
		{"error report at version 1", 1},
		{"error report at the rejected version 2", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := rtrtest.NewCache(t)
			tc2 := newTestClient(t, cache, 2)
			tc2.reprobeInterval = testReprobe
			tc2.start(t)

			reject := func(q rtrtest.Query) {
				t.Helper()
				if q.Type != rtrtest.PDUResetQuery || q.Version != 2 {
					t.Fatalf("query type %d at version %d, want a Reset Query at version 2", q.Type, q.Version)
				}
				q.Conn.Send(rtrtest.ErrorReport(tc.errorPDUv, 4, "Unsupported Protocol Version"))
				q.Conn.Close()
			}

			reject(cache.Next(5 * time.Second))
			q := cache.Next(5 * time.Second)
			if q.Type != rtrtest.PDUResetQuery || q.Version != 1 {
				t.Fatalf("after the rejection: query type %d at version %d, want a Reset Query at version 1", q.Type, q.Version)
			}
			session := q.Conn
			session.Send(rtrtest.CacheResponse(1, 7), rtrtest.IPv4Prefix(1, true, testPrefix, 24, 65000),
				rtrtest.EndOfData(1, 7, 1, 3600, 600, 7200))
			tc2.synced(t)
			if got := rtrtest.Gauge("raven_rtr_protocol_version", cache.Addr()); got != 1 {
				t.Fatalf("raven_rtr_protocol_version = %v after the sync, want 1", got)
			}

			// Three re-probe intervals. Every query is a version 2 probe on
			// a new connection, which the cache rejects; the version 1
			// session is never torn down and nothing else is asked.
			for probe := 1; probe <= 3; probe++ {
				q := cache.Next(3 * time.Second)
				if q.Conn == session {
					t.Fatalf("probe %d: query type %d on the version 1 session, want a probe on a new connection", probe, q.Type)
				}
				reject(q)
			}
			// Stop short of the next probe: no query at all in between.
			cache.None(testReprobe/2, "between re-probes: the client should stay on its version 1 session")
			if got := rtrtest.Gauge("raven_rtr_protocol_version", cache.Addr()); got != 1 {
				t.Errorf("raven_rtr_protocol_version = %v, want still 1", got)
			}
			if n := strings.Count(tc2.logs.String(), "RTR session established"); n != 1 {
				t.Errorf("%d sessions established, want 1 (the version 1 session, kept); logs:\n%s", n, tc2.logs)
			}
			if n := strings.Count(tc2.logs.String(), "downgrading"); n != 1 {
				t.Errorf("%d downgrades, want 1; logs:\n%s", n, tc2.logs)
			}
		})
	}
}
