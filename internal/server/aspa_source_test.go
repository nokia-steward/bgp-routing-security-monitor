package server

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/validation"
)

var aspaTestPrefix = netip.MustParsePrefix("192.0.2.0/24")

// aspaTestServer is a server validating ROV, with ASPA on or off in config,
// and an RTR client asking for version 2, wired as raven serve wires it, to
// the returned fake cache. No ingest loop runs: the test applies routes and
// revalidation passes itself.
func aspaTestServer(t *testing.T, aspa bool) (*Server, *rtrtest.Cache) {
	t.Helper()
	s, err := New(&config.Config{Validation: config.ValidationConfig{ROV: true, ASPA: aspa}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cache := rtrtest.NewCache(t)
	client, err := rtr.NewClient(cache.Addr(), "tcp", nil, s.vrpStore, s.aspaStore, 2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	client.SetVersionReprobeInterval(300 * time.Millisecond)
	s.wireRTRClient(client, cache.Addr())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return s, cache
}

// syncV1 has the cache turn down version 2 and serve version 1: one VRP
// making the test prefix's origin AS64501 Valid, and no ASPA (version 1 has
// none). It returns the version 1 session's connection.
func syncV1(t *testing.T, s *Server, cache *rtrtest.Cache) *rtrtest.Conn {
	t.Helper()
	q := cache.Next(5 * time.Second)
	if q.Version != 2 {
		t.Fatalf("first query at version %d, want 2", q.Version)
	}
	q.Conn.Send(rtrtest.ErrorReport(1, 4, "Unsupported Protocol Version"))
	q.Conn.Close()
	q = cache.Next(15 * time.Second) // after the client's retry backoff (5s)
	if q.Version != 1 {
		t.Fatalf("after the rejection: query at version %d, want 1", q.Version)
	}
	q.Conn.Send(rtrtest.CacheResponse(1, 7), rtrtest.IPv4Prefix(1, true, aspaTestPrefix, 24, 64501),
		rtrtest.EndOfData(1, 7, 1, 3600, 600, 7200))
	waitSynced(t, s)
	return q.Conn
}

// waitSynced waits for the server to record a completed sync: the stores
// are complete.
func waitSynced(t *testing.T, s *Server) {
	t.Helper()
	waitUntil(t, "a recorded RTR sync", func() bool {
		s.rtrMu.RLock()
		defer s.rtrMu.RUnlock()
		return len(s.rtrLastSync) > 0
	})
}

// sendV2Sync answers a version 2 Reset Query with the VRP and an ASPA for
// AS64501.
func sendV2Sync(c *rtrtest.Conn) {
	c.Send(rtrtest.CacheResponse(2, 8), rtrtest.IPv4Prefix(2, true, aspaTestPrefix, 24, 64501),
		rtrtest.ASPA(true, 64501, 64999), rtrtest.EndOfData(2, 8, 1, 3600, 600, 7200))
}

// singleHop is a route whose AS_PATH is its origin alone: a path of one AS
// verifies as ASPA Valid whatever the ASPA data, so it shows whether ASPA ran.
func singleHop() types.Route {
	return types.Route{
		Router: routerA, PeerAddr: rsPeer, PeerASN: 64501, Prefix: aspaTestPrefix,
		ASPath: []uint32{64501}, ASPathRaw: []types.ASSegment{{Type: types.ASSegmentSequence, ASNs: []uint32{64501}}},
		RIBType: types.AdjRIBInPre,
	}
}

// revalidateNow runs the requested revalidation pass to the end, as
// ingestLoop would.
func revalidateNow(t *testing.T, s *Server) {
	t.Helper()
	select {
	case <-s.revalidateCh:
	case <-time.After(5 * time.Second):
		t.Fatal("no revalidation requested")
	}
	s.startRevalidation()
	for s.revalidating.Load() {
		s.stepBackground()
	}
}

func checkASPA(t *testing.T, s *Server, r types.Route, state types.ASPAState, reason string, posture types.SecurityPosture) {
	t.Helper()
	got := s.table.Get(r.Key())
	if got == nil {
		t.Fatal("route not in the table")
	}
	if got.ASPA.State != state || got.ASPA.Reason != reason || got.SecurityPosture != posture {
		t.Errorf("ASPA %s (%q), posture %s; want %s (%q), %s",
			got.ASPA.State, got.ASPA.Reason, got.SecurityPosture, state, reason, posture)
	}
}

// With only a version 1 RTR session there is no ASPA data: ASPA is Unknown
// with a reason, so the posture is origin-only, not secured on the strength
// of a one-AS path.
func TestASPAUnknownWithoutV2Session(t *testing.T) {
	s, cache := aspaTestServer(t, true)
	if got := s.engine.ASPAUnavailable(); got != validation.ASPAReasonNoData {
		t.Fatalf("before any sync: ASPA unavailable %q, want %q", got, validation.ASPAReasonNoData)
	}
	syncV1(t, s, cache)
	r := singleHop()
	s.ingestRoute(r, 1, 1)
	checkASPA(t, s, r, types.ASPAUnknown, validation.ASPAReasonNoData, types.PostureOriginOnly)
	if got := s.engine.ASPAUnavailable(); got != validation.ASPAReasonNoData {
		t.Errorf("after the version 1 sync: ASPA unavailable %q, want %q", got, validation.ASPAReasonNoData)
	}
}

// With a version 2 session ASPA runs: a path of one AS is Valid, secured.
func TestASPAVerifiedWithV2Session(t *testing.T) {
	s, cache := aspaTestServer(t, true)
	sendV2Sync(cache.Next(5 * time.Second).Conn)
	waitUntil(t, "ASPA on after the version 2 sync", func() bool { return s.engine.ASPAUnavailable() == "" })
	r := singleHop()
	s.ingestRoute(r, 1, 1)
	checkASPA(t, s, r, types.ASPAValid, "", types.PostureSecured)
}

// A cache that gains version 2 after a version 1 session: its first version 2
// sync turns ASPA on and revalidates the routes validated without it.
func TestASPAOnAfterUpgradeRevalidates(t *testing.T) {
	s, cache := aspaTestServer(t, true)
	session := syncV1(t, s, cache)
	r := singleHop()
	s.ingestRoute(r, 1, 1)
	checkASPA(t, s, r, types.ASPAUnknown, validation.ASPAReasonNoData, types.PostureOriginOnly)
	for len(s.revalidateCh) > 0 { // the version 1 sync's own data change
		revalidateNow(t, s)
	}

	// The re-probe at version 2 succeeds; the client reconnects at 2.
	q := cache.Next(5 * time.Second)
	if q.Version != 2 || q.Conn == session {
		t.Fatalf("got query at version %d (on the session: %v), want a version 2 re-probe", q.Version, q.Conn == session)
	}
	q.Conn.Send(rtrtest.CacheResponse(2, 8))
	q = cache.Next(5 * time.Second)
	if q.Version != 2 {
		t.Fatalf("after the re-probe: query at version %d, want 2", q.Version)
	}
	sendV2Sync(q.Conn)
	waitUntil(t, "ASPA on after the upgrade", func() bool { return s.engine.ASPAUnavailable() == "" })
	revalidateNow(t, s)
	checkASPA(t, s, r, types.ASPAValid, "", types.PostureSecured)
}

// validation.aspa false: ASPA is never run, whatever the RTR version.
func TestASPADisabled(t *testing.T) {
	s, cache := aspaTestServer(t, false)
	sendV2Sync(cache.Next(5 * time.Second).Conn)
	waitSynced(t, s)
	r := singleHop()
	s.ingestRoute(r, 1, 1)
	checkASPA(t, s, r, types.ASPAUnknown, validation.ASPAReasonDisabled, types.PostureOriginOnly)
}

// Turning ASPA on or off requests a full revalidation of its own, after the
// switch: the revalidation a version 2 sync's data requests is made before
// the sync is recorded, so a pass that took it then would run with ASPA still
// off. Repeating the same state requests nothing; with ASPA disabled nothing
// switches.
func TestASPASwitchRequestsRevalidation(t *testing.T) {
	s, err := New(&config.Config{Validation: config.ValidationConfig{ROV: true, ASPA: true}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	requested := func() bool {
		select {
		case <-s.revalidateCh:
			s.deltaMu.Lock()
			full := s.pendingDelta != nil && s.pendingDelta.Full
			s.pendingDelta = nil
			s.deltaMu.Unlock()
			if !full {
				t.Error("revalidation requested, but not of the whole table")
			}
			return true
		default:
			return false
		}
	}
	for i, step := range []struct {
		cache  string
		v2     bool
		reason string
		want   bool
	}{
		{"a", false, validation.ASPAReasonNoData, false}, // still no ASPA: nothing to redo
		{"a", true, "", true},                            // first version 2 sync: on
		{"b", false, "", false},                          // another cache at version 1: still on
		{"a", true, "", false},                           // again: no change
		{"a", false, validation.ASPAReasonNoData, true},  // the last version 2 cache falls back: off
	} {
		s.noteASPASource(step.cache, step.v2)
		if got := s.engine.ASPAUnavailable(); got != step.reason {
			t.Errorf("step %d: ASPA unavailable %q, want %q", i, got, step.reason)
		}
		if got := requested(); got != step.want {
			t.Errorf("step %d: revalidation requested %v, want %v", i, got, step.want)
		}
	}

	off, err := New(&config.Config{Validation: config.ValidationConfig{ROV: true}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	off.noteASPASource("a", true)
	if got := off.engine.ASPAUnavailable(); got != validation.ASPAReasonDisabled || len(off.revalidateCh) != 0 {
		t.Errorf("disabled: ASPA unavailable %q, %d requests; want %q and none", got, len(off.revalidateCh), validation.ASPAReasonDisabled)
	}
}
