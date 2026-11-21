package server

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

// In raven serve, every completed RTR sync records the cache as synced, but
// only one that changed the data requests a revalidation pass: a refresh
// poll that finds the serial unchanged must not cost a pass over the table.
func TestRTRPollWithUnchangedSerialRequestsNoRevalidation(t *testing.T) {
	s := newTestServer(t)
	cache := rtrtest.NewCache(t)
	addr := cache.Addr()
	client, err := rtr.NewClient(addr, "tcp", nil, s.vrpStore, s.aspaStore, 2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.wireRTRClient(client, addr)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.Start(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	// No ingest loop runs, so requests stay queued for the test to count.

	lastSync := func() int64 {
		s.rtrMu.RLock()
		defer s.rtrMu.RUnlock()
		return s.rtrLastSync[addr]
	}
	waitSynced := func(what string) {
		t.Helper()
		waitUntil(t, what, func() bool { return lastSync() != 0 })
	}
	clearSynced := func() {
		s.rtrMu.Lock()
		s.rtrLastSync[addr] = 0
		s.rtrMu.Unlock()
	}

	q := cache.Next(5 * time.Second)
	conn := q.Conn
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 65000),
		rtrtest.EndOfData(2, 7, 5, 1, 600, 7200)) // refresh after 1s
	waitSynced("the first sync")
	if n := len(s.revalidateCh); n != 1 {
		t.Fatalf("%d revalidation requests after the first sync, want 1", n)
	}
	<-s.revalidateCh
	clearSynced()

	q = cache.Next(5 * time.Second) // the refresh poll
	if q.Type != rtrtest.PDUSerialQuery || q.Serial != 5 {
		t.Fatalf("got query type %d serial %d, want a refresh poll from serial 5", q.Type, q.Serial)
	}
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.EndOfData(2, 7, 5, 1, 600, 7200))
	waitSynced("the unchanged poll's sync")
	if n := len(s.revalidateCh); n != 0 {
		t.Errorf("%d revalidation requests after a poll with an unchanged serial, want 0", n)
	}
	clearSynced()

	q = cache.Next(5 * time.Second)
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("198.51.100.0/24"), 24, 65001),
		rtrtest.EndOfData(2, 7, 6, 1, 600, 7200))
	waitSynced("the changed poll's sync")
	if n := len(s.revalidateCh); n != 1 {
		t.Errorf("%d revalidation requests after a poll that changed the data, want 1", n)
	}
}

// The Expire Interval in effect is logged once at startup: the configured
// rtr.expire-interval, clamped (with a WARN) to RFC 8210's range, or each
// cache's own when unset.
func TestLogExpireInterval(t *testing.T) {
	for _, tc := range []struct {
		configured int
		want       uint32
		log        string
	}{
		{0, 0, `level=INFO msg="RTR expire interval: each cache's own (End of Data)"`},
		{3600, 3600, `level=INFO msg="RTR expire interval: rtr.expire-interval overrides each cache's" expire_interval=3600`},
		{60, 600, `level=WARN msg="rtr.expire-interval outside RFC 8210's 600-172800 s; clamped" configured=60 expire_interval=600`},
	} {
		var buf strings.Builder
		got := logExpireInterval(slog.New(slog.NewTextHandler(&buf, nil)), tc.configured)
		if got != tc.want || !strings.Contains(buf.String(), tc.log) {
			t.Errorf("configured %d: override %d, log %q; want %d and %q", tc.configured, got, buf.String(), tc.want, tc.log)
		}
	}
}

// raven serve builds each RTR client with rtr.expire-interval applied:
// clamped when set, the default (then each cache's) when unset.
func TestRTRClientGetsExpireOverride(t *testing.T) {
	s := newTestServer(t)
	for _, tc := range []struct {
		configured int
		want       uint32
	}{{0, 7200}, {3600, 3600}, {60, 600}} {
		eff, _ := rtr.ExpireOverride(tc.configured)
		client, err := s.newRTRClient(config.RTRCacheConfig{Address: "127.0.0.1:3323"}, eff)
		if err != nil {
			t.Fatal(err)
		}
		if got := client.ExpireInterval(); got != tc.want {
			t.Errorf("rtr.expire-interval %d: client expire interval %d, want %d", tc.configured, got, tc.want)
		}
	}
}
