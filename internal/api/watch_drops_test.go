package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

type syncBuffer struct {
	ch chan string
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.ch <- string(p)
	return len(p), nil
}

func droppedTotal(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		if mf.GetName() == "raven_watch_events_dropped_total" {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	return 0
}

// A watcher that does not read loses events once its buffer is full: each
// one counts in raven_watch_events_dropped_total, the overflow is logged
// once when it starts and once when the watcher catches up, not per event,
// and a watcher that reads, through the real watch endpoint, gets every
// event.
func TestWatchDropsAreCountedAndLoggedOncePerEpisode(t *testing.T) {
	logs := &syncBuffer{ch: make(chan string, 100)}
	s := NewServer(routetable.New(), nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(logs, nil)), "test")

	// The reading watcher, through /api/v1/watch.
	srv := httptest.NewServer(s.Mux())
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/watch", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := make(chan string, 10_000)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var rr RouteResponse
				if json.Unmarshal([]byte(line), &rr) == nil {
					got <- rr.Prefix
				}
			}
		}
	}()

	// The stuck watcher: a subscriber whose channel nobody reads.
	stuck := make(chan RouteResponse, 4)
	s.watchMu.Lock()
	s.watchSubs[stuck] = &watcher{}
	s.watchMu.Unlock()

	before := droppedTotal(t)
	const n = 50
	for i := range n {
		r := &types.Route{PeerAddr: netip.MustParseAddr("192.0.2.1"),
			Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i), 0}), 24), ASPath: []uint32{64500, 64501}}
		s.NotifyRouteFrom(r, "bmp")
		// Let the reading watcher's handler keep up: it is not the one
		// under test.
		select {
		case p := <-got:
			if want := r.Prefix.String(); p != want {
				t.Fatalf("reading watcher got %s, want %s", p, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("reading watcher did not get event %d", i)
		}
	}
	if d := droppedTotal(t) - before; d != n-float64(cap(stuck)) {
		t.Errorf("dropped counter rose by %v, want %d (all but the stuck watcher's buffer of %d)", d, n-cap(stuck), cap(stuck))
	}
	warn := <-logs.ch
	if !strings.Contains(warn, "level=WARN") || !strings.Contains(warn, "not reading fast enough") {
		t.Errorf("first log line %q, want the overflow WARN", warn)
	}
	select {
	case l := <-logs.ch:
		t.Fatalf("second log line during one overflow episode: %q", l)
	default:
	}

	// It catches up: one INFO with the episode's count, then a new
	// episode logs again.
	for len(stuck) > 0 {
		<-stuck
	}
	s.NotifyRouteFrom(&types.Route{PeerAddr: netip.MustParseAddr("192.0.2.1"), Prefix: netip.MustParsePrefix("10.1.0.0/24")}, "rtr")
	<-got
	if l := <-logs.ch; !strings.Contains(l, "caught up") || !strings.Contains(l, fmt.Sprintf("dropped=%d", n-cap(stuck))) {
		t.Errorf("log line %q, want caught up with dropped=%d", l, n-cap(stuck))
	}
	if rr := <-stuck; rr.Source != "rtr" {
		t.Errorf("source %q on the event, want rtr", rr.Source)
	}
}
