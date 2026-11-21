package cli

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/bmp/bmptest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/server"
)

// #81: raven watch reconnects when its stream ends, says so on stderr, and
// keeps stdout for events.

const watchWait = 15 * time.Second

// freeAddr returns a 127.0.0.1 address with a port nothing listens on, so
// serve can be started (and restarted) there.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// watchServe is raven serve in-process (demo VRPs, no RTR cache) with its
// API and BMP listener at fixed addresses, and a fake router feeding it.
type watchServe struct {
	t      *testing.T
	feed   *bmptest.Feed
	peer   bmptest.Peer
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

func startWatchServe(t *testing.T, apiAddr, bmpAddr string) *watchServe {
	t.Helper()
	cfg := &config.Config{}
	cfg.API.Listen = apiAddr
	cfg.BMP.Listen = bmpAddr
	cfg.Validation.ROV = true
	cfg.Validation.ASPA = true
	cfg.Validation.ASPADefaultProcedure = "upstream"
	s, err := server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.SetDemoMode(true)
	ctx, cancel := context.WithCancel(context.Background())
	h := &watchServe{t: t, cancel: cancel, done: make(chan error, 1)}
	go func() { h.done <- s.RunContext(ctx) }()
	t.Cleanup(h.stop)
	waitFor(t, "serve's API at "+apiAddr, func() bool {
		resp, err := http.Get("http://" + apiAddr + "/api/v1/status")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	h.feed = bmptest.Dial(t, bmpAddr)
	h.feed.Initiation("watch-test")
	h.peer = bmptest.Peer{Addr: netip.MustParseAddr("198.18.0.1"), ASN: 64501, BGPID: netip.MustParseAddr("198.18.0.1")}
	h.feed.PeerUp(h.peer)
	return h
}

func (h *watchServe) announce(prefix string) {
	h.feed.Announce(h.peer, bmptest.Route{Prefix: netip.MustParsePrefix(prefix), ASPath: []uint32{64501, 64502}})
}

// stop shuts serve down and waits until it has.
func (h *watchServe) stop() {
	h.once.Do(func() {
		h.cancel()
		select {
		case err := <-h.done:
			if err != nil {
				h.t.Errorf("serve: %v", err)
			}
		case <-time.After(watchWait):
			h.t.Error("serve did not stop")
		}
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(watchWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// watchRun is raven watch running against addr.
type watchRun struct {
	stdout, stderr lockedBuffer
	cancel         context.CancelFunc
	done           chan error
}

// startWatch runs raven watch with args against addr until stopped.
func startWatch(t *testing.T, addr string, args ...string) *watchRun {
	t.Helper()
	w := &watchRun{done: make(chan error, 1)}
	cmd := newWatchCmd(&addr)
	cmd.SetArgs(args)
	cmd.SetOut(&w.stdout)
	cmd.SetErr(&w.stderr)
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	go func() { w.done <- cmd.ExecuteContext(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-w.done:
		case <-time.After(watchWait):
			t.Error("watch did not exit when cancelled")
		}
	})
	return w
}

// stderrHas waits until stderr has a line containing s.
func (w *watchRun) stderrHas(t *testing.T, s string) {
	t.Helper()
	waitFor(t, "a stderr line with "+s, func() bool { return strings.Contains(w.stderr.String(), s) })
}

// wait returns watch's result, failing if it takes longer than within.
func (w *watchRun) wait(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case err := <-w.done:
		w.done <- err // for the cleanup
		return err
	case <-time.After(within):
		t.Fatalf("watch still running after %v; stderr:\n%s", within, w.stderr.String())
		return nil
	}
}

func countLines(s, sub string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// eventsOnly fails unless every stdout line is a watch event.
func eventsOnly(t *testing.T, stdout string) {
	t.Helper()
	for _, l := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if l != "" && !strings.HasPrefix(l, "[") {
			t.Errorf("stdout line %q is not an event", l)
		}
	}
}

// Serve restarts under a running raven watch: watch says the stream ended,
// reconnects, says how long it was away and that nothing was replayed, and
// prints what serve sends after the restart.
func TestWatchReconnectsAfterServeRestart(t *testing.T) {
	apiAddr, bmpAddr := freeAddr(t), freeAddr(t)
	h := startWatchServe(t, apiAddr, bmpAddr)
	w := startWatch(t, apiAddr)
	w.stderrHas(t, "watching for route events")
	h.announce("203.0.113.0/24")
	waitFor(t, "the first event", func() bool { return strings.Contains(w.stdout.String(), "203.0.113.0/24") })

	h.stop()
	w.stderrHas(t, "stream ended")
	h2 := startWatchServe(t, apiAddr, bmpAddr)
	w.stderrHas(t, "reconnected")
	h2.announce("198.51.100.0/24")
	waitFor(t, "the event after the restart", func() bool { return strings.Contains(w.stdout.String(), "198.51.100.0/24") })

	w.cancel()
	if err := w.wait(t, 2*time.Second); err != nil {
		t.Errorf("watch: %v, want nil on cancel", err)
	}
	stderr := w.stderr.String()
	t.Logf("stderr:\n%s", stderr)
	if countLines(stderr, "stream ended") != 1 || countLines(stderr, "reconnected") != 1 {
		t.Errorf("stderr, want one stream ended and one reconnected line:\n%s", stderr)
	}
	if !strings.Contains(stderr, "events during the gap were not replayed") ||
		!strings.Contains(stderr, "reconnected to "+apiAddr+" after ") {
		t.Errorf("reconnected line without the gap:\n%s", stderr)
	}
	eventsOnly(t, w.stdout.String())
}

// A first connect to nothing is retried, the failure printed once however
// often it repeats; once serve starts, watch connects and streams.
func TestWatchRetriesFirstConnect(t *testing.T) {
	defer func(b struct{ least, most time.Duration }) { watchBackoff = b }(watchBackoff)
	watchBackoff.least, watchBackoff.most = 10*time.Millisecond, 20*time.Millisecond
	apiAddr, bmpAddr := freeAddr(t), freeAddr(t)
	w := startWatch(t, apiAddr)
	w.stderrHas(t, "cannot connect")
	time.Sleep(300 * time.Millisecond) // a dozen more failed tries
	h := startWatchServe(t, apiAddr, bmpAddr)
	w.stderrHas(t, "watching for route events")
	h.announce("203.0.113.0/24")
	waitFor(t, "the event", func() bool { return strings.Contains(w.stdout.String(), "203.0.113.0/24") })
	stderr := w.stderr.String()
	if countLines(stderr, "cannot connect") != 1 || !strings.Contains(stderr, "connected to "+apiAddr+" after ") {
		t.Errorf("stderr, want one cannot connect line (repeats not printed) and the connected line:\n%s", stderr)
	}
	eventsOnly(t, w.stdout.String())
}

// --once does not retry: a first connect that fails, or a stream that ends,
// is an error (exit non-zero) with the reason; Ctrl+C is not.
func TestWatchOnce(t *testing.T) {
	apiAddr, bmpAddr := freeAddr(t), freeAddr(t)
	w := startWatch(t, apiAddr, "--once")
	err := w.wait(t, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "connect to daemon at "+apiAddr) {
		t.Errorf("--once against nothing: %v, want the connect error", err)
	}

	h := startWatchServe(t, apiAddr, bmpAddr)
	w = startWatch(t, apiAddr, "--once")
	w.stderrHas(t, "watching for route events")
	h.stop()
	err = w.wait(t, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "watch stream from "+apiAddr+" ended") {
		t.Errorf("--once, serve stopped: %v, want the stream-ended error", err)
	}
	if strings.Contains(w.stderr.String(), "reconnect") || w.stdout.String() != "" {
		t.Errorf("--once retried or wrote to stdout:\nstdout %q\nstderr %q", w.stdout.String(), w.stderr.String())
	}

	startWatchServe(t, apiAddr, bmpAddr)
	w = startWatch(t, apiAddr, "--once")
	w.stderrHas(t, "watching for route events")
	w.cancel()
	if err := w.wait(t, 2*time.Second); err != nil {
		t.Errorf("--once, cancelled: %v, want nil", err)
	}
}

// The filters are sent, unchanged, on every reconnect.
func TestWatchResendsFiltersOnReconnect(t *testing.T) {
	defer func(b struct{ least, most time.Duration }) { watchBackoff = b }(watchBackoff)
	watchBackoff.least, watchBackoff.most = 10*time.Millisecond, 20*time.Millisecond
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()
		io.WriteString(w, `data: {"prefix":"1.1.1.0/24","peer":"192.0.2.1","origin_asn":13335,"posture":"secured"}`+"\n\n")
	}))
	defer srv.Close()
	w := startWatch(t, strings.TrimPrefix(srv.URL, "http://"), "--prefix", "1.1.1.0/24", "--origin-asn", "13335",
		"--peer", "80.81.194.180", "--posture", "secured", "--afi", "ipv4", "--router", "br1.nyc", "--rib", "loc-rib")
	waitFor(t, "three connects", func() bool { mu.Lock(); defer mu.Unlock(); return len(queries) >= 3 })
	w.cancel()
	w.wait(t, 2*time.Second)
	want := "afi=ipv4&origin-asn=13335&peer=80.81.194.180&posture=secured&prefix=1.1.1.0%2F24&rib=loc-rib&router=br1.nyc"
	mu.Lock()
	defer mu.Unlock()
	for i, q := range queries {
		if q != want {
			t.Errorf("connect %d query %q, want %q", i, q, want)
		}
	}
}

// A 4xx (a bad filter) is not retried: the daemon would refuse again.
func TestWatchRefusedIsNotRetried(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Error(w, "invalid prefix", http.StatusBadRequest)
	}))
	defer srv.Close()
	w := startWatch(t, strings.TrimPrefix(srv.URL, "http://"), "--prefix", "nonsense")
	err := w.wait(t, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "400 Bad Request: invalid prefix") {
		t.Errorf("watch: %v, want the 400", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("%d connects, want 1", calls)
	}
}

// The wait doubles from 1 s to a 30 s cap, never more, less at most a
// fifth of jitter, and starts again from 1 s after a reset.
func TestWatchBackoffIsCapped(t *testing.T) {
	b := backoff{least: time.Second, most: 30 * time.Second}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30, 30, 30, 30, 30}
	for round := range 2 {
		for i, w := range want {
			w *= time.Second
			got := b.next()
			if got > w || got < w*4/5 {
				t.Errorf("round %d, wait %d: %v, want within [%v, %v]", round, i, got, w*4/5, w)
			}
		}
		b.reset()
	}
	for range 10_000 {
		if got := b.next(); got > 30*time.Second {
			t.Fatalf("wait %v over the 30 s cap", got)
		}
	}
}
