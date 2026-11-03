package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/config"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes slog makes
// from the server goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newPprofTestServer returns a Server carrying only what startPprof needs,
// with its log captured.
func newPprofTestServer(listen string) (*Server, *syncBuffer) {
	logs := &syncBuffer{}
	cfg := &config.Config{Debug: config.DebugConfig{Pprof: config.PprofConfig{Listen: listen}}}
	return &Server{cfg: cfg, log: slog.New(slog.NewTextHandler(logs, nil))}, logs
}

// checkCPUProfile fails the test unless body is a complete gzipped CPU
// profile, as go tool pprof reads it.
func checkCPUProfile(t *testing.T, body []byte) {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("CPU profile is not gzipped (%d bytes): %v", len(body), err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("CPU profile is truncated (%d bytes): %v", len(body), err)
	}
	if !bytes.Contains(raw, []byte("nanoseconds")) {
		t.Fatalf("CPU profile (%d bytes decompressed) carries no cpu/nanoseconds sample type", len(raw))
	}
}

// waitGroupDone fails the test if wg does not drain within d.
func waitGroupDone(t *testing.T, wg *sync.WaitGroup, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("pprof server did not stop within %v of cancellation", d)
	}
}

func TestPprofDisabledWhenListenEmpty(t *testing.T) {
	s, logs := newPprofTestServer("")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	if addr := s.startPprof(ctx, &wg); addr != nil {
		t.Fatalf("startPprof with empty listen returned %v, want nil", addr)
	}
	// Nothing was registered on wg: Wait must return without cancellation.
	waitGroupDone(t, &wg, time.Second)
	if strings.Contains(logs.String(), "pprof") {
		t.Fatalf("disabled pprof logged something:\n%s", logs)
	}
}

func TestPprofServesProfilesWhenConfigured(t *testing.T) {
	s, logs := newPprofTestServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	addr := s.startPprof(ctx, &wg)
	if addr == nil {
		t.Fatalf("startPprof returned nil; logs:\n%s", logs)
	}
	base := "http://" + addr.String()

	get := func(path string) (*http.Response, []byte) {
		t.Helper()
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("GET %s: reading body: %v", path, err)
		}
		return resp, body
	}

	// The proto profiles go tool pprof reads are gzip-compressed.
	for _, path := range []string{"/debug/pprof/heap", "/debug/pprof/allocs"} {
		resp, body := get(path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200: %s", path, resp.StatusCode, body)
		}
		if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
			t.Fatalf("GET %s: body is not a gzipped profile (%d bytes)", path, len(body))
		}
	}

	resp, body := get("/debug/pprof/goroutine?debug=1")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "goroutine profile:") {
		t.Fatalf("GET goroutine?debug=1 = %d, want 200 with a text profile:\n%s", resp.StatusCode, body)
	}

	resp, body = get("/debug/pprof/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "heap") {
		t.Fatalf("GET index = %d, want 200 listing heap:\n%s", resp.StatusCode, body)
	}

	if resp, _ := get("/debug/pprof/nosuchprofile"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET unknown profile = %d, want 404", resp.StatusCode)
	}

	out := logs.String()
	if !strings.Contains(out, `msg="pprof endpoint started"`) || !strings.Contains(out, "addr="+addr.String()) {
		t.Fatalf("missing INFO start line with addr=%s:\n%s", addr, out)
	}
	if strings.Contains(out, "level=WARN") {
		t.Fatalf("loopback listener logged a warning:\n%s", out)
	}

	cancel()
	waitGroupDone(t, &wg, 2*time.Second)
	if conn, err := net.DialTimeout("tcp", addr.String(), time.Second); err == nil {
		conn.Close()
		t.Fatalf("pprof listener %s still accepting after shutdown", addr)
	}
}

// A CPU profile holds its request open for seconds= seconds. Shutdown must
// neither wait for it nor leave CPU profiling switched on behind it, and the
// caller still gets the (short) profile collected so far.
func TestPprofShutdownEndsInFlightCPUProfile(t *testing.T) {
	s, logs := newPprofTestServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	addr := s.startPprof(ctx, &wg)
	if addr == nil {
		t.Fatalf("startPprof returned nil; logs:\n%s", logs)
	}

	// The handler flushes its 200 only once profiling is running, so when
	// Get returns the profile is known to be in flight.
	resp, err := http.Get("http://" + addr.String() + "/debug/pprof/profile?seconds=60")
	if err != nil {
		t.Fatalf("GET profile: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET profile = %d, want 200: %s", resp.StatusCode, body)
	}

	start := time.Now()
	cancel()
	waitGroupDone(t, &wg, 2*time.Second)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading profile cut short by shutdown: %v (%d bytes)", err, len(body))
	}
	checkCPUProfile(t, body)

	// Once the handler has noticed, the process-wide CPU profiler is free.
	deadline := time.Now().Add(2 * time.Second)
	for pprof.StartCPUProfile(io.Discard) != nil {
		if time.Now().After(deadline) {
			t.Fatalf("CPU profiling still on %v after shutdown; the 60s profile outlived the server", time.Since(start))
		}
		time.Sleep(10 * time.Millisecond)
	}
	pprof.StopCPUProfile()
}

// A profile that runs to its seconds= end arrives whole. Only one CPU profile
// can run per process, so a second request while one is running must get an
// error status rather than a 200 with an empty body.
func TestPprofCPUProfile(t *testing.T) {
	s, logs := newPprofTestServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	addr := s.startPprof(ctx, &wg)
	if addr == nil {
		t.Fatalf("startPprof returned nil; logs:\n%s", logs)
	}
	url := "http://" + addr.String() + "/debug/pprof/profile?seconds=0.2"

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET profile: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading profile: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET profile = %d, want 200: %s", resp.StatusCode, body)
	}
	checkCPUProfile(t, body)

	if err := pprof.StartCPUProfile(io.Discard); err != nil {
		t.Fatalf("CPU profiling still on after the profile was served: %v", err)
	}
	resp, err = http.Get(url)
	pprof.StopCPUProfile()
	if err != nil {
		t.Fatalf("GET profile while one is running: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET profile while one is running = %d, want 500: %s", resp.StatusCode, body)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		t.Fatalf("error response still offers a download: Content-Disposition %q", cd)
	}

	cancel()
	waitGroupDone(t, &wg, 2*time.Second)
}

// profilerOwnedWriter is a ResponseWriter that records any Write made from the
// runtime's CPU profile writer goroutine.
type profilerOwnedWriter struct {
	*httptest.ResponseRecorder
	fromProfiler atomic.Bool
}

func (w *profilerOwnedWriter) Write(p []byte) (int, error) {
	buf := make([]byte, 64<<10)
	if strings.Contains(string(buf[:runtime.Stack(buf, false)]), "runtime/pprof.profileWriter") {
		w.fromProfiler.Store(true)
	}
	return w.ResponseRecorder.Write(p)
}

// The handler flushes the response while the CPU profile runs, and an
// http.ResponseWriter is not safe for concurrent use, so the profiler's
// writer goroutine must never be handed w itself. The race detector only
// sees that when the two goroutines happen to overlap; this sees it every
// time.
func TestPprofCPUProfileDoesNotShareResponseWriter(t *testing.T) {
	w := &profilerOwnedWriter{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodGet, "/debug/pprof/profile?seconds=0.2", nil)
	pprofCPUProfile(w, r, nil)

	if w.fromProfiler.Load() {
		t.Fatal("the CPU profile writer goroutine wrote to the http.ResponseWriter directly")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body)
	}
	checkCPUProfile(t, w.Body.Bytes())
}

func TestPprofWarnsWhenExposedBeyondLoopback(t *testing.T) {
	for _, tc := range []struct {
		listen   string
		wantWarn bool
	}{
		{"127.0.0.1:0", false},
		{"localhost:0", false},
		{":0", true}, // empty host binds every interface
		{"0.0.0.0:0", true},
	} {
		t.Run(tc.listen, func(t *testing.T) {
			s, logs := newPprofTestServer(tc.listen)
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			addr := s.startPprof(ctx, &wg)
			cancel()
			waitGroupDone(t, &wg, 2*time.Second)
			if addr == nil {
				t.Fatalf("startPprof(%q) returned nil; logs:\n%s", tc.listen, logs)
			}
			out := logs.String()
			gotWarn := strings.Contains(out, "level=WARN") && strings.Contains(out, "exposed beyond localhost")
			if gotWarn != tc.wantWarn {
				t.Fatalf("listen %q (bound %s): warning logged = %v, want %v:\n%s", tc.listen, addr, gotWarn, tc.wantWarn, out)
			}
		})
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.10.20.30", true},
		{"::1", true},
		{"0.0.0.0", false},
		{"::", false},
		{"10.0.0.1", false},
		{"192.0.2.1", false},
		{"2001:db8::1", false},
	} {
		addr := &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 6060}
		if got := isLoopbackAddr(addr); got != tc.want {
			t.Errorf("isLoopbackAddr(%s) = %v, want %v", addr, got, tc.want)
		}
	}
}

// A port that is already taken must not stop the daemon: startPprof logs
// and carries on with pprof off.
func TestPprofListenFailureIsNotFatal(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	s, logs := newPprofTestServer(taken.Addr().String())
	var wg sync.WaitGroup
	if addr := s.startPprof(context.Background(), &wg); addr != nil {
		t.Fatalf("startPprof on a taken port returned %v, want nil", addr)
	}
	waitGroupDone(t, &wg, time.Second)
	if !strings.Contains(logs.String(), "failed to start pprof endpoint") {
		t.Fatalf("listen failure not logged:\n%s", logs)
	}
}

// Linking net/http/pprof, directly or through a dependency, registers
// profiling on http.DefaultServeMux in init() regardless of config. This test
// binary links everything the server package does, so a stray import fails
// here.
func TestPprofNotRegisteredOnDefaultServeMux(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/heap", nil)
	if _, pattern := http.DefaultServeMux.Handler(req); pattern != "" {
		t.Fatalf("http.DefaultServeMux serves /debug/pprof/heap via pattern %q; something imports net/http/pprof", pattern)
	}
}
