package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
)

// bindForTest runs bindListeners with cfg and returns the log it wrote; the
// listeners are closed when the test ends.
func bindForTest(t *testing.T, cfg *config.Config) string {
	t.Helper()
	var logs syncBuffer
	s, err := New(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	if err := s.bindListeners(ctx, &wg); err != nil {
		cancel()
		t.Fatal(err)
	}
	wg.Add(1)
	go func() { defer wg.Done(); s.bmpListen.Start(ctx) }() // closes it on cancel, as in Run
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return logs.String()
}

// listenerAddr returns the address one "listeners bound" field reports.
func listenerAddr(t *testing.T, logs, name string) string {
	t.Helper()
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, `msg="listeners bound"`) {
			continue
		}
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, name+"="); ok {
				return v
			}
		}
	}
	t.Fatalf("no %s in the listeners line:\n%s", name, logs)
	return ""
}

// The API binds loopback by default. The default port may be taken on the
// test host; the default address is checked either way.
func TestAPIDefaultBindsLoopback(t *testing.T) {
	if got := APIListen(&config.Config{}); got != "127.0.0.1:11020" {
		t.Fatalf("default API address %q, want 127.0.0.1:11020", got)
	}
	if ln, err := net.Listen("tcp", "127.0.0.1:11020"); err != nil {
		t.Skipf("127.0.0.1:11020 is in use here (%v); the default address was checked", err)
	} else {
		ln.Close()
	}
	logs := bindForTest(t, &config.Config{BMP: config.BMPConfig{Listen: "127.0.0.1:0"}})
	api := listenerAddr(t, logs, "api")
	if api != "127.0.0.1:11020" {
		t.Errorf("API bound %s, want 127.0.0.1:11020", api)
	}
}

// An explicit api.listen is honoured, and every listener is in the one
// startup line with its bound address.
func TestExplicitAPIListenAndListenersLine(t *testing.T) {
	cfg := &config.Config{
		BMP:     config.BMPConfig{Listen: "127.0.0.1:0"},
		API:     config.APIConfig{Listen: "0.0.0.0:0"},
		Outputs: config.OutputsConfig{Prometheus: &config.PrometheusOutput{Listen: "127.0.0.1:0", Path: "/metrics"}},
		Debug:   config.DebugConfig{Pprof: config.PprofConfig{Listen: "127.0.0.1:0"}},
	}
	logs := bindForTest(t, cfg)
	if n := strings.Count(logs, `msg="listeners bound"`); n != 1 {
		t.Fatalf("%d listeners lines, want 1:\n%s", n, logs)
	}
	api := listenerAddr(t, logs, "api")
	if !strings.HasPrefix(api, "0.0.0.0:") && !strings.HasPrefix(api, "[::]:") {
		t.Errorf("API bound %s, want the configured 0.0.0.0", api)
	}
	for _, name := range []string{"bmp", "metrics", "pprof"} {
		if a := listenerAddr(t, logs, name); !strings.HasPrefix(a, "127.0.0.1:") || strings.HasSuffix(a, ":0") {
			t.Errorf("%s bound %q, want a resolved 127.0.0.1 port", name, a)
		}
	}
	_, port, _ := net.SplitHostPort(api)
	resp, err := http.Get("http://127.0.0.1:" + port + "/api/v1/routes")
	if err != nil {
		t.Fatalf("API not serving on %s: %v", api, err)
	}
	resp.Body.Close()
}

// A BMP listener on all interfaces with no allowlist warns at startup.
func TestOpenBMPWarnsAtStartup(t *testing.T) {
	logs := bindForTest(t, &config.Config{BMP: config.BMPConfig{Listen: "0.0.0.0:0"}, API: config.APIConfig{Listen: "127.0.0.1:0"}})
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "bmp.allowed-routers") {
		t.Errorf("no startup warning for an open BMP listener:\n%s", logs)
	}
}
