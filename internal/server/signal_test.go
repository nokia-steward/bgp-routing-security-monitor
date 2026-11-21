//go:build unix

package server

import (
	"io"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

// #82: SIGHUP shuts raven serve down as SIGTERM does: Run returns and the
// shutdown snapshots are written. Go's default would exit at once.
func TestRunSIGHUPShutsDownCleanly(t *testing.T) {
	cache := rtrtest.NewServer(t, rtrtest.ServerConfig{MaxVersion: 2, Session: 9, Refresh: 3600, Retry: 600, Expire: 7200})
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.BMP.Listen = "127.0.0.1:0"
	cfg.API.Listen = "127.0.0.1:0"
	cfg.RTR.Caches = []config.RTRCacheConfig{{Address: cache.Addr()}}
	cfg.RTR.RTRVersion = "auto"
	cfg.Persistence = config.PersistenceConfig{Enabled: true, SnapshotDir: dir, StaleEvictionTimeout: time.Hour}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	select {
	case <-s.listening:
	case err := <-done:
		t.Fatalf("serve stopped before listening: %v", err)
	case <-time.After(testWaitBound):
		t.Fatal("serve did not bind its listeners")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after SIGHUP: %v", err)
		}
	case <-time.After(testWaitBound):
		t.Fatal("serve did not stop after SIGHUP")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Errorf("snapshot dir after SIGHUP: %v, %d files, want the shutdown snapshots", err, len(entries))
	}
}
