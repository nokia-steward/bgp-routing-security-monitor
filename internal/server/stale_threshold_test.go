package server

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// rtr.stale-threshold, from the config file through config.Load and New,
// wins over the threshold raven serve learns: 3h (configured), where 30
// gaps of 15 minutes learn 1h. serve keeps no gap history across restarts,
// so there is nothing seeded to win over.
func TestServeStaleThresholdWinsOverLearned(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	path := filepath.Join(t.TempDir(), "raven.yaml")
	if err := os.WriteFile(path, []byte("rtr:\n  stale-threshold: 3h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	config.ConfigureEnv()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.BMP.Listen = "127.0.0.1:0"
	cfg.API.Listen = "127.0.0.1:0"
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	const cache = "fort.example.net:323"
	learned := telemetry.NewDataTracker()
	at := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	for i := range 31 {
		ev := telemetry.SessionEvent{Timestamp: at.Add(time.Duration(i) * 15 * time.Minute), Cache: cache,
			EventType: telemetry.EventSync, SyncType: telemetry.SyncTypeIncremental, DataFingerprint: fmt.Sprintf("%032d", i)}
		s.observeData(ev)
		learned.Observe(ev)
	}
	if thr, src, _ := learned.Threshold(cache); thr != time.Hour || src != telemetry.ThresholdLearned {
		t.Fatalf("the syncs learn %v (%s), want 1h learned", thr, src)
	}
	if thr, src, n := s.data.Threshold(cache); thr != 3*time.Hour || src != telemetry.ThresholdConfigured || n != 30 {
		t.Errorf("rtr.stale-threshold 3h: %v (%s, %d gaps), want 3h (configured, 30 gaps)", thr, src, n)
	}
}
