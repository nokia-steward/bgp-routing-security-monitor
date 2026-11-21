//go:build unix

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// #82: SIGHUP (a closed terminal, a lost SSH session, tmux kill-session)
// shuts raven rtr monitor down as SIGTERM does: the session ends with a
// disconnected (shutdown) record and the final --anomaly-snapshot is
// written. Go's default would exit at once, with neither.
//
// #80 too: the log file already holds an earlier run's records and there
// is no snapshot, so the gap history is seeded from the log at startup;
// the snapshot written at shutdown carries it.
func TestMonitorSIGHUPShutsDownCleanly(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(2))
	srv.SetData(rtrtest.GenVRPs(0, 3, 65001), nil)
	dir := t.TempDir()
	logFile := filepath.Join(dir, "rtr-telemetry.ndjson")
	snap := filepath.Join(dir, "anomaly-baseline.json")
	earlier, err := os.ReadFile("../telemetry/testdata/anycast-node-stall-2026-11-12.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	earlier = bytes.ReplaceAll(earlier, []byte(`"rtr.rpki.cloudflare.com:8282"`), []byte(`"`+srv.Addr()+`"`))
	if err := os.WriteFile(logFile, earlier, 0o600); err != nil {
		t.Fatal(err)
	}
	_, cold, err := telemetry.SeedBaseline(bytes.NewReader(earlier))
	if err != nil {
		t.Fatal(err)
	}

	cmd := newRTRMonitorCmd()
	cmd.SetArgs([]string{"--cache", srv.Addr(), "--log-file", logFile, "--anomaly-snapshot", snap})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	deadline := time.Now().Add(30 * time.Second)
	for {
		b, _ := os.ReadFile(logFile)
		if bytes.Contains(b[len(earlier):], []byte(`"event_type":"sync"`)) {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("monitor stopped before its first sync: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sync record within 30s; log:\n%s", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(snap); !os.IsNotExist(err) {
		t.Fatalf("snapshot before the signal: %v, want none yet", err)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("monitor after SIGHUP: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("monitor did not stop within 30s of SIGHUP")
	}

	f, err := os.Open(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var last map[string]any
	for sc := bufio.NewScanner(f); sc.Scan(); {
		last = nil
		if err := json.Unmarshal(sc.Bytes(), &last); err != nil {
			t.Fatalf("NDJSON %q: %v", sc.Text(), err)
		}
	}
	if last["event_type"] != "disconnected" || last["disconnect_reason"] != "shutdown" {
		t.Errorf("last record %v, want disconnected (shutdown)", last)
	}
	raw, err := os.ReadFile(snap)
	if err != nil {
		t.Fatalf("no anomaly snapshot after SIGHUP: %v", err)
	}
	var file struct {
		SchemaVersion int `json:"schema_version"`
		DataGaps      map[string]struct {
			Pos    int  `json:"pos"`
			Filled bool `json:"filled"`
		} `json:"data_gaps"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || file.SchemaVersion != 1 {
		t.Fatalf("anomaly snapshot: %v, schema_version %d", err, file.SchemaVersion)
	}
	// The live session's first sync adds no gap: the history is the
	// seeded one.
	if g := file.DataGaps[srv.Addr()]; g.Filled || g.Pos != cold.DataGaps[0].Gaps || g.Pos == 0 {
		t.Errorf("snapshot data_gaps %+v, want the %d gaps seeded from the log", g, cold.DataGaps[0].Gaps)
	}
}
