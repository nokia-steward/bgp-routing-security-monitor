package cli

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

type dumpDoc struct {
	Metadata struct {
		Cache           string `json:"cache"`
		SessionID       uint16 `json:"sessionID"`
		Serial          uint32 `json:"serial"`
		ProtocolVersion uint8  `json:"protocolVersion"`
		DataFingerprint string `json:"dataFingerprint"`
		ASPAsAvailable  bool   `json:"aspasAvailable"`
	} `json:"metadata"`
	ROAs []struct {
		ASN       string `json:"asn"`
		Prefix    string `json:"prefix"`
		MaxLength int    `json:"maxLength"`
	} `json:"roas"`
	ASPAs *[]struct {
		Customer  string   `json:"customer"`
		Providers []string `json:"providers"`
	} `json:"aspas"`
}

// runDump runs "rtr dump" with args and returns its stdout and stderr.
func runDump(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newRTRDumpCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestRTRDumpVersion2(t *testing.T) {
	cache := rtrtest.NewCache(t)
	go func() {
		q := cache.Next(5 * time.Second)
		q.Conn.Send(
			rtrtest.CacheResponse(2, 777),
			rtrtest.IPv6Prefix(2, true, netip.MustParsePrefix("2001:db8::/32"), 48, 64500),
			rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 64501),
			rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 64500),
			rtrtest.ASPA(true, 64511, 3356, 174, 0),
			rtrtest.EndOfData(2, 777, 42, 3600, 600, 7200),
		)
	}()

	out, errOut, err := runDump(t, "--cache", cache.Addr(), "--timeout", "10s")
	if err != nil {
		t.Fatalf("dump: %v\n%s", err, errOut)
	}
	var d dumpDoc
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	m := d.Metadata
	if m.Cache != cache.Addr() || m.SessionID != 777 || m.Serial != 42 || m.ProtocolVersion != 2 || !m.ASPAsAvailable {
		t.Fatalf("metadata: %+v", m)
	}
	if len(m.DataFingerprint) != 32 {
		t.Fatalf("fingerprint %q", m.DataFingerprint)
	}
	if len(d.ROAs) != 3 || d.ROAs[0].ASN != "AS64500" || d.ROAs[0].Prefix != "192.0.2.0/24" || d.ROAs[2].Prefix != "2001:db8::/32" {
		t.Fatalf("roas: %+v", d.ROAs)
	}
	if d.ASPAs == nil || len(*d.ASPAs) != 1 {
		t.Fatalf("aspas: %v", d.ASPAs)
	}
	if a := (*d.ASPAs)[0]; a.Customer != "AS64511" || strings.Join(a.Providers, ",") != "AS0,AS174,AS3356" {
		t.Fatalf("aspa: %+v", a)
	}
	if !strings.Contains(errOut, "serial 42") || !strings.Contains(errOut, "3 VRPs, 1 ASPAs") {
		t.Fatalf("summary: %q", errOut)
	}
}

// Pinned to RTR version 1 the dump says that ASPAs were unavailable and
// writes no list for them.
func TestRTRDumpVersion1(t *testing.T) {
	cache := rtrtest.NewCache(t)
	go func() {
		q := cache.Next(5 * time.Second)
		q.Conn.Send(
			rtrtest.CacheResponse(1, 5),
			rtrtest.IPv4Prefix(1, true, netip.MustParsePrefix("198.51.100.0/24"), 24, 64502),
			rtrtest.EndOfData(1, 5, 9, 3600, 600, 7200),
		)
	}()

	file := filepath.Join(t.TempDir(), "dump.json")
	_, errOut, err := runDump(t, "--cache", cache.Addr(), "--rtr-version", "1", "-o", file, "--timeout", "10s")
	if err != nil {
		t.Fatalf("dump: %v\n%s", err, errOut)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var d dumpDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	if d.Metadata.ProtocolVersion != 1 || d.Metadata.ASPAsAvailable || d.ASPAs != nil || len(d.ROAs) != 1 {
		t.Fatalf("v1 dump:\n%s", raw)
	}
	if !strings.Contains(errOut, "no ASPA in this RTR version") {
		t.Fatalf("summary: %q", errOut)
	}
}

func TestRTRDumpTimeout(t *testing.T) {
	cache := rtrtest.NewCache(t) // accepts the query and never answers
	_, _, err := runDump(t, "--cache", cache.Addr(), "--timeout", "300ms")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want a timeout, got %v", err)
	}
}

func TestRTRDumpBadTransport(t *testing.T) {
	if _, _, err := runDump(t, "--transport", "udp"); err == nil {
		t.Fatal("want an error for --transport udp")
	}
}
