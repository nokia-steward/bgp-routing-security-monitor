package snapshot_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/snapshot"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

const testVersion = "v1.0.0-test"

// ── helpers ──────────────────────────────────────────────────────────────────

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }

func syntheticRoute(i int) *types.Route {
	// Generate varied but deterministic routes.
	peer := netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
	prefix := netip.PrefixFrom(
		netip.AddrFrom4([4]byte{100, byte(i / 256), byte(i % 256), 0}),
		24,
	)
	return &types.Route{
		Prefix:          prefix,
		PeerAddr:        peer,
		PeerASN:         uint32(64500 + i),
		RouterID:        mustAddr("1.2.3.4"),
		ASPath:          []uint32{65000, uint32(64500 + i)},
		NextHop:         peer,
		Timestamp:       time.Unix(1_700_000_000+int64(i), 0),
		RIBType:         types.AdjRIBInPre,
		ROV:             types.ROVResult{State: types.ROVValid},
		ASPA:            types.ASPAResult{State: types.ASPAValid},
		SecurityPosture: types.PostureSecured,
	}
}

func newWriterReader(t *testing.T, version string) (*snapshot.Writer, *snapshot.Reader, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := snapshot.NewWriter(dir, version)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	r := snapshot.NewReader(dir, version)
	return w, r, dir
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestWriteReadRoutes_RoundTrip(t *testing.T) {
	const n = 100
	w, r, _ := newWriterReader(t, testVersion)

	routes := make([]*types.Route, n)
	for i := range n {
		routes[i] = syntheticRoute(i)
	}

	if err := w.WriteRoutes(routes); err != nil {
		t.Fatalf("WriteRoutes: %v", err)
	}

	got, err := r.ReadRoutes()
	if err != nil {
		t.Fatalf("ReadRoutes: %v", err)
	}
	if len(got) != n {
		t.Fatalf("ReadRoutes returned %d routes, want %d", len(got), n)
	}

	// All restored routes must be Stale.
	for i, rt := range got {
		if !rt.Stale {
			t.Errorf("route[%d]: Stale=false, want true", i)
		}
	}

	// Spot-check first entry.
	first := got[0]
	if first.Prefix != routes[0].Prefix {
		t.Errorf("first prefix = %s, want %s", first.Prefix, routes[0].Prefix)
	}
	if first.PeerASN != routes[0].PeerASN {
		t.Errorf("first PeerASN = %d, want %d", first.PeerASN, routes[0].PeerASN)
	}
	if first.SecurityPosture != routes[0].SecurityPosture {
		t.Errorf("first posture = %q, want %q", first.SecurityPosture, routes[0].SecurityPosture)
	}

	// Spot-check last entry.
	last := got[n-1]
	if last.Prefix != routes[n-1].Prefix {
		t.Errorf("last prefix = %s, want %s", last.Prefix, routes[n-1].Prefix)
	}
	if last.PeerASN != routes[n-1].PeerASN {
		t.Errorf("last PeerASN = %d, want %d", last.PeerASN, routes[n-1].PeerASN)
	}
}

func TestWriteReadRPKI_RoundTrip(t *testing.T) {
	w, r, _ := newWriterReader(t, testVersion)

	vrps := make([]types.VRP, 50)
	for i := range vrps {
		vrps[i] = types.VRP{
			Prefix:    netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, byte(i), 0}), 24),
			ASN:       uint32(64500 + i),
			MaxLength: 24,
		}
	}

	aspas := make([]types.ASPARecord, 10)
	for i := range aspas {
		aspas[i] = types.ASPARecord{
			CustomerASN:  uint32(65000 + i),
			ProviderASNs: []uint32{65100 + uint32(i), 65200 + uint32(i)},
		}
	}

	const testSerial = uint32(42)
	if err := w.WriteRPKI(vrps, aspas, testSerial); err != nil {
		t.Fatalf("WriteRPKI: %v", err)
	}

	gotVRPs, gotASPAs, gotSerial, err := r.ReadRPKI()
	if err != nil {
		t.Fatalf("ReadRPKI: %v", err)
	}
	if len(gotVRPs) != 50 {
		t.Fatalf("VRP count = %d, want 50", len(gotVRPs))
	}
	if len(gotASPAs) != 10 {
		t.Fatalf("ASPA count = %d, want 10", len(gotASPAs))
	}
	if gotSerial != testSerial {
		t.Errorf("serial = %d, want %d", gotSerial, testSerial)
	}

	// Spot-check first VRP.
	if gotVRPs[0].Prefix != vrps[0].Prefix {
		t.Errorf("VRP[0] prefix = %s, want %s", gotVRPs[0].Prefix, vrps[0].Prefix)
	}
	if gotVRPs[0].ASN != vrps[0].ASN {
		t.Errorf("VRP[0] ASN = %d, want %d", gotVRPs[0].ASN, vrps[0].ASN)
	}

	// Spot-check first ASPA provider set.
	if len(gotASPAs[0].ProviderASNs) != 2 {
		t.Fatalf("ASPA[0] providers = %d, want 2", len(gotASPAs[0].ProviderASNs))
	}
}

func TestReader_MissingFile(t *testing.T) {
	dir := t.TempDir()
	r := snapshot.NewReader(dir, testVersion)

	routes, err := r.ReadRoutes()
	if err != nil {
		t.Fatalf("ReadRoutes on empty dir: unexpected error: %v", err)
	}
	if routes != nil {
		t.Fatalf("ReadRoutes on empty dir: want nil, got %d routes", len(routes))
	}

	vrps, aspas, serial, err := r.ReadRPKI()
	if err != nil {
		t.Fatalf("ReadRPKI on empty dir: unexpected error: %v", err)
	}
	if vrps != nil || aspas != nil || serial != 0 {
		t.Fatalf("ReadRPKI on empty dir: want nil/nil/0, got %d/%d/%d", len(vrps), len(aspas), serial)
	}
}

func TestReader_VersionMismatch(t *testing.T) {
	dir := t.TempDir()

	// Write with version v0.0.1.
	w, err := snapshot.NewWriter(dir, "v0.0.1")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WriteRoutes([]*types.Route{syntheticRoute(0)}); err != nil {
		t.Fatalf("WriteRoutes: %v", err)
	}

	// Read with version v0.0.2 — must get ErrVersionMismatch.
	r := snapshot.NewReader(dir, "v0.0.2")
	_, err = r.ReadRoutes()
	if err == nil {
		t.Fatal("ReadRoutes: expected ErrVersionMismatch, got nil")
	}
	if err != snapshot.ErrVersionMismatch {
		t.Errorf("ReadRoutes error = %v, want ErrVersionMismatch", err)
	}
}

func TestReader_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.snap"), []byte("not json {{{{"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := snapshot.NewReader(dir, testVersion)
	_, err := r.ReadRoutes()
	if err == nil {
		t.Fatal("ReadRoutes on corrupt file: expected error, got nil")
	}
}

func TestTable_EvictStale(t *testing.T) {
	tbl := routetable.New()

	// Build 5 distinct stale routes.
	staleRoutes := make([]*types.Route, 5)
	for i := range staleRoutes {
		staleRoutes[i] = &types.Route{
			Prefix:   mustPrefix("10." + itoa(i) + ".0.0/24"),
			PeerAddr: mustAddr("192.0.2.1"),
			PeerASN:  65000,
			ASPath:   []uint32{65000},
			RIBType:  types.AdjRIBInPre,
		}
	}
	tbl.Restore(staleRoutes)

	if tbl.Count() != 5 {
		t.Fatalf("count after Restore = %d, want 5", tbl.Count())
	}

	// Confirm staleRoutes[0] via a simulated BMP upsert (Stale=false).
	confirmed := *staleRoutes[0]
	confirmed.Stale = false
	tbl.Insert(&confirmed)

	// Evict — 4 stale, 1 confirmed.
	evicted := tbl.EvictStale()
	if evicted != 4 {
		t.Errorf("EvictStale returned %d, want 4", evicted)
	}
	if tbl.Count() != 1 {
		t.Errorf("table count after eviction = %d, want 1", tbl.Count())
	}

	// The surviving route must not be stale.
	survivors := tbl.All()
	if len(survivors) != 1 {
		t.Fatalf("All() returned %d routes, want 1", len(survivors))
	}
	if survivors[0].Stale {
		t.Error("surviving route is still Stale, want false")
	}
}

// itoa converts an int to its decimal string — avoids strconv import.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}
