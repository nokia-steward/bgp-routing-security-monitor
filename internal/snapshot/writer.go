package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/snapshot/v1"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

const writeTimeout = 30 * time.Second

// Writer handles atomic snapshot writes to disk.
type Writer struct {
	dir     string
	version string
}

// NewWriter creates a Writer rooted at dir (created if absent).
// version is the RAVEN build version embedded in every snapshot for
// compatibility checking on read.
func NewWriter(dir string, version string) (*Writer, error) {
	dir = expandHome(dir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("snapshot: create dir %q: %w", dir, err)
	}
	return &Writer{dir: dir, version: version}, nil
}

// WriteRoutes serialises routes to <dir>/routes.snap atomically.
func (w *Writer) WriteRoutes(routes []*types.Route) error {
	start := time.Now()

	snap := &snapshotv1.RouteSnapshot{
		FormatVersion:    snapshotv1.RouteFormatVersion,
		SnapshotTimeUnix: start.UnixNano(),
		RavenVersion:     w.version,
		Routes:           make([]snapshotv1.RouteRecord, 0, len(routes)),
	}
	for _, r := range routes {
		snap.Routes = append(snap.Routes, routeToRecord(r))
	}

	if err := w.writeAtomic("routes.snap", snap); err != nil {
		return err
	}
	slog.Info("snapshot: wrote routes",
		"count", len(routes),
		"elapsed", time.Since(start).Round(time.Millisecond),
	)
	return nil
}

// WriteRPKI serialises VRPs and ASPAs to <dir>/rpki.snap atomically.
func (w *Writer) WriteRPKI(vrps []types.VRP, aspas []types.ASPARecord, serial uint32) error {
	start := time.Now()

	snap := &snapshotv1.RPKISnapshot{
		SnapshotTimeUnix: start.UnixNano(),
		RavenVersion:     w.version,
		RTRSerial:        serial,
		VRPs:             make([]snapshotv1.VRPRecord, 0, len(vrps)),
		ASPAs:            make([]snapshotv1.ASPARecord, 0, len(aspas)),
	}
	for _, v := range vrps {
		snap.VRPs = append(snap.VRPs, snapshotv1.VRPRecord{
			Prefix:    v.Prefix.String(),
			ASN:       v.ASN,
			MaxLength: uint32(v.MaxLength),
		})
	}
	for _, a := range aspas {
		snap.ASPAs = append(snap.ASPAs, snapshotv1.ASPARecord{
			CustomerASN:  a.CustomerASN,
			ProviderASNs: a.ProviderASNs,
		})
	}

	if err := w.writeAtomic("rpki.snap", snap); err != nil {
		return err
	}
	slog.Info("snapshot: wrote RPKI",
		"vrps", len(vrps),
		"aspas", len(aspas),
		"elapsed", time.Since(start).Round(time.Millisecond),
	)
	return nil
}

// writeAtomic JSON-encodes v into <dir>/<name>.tmp then renames it to
// <dir>/<name>. All of this must finish within writeTimeout.
func (w *Writer) writeAtomic(name string, v any) error {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- w.doWriteAtomic(name, v)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return fmt.Errorf("snapshot write %q timeout after %s", name, writeTimeout)
	}
}

func (w *Writer) doWriteAtomic(name string, v any) error {
	tmp := filepath.Join(w.dir, name+".tmp")
	dst := filepath.Join(w.dir, name)

	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("snapshot: create temp file: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "")
	if encErr := enc.Encode(v); encErr != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("snapshot: encode: %w", encErr)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("snapshot: close temp file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("snapshot: rename to %q: %w", dst, err)
	}
	return nil
}

// ── conversion helpers ──────────────────────────────────────────────────────

func routeToRecord(r *types.Route) snapshotv1.RouteRecord {
	return snapshotv1.RouteRecord{
		Prefix:            prefixString(r.Prefix),
		Router:            addrString(r.Router),
		PeerDistinguisher: r.PeerDistinguisher,
		PeerType:          r.PeerType,
		PathID:            r.PathID,
		PeerAddr:          addrString(r.PeerAddr),
		PeerASN:           r.PeerASN,
		RouterID:          addrString(r.RouterID),
		ASPath:            r.ASPath,
		OriginASN:         r.OriginASN(),
		NextHop:           addrString(r.NextHop),
		TimestampUnix:     r.Timestamp.UnixNano(),
		RIBType:           r.RIBType.String(),
		ROVState:          r.ROV.State.String(),
		ASPAState:         r.ASPA.State.String(),
		Posture:           string(r.SecurityPosture),
		Stale:             r.Stale,
	}
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
