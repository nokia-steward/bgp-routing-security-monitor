package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	snapshotv1 "github.com/nokia-steward/bgp-routing-security-monitor/internal/snapshot/v1"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// ErrVersionMismatch is returned when the snapshot was written by a
// different RAVEN version. Callers should log a warning and continue
// with a cold start — never crash on this error.
var ErrVersionMismatch = errors.New("snapshot: version mismatch, discarding")

// ErrFormatMismatch is returned when routes.snap is in another format than
// this RAVEN reads (snapshotv1.RouteFormatVersion). It is not migrated:
// callers log a warning and cold start, as for ErrVersionMismatch.
var ErrFormatMismatch = errors.New("snapshot: route format mismatch, discarding")

// Reader handles snapshot reads from disk.
type Reader struct {
	dir     string
	version string
}

// NewReader creates a Reader rooted at dir.
func NewReader(dir string, version string) *Reader {
	return &Reader{dir: expandHome(dir), version: version}
}

// ReadRoutes reads <dir>/routes.snap.
// Returns (nil, nil) if the file does not exist (first start).
// Returns ErrVersionMismatch if the snapshot was written by a different version.
// Returns a non-nil error if the file is unreadable or corrupt.
func (r *Reader) ReadRoutes() ([]*types.Route, error) {
	path := filepath.Join(r.dir, "routes.snap")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("snapshot: read routes.snap: %w", err)
	}

	var snap snapshotv1.RouteSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("snapshot: decode routes.snap: %w", err)
	}

	if snap.FormatVersion != snapshotv1.RouteFormatVersion {
		return nil, fmt.Errorf("%w: routes.snap is format %d, this RAVEN reads format %d",
			ErrFormatMismatch, snap.FormatVersion, snapshotv1.RouteFormatVersion)
	}
	if snap.RavenVersion != r.version {
		return nil, ErrVersionMismatch
	}

	routes := make([]*types.Route, 0, len(snap.Routes))
	for i, rec := range snap.Routes {
		route, err := recordToRoute(rec)
		if err != nil {
			return nil, fmt.Errorf("snapshot: route record %d: %w", i, err)
		}
		routes = append(routes, route)
	}
	return routes, nil
}

// ReadRPKI reads <dir>/rpki.snap.
// Returns (nil, nil, 0, nil) if the file does not exist (first start).
// Returns ErrVersionMismatch if the snapshot was written by a different version.
func (r *Reader) ReadRPKI() (vrps []types.VRP, aspas []types.ASPARecord, serial uint32, err error) {
	path := filepath.Join(r.dir, "rpki.snap")
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return nil, nil, 0, nil
		}
		return nil, nil, 0, fmt.Errorf("snapshot: read rpki.snap: %w", readErr)
	}

	var snap snapshotv1.RPKISnapshot
	if jsonErr := json.Unmarshal(data, &snap); jsonErr != nil {
		return nil, nil, 0, fmt.Errorf("snapshot: decode rpki.snap: %w", jsonErr)
	}

	if snap.RavenVersion != r.version {
		return nil, nil, 0, ErrVersionMismatch
	}

	vrps = make([]types.VRP, 0, len(snap.VRPs))
	for _, v := range snap.VRPs {
		prefix, parseErr := netip.ParsePrefix(v.Prefix)
		if parseErr != nil {
			return nil, nil, 0, fmt.Errorf("snapshot: VRP prefix %q: %w", v.Prefix, parseErr)
		}
		vrps = append(vrps, types.VRP{
			Prefix:    prefix,
			ASN:       v.ASN,
			MaxLength: uint8(v.MaxLength),
		})
	}

	aspas = make([]types.ASPARecord, 0, len(snap.ASPAs))
	for _, a := range snap.ASPAs {
		aspas = append(aspas, types.ASPARecord{
			CustomerASN:  a.CustomerASN,
			ProviderASNs: a.ProviderASNs,
		})
	}

	return vrps, aspas, snap.RTRSerial, nil
}

// ── conversion helpers ──────────────────────────────────────────────────────

func recordToRoute(rec snapshotv1.RouteRecord) (*types.Route, error) {
	prefix, err := netip.ParsePrefix(rec.Prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid prefix %q: %w", rec.Prefix, err)
	}

	peerAddr, err := parseAddr(rec.PeerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid peer addr %q: %w", rec.PeerAddr, err)
	}

	router, err := parseAddr(rec.Router)
	if err != nil {
		return nil, fmt.Errorf("invalid router %q: %w", rec.Router, err)
	}
	routerID, _ := parseAddr(rec.RouterID)
	nextHop, _ := parseAddr(rec.NextHop)

	// An unknown RIB is an error, not a silent Adj-RIB-In pre-policy
	// route. Snapshots written before the RIB names were unified say
	// pre-policy and post-policy, which ParseRIBType still reads.
	rib, err := types.ParseRIBType(rec.RIBType)
	if err != nil {
		return nil, err
	}
	rovState := parseROVState(rec.ROVState)
	aspaState := parseASPAState(rec.ASPAState)
	// A Loc-RIB route's Peer AS is the router's own AS (RFC 9069 §4.1),
	// the origin of an empty AS_PATH (types.Route.OriginAS); revalidation
	// would otherwise find it not known.
	var localASN uint32
	if rib == types.LocRIB {
		localASN = rec.PeerASN
	}

	return &types.Route{
		Prefix:            prefix,
		Router:            router,
		PeerDistinguisher: rec.PeerDistinguisher,
		PeerType:          rec.PeerType,
		PathID:            rec.PathID,
		PeerAddr:          peerAddr,
		PeerASN:           rec.PeerASN,
		LocalASN:          localASN,
		RouterID:          routerID,
		ASPath:            rec.ASPath,
		NextHop:           nextHop,
		Timestamp:         time.Unix(0, rec.TimestampUnix),
		RIBType:           rib,
		ROV:               types.ROVResult{State: rovState},
		ASPA:              types.ASPAResult{State: aspaState},
		SecurityPosture:   types.SecurityPosture(rec.Posture),
		Stale:             true, // always stale on restore
	}, nil
}

func parseAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(s)
}

func parseROVState(s string) types.ROVState {
	switch s {
	case "Invalid":
		return types.ROVInvalid
	case "NotFound":
		return types.ROVNotFound
	default:
		return types.ROVValid
	}
}

func parseASPAState(s string) types.ASPAState {
	switch s {
	case "Invalid":
		return types.ASPAInvalid
	case "Unknown":
		return types.ASPAUnknown
	case "Unverifiable":
		return types.ASPAUnverifiable
	default:
		return types.ASPAValid
	}
}
