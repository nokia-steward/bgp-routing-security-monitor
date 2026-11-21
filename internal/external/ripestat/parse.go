package ripestat

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external"
)

// lookingGlassResponse is the subset of the RIPEstat envelope we depend on.
//
// The `messages` field is deliberately absent: it is an array of arrays whose
// shape we would rather not couple to, and a shape change there must not turn
// every lookup inconclusive. Failure is detected from the HTTP status and the
// `status` field instead.
type lookingGlassResponse struct {
	Status       string            `json:"status"`
	DataCallName string            `json:"data_call_name"`
	Data         *lookingGlassData `json:"data"`
}

type lookingGlassData struct {
	RRCs []lookingGlassRRC `json:"rrcs"`
	// LatestTime is the collection timestamp reported by RIPEstat. Retained
	// for diagnostics; the result carries our own query time.
	LatestTime string `json:"latest_time"`
}

type lookingGlassRRC struct {
	RRC      string             `json:"rrc"`
	Location string             `json:"location"`
	Peers    []lookingGlassPeer `json:"peers"`
}

type lookingGlassPeer struct {
	ASNOrigin string `json:"asn_origin"`
	ASPath    string `json:"as_path"`
	Peer      string `json:"peer"`
	Prefix    string `json:"prefix"`
}

// summarize folds a looking-glass response into per-origin observation counts.
//
// The unit of counting is the collector peer: one (rrc, peer address) pair.
// A single route collector peering with 30 networks contributes up to 30
// observations, which is what makes "how widely is this origin seen" a
// meaningful number. Duplicate entries for the same collector peer are
// counted once.
//
// An empty rrcs list is not an error — the looking-glass call is exact-match,
// so a prefix no collector carries legitimately returns nothing, and that is
// exactly the LocalOnly signal.
func summarize(body []byte) (external.GlobalOriginSummary, error) {
	var resp lookingGlassResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return external.GlobalOriginSummary{}, fmt.Errorf("malformed response: %w", err)
	}
	// RIPEstat reports call-level failure in `status` while still returning
	// HTTP 200 in some cases.
	if resp.Status != "" && resp.Status != "ok" {
		return external.GlobalOriginSummary{}, fmt.Errorf("data call status %q", resp.Status)
	}
	if resp.Data == nil {
		return external.GlobalOriginSummary{}, fmt.Errorf("malformed response: missing data object")
	}

	counts := make(map[uint32]int)
	seen := make(map[string]struct{})
	total := 0
	for _, rrc := range resp.Data.RRCs {
		for _, peer := range rrc.Peers {
			asn, ok := originASN(peer)
			if !ok {
				// A peer entry we cannot attribute to an origin tells us
				// nothing; skipping it is preferable to guessing.
				continue
			}
			key := rrc.RRC + "|" + peer.Peer
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			counts[asn]++
			total++
		}
	}

	origins := make([]external.GlobalOriginObservation, 0, len(counts))
	for asn, n := range counts {
		origins = append(origins, external.GlobalOriginObservation{ASN: asn, CollectorCount: n})
	}
	external.SortObservations(origins)

	return external.GlobalOriginSummary{Origins: origins, CollectorCount: total}, nil
}

// originASN resolves a peer entry's origin ASN from the explicit asn_origin
// field, falling back to the last hop of as_path only when asn_origin is
// absent entirely.
//
// A present-but-unparseable asn_origin (an AS_SET) is not resolved from
// as_path: the last as_path hop would be the same AS_SET, and walking further
// back would attribute the route to a transit AS rather than its origin.
func originASN(p lookingGlassPeer) (uint32, bool) {
	if strings.TrimSpace(p.ASNOrigin) != "" {
		return parseASN(p.ASNOrigin)
	}
	fields := strings.Fields(p.ASPath)
	if len(fields) == 0 {
		return 0, false
	}
	return parseASN(fields[len(fields)-1])
}

// parseASN accepts a bare ASN string. RIPEstat renders an AS_SET origin with
// braces (e.g. "{64500,64501}"); those are ambiguous as a single origin, so
// they are rejected rather than arbitrarily resolved to one member.
func parseASN(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "{},") {
		return 0, false
	}
	asn, err := strconv.ParseUint(s, 10, 32)
	if err != nil || asn == 0 {
		return 0, false
	}
	return uint32(asn), true
}
