package rtr

import (
	"log/slog"
	"net/netip"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// LoadTestVRPs seeds the VRP store with test ROAs for the demo lab.
// This simulates what Routinator would provide via RTR.
//
// Lab prefixes and their ROV outcomes:
//
//	198.51.100.0/24 origin AS65000 → Valid (ROA matches)
//	203.0.113.0/24  origin AS65000 → Valid (ROA matches)
//	192.0.2.0/24    origin AS99999 → Invalid (wrong origin — simulates hijack)
//	100.64.0.0/24   (no ROA)       → NotFound (no RPKI coverage)
//	10.10.0.0/24    (no ROA)       → NotFound (no RPKI coverage)
func LoadTestVRPs(vrpStore *store.VRPStore, log *slog.Logger) {
	vrps := []types.VRP{
		// ROA for 198.51.100.0/24 authorizing AS65000
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 65000, MaxLength: 24},

		// ROA for 203.0.113.0/24 authorizing AS65000
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASN: 65000, MaxLength: 24},

		// ROA for 192.0.2.0/24 authorizing AS99999 (NOT AS65000)
		// This means routes for 192.0.2.0/24 with origin AS65000 will be INVALID
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), ASN: 99999, MaxLength: 24},
	}

	vrpStore.ReplaceAll(vrps, 1, 1)
	log.Info("test VRPs loaded",
		"vrp_count", vrpStore.Count(),
		"note", "demo mode — not connected to live RPKI validator",
	)
}
