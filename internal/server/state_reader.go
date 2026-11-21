package server

import (
	"slices"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/api"
	ravenotel "github.com/nokia-steward/bgp-routing-security-monitor/internal/otel"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Verify at compile time that *Server implements ravenotel.StateReader.
var _ ravenotel.StateReader = (*Server)(nil)

// RouteCounts returns the current route counts of the RIBs
// raven_routes_total counts, by RIB, security posture and address family.
func (s *Server) RouteCounts() []ravenotel.RouteCount {
	var result []ravenotel.RouteCount
	for k, n := range s.routeCounts() {
		if !slices.Contains(metricRIBs, k.rib) {
			continue
		}
		result = append(result, ravenotel.RouteCount{RIB: k.rib.String(), Posture: k.posture, AFI: k.afi, Count: n})
	}
	return result
}

// PeerRouteCounts returns, for each BMP peer, the number of its routes the
// route table holds now.
func (s *Server) PeerRouteCounts() []ravenotel.PeerRouteCount {
	peers := s.bmpListen.GetPeers()
	counts := s.table.PeerRouteCounts()
	result := make([]ravenotel.PeerRouteCount, 0, len(peers))
	for _, p := range peers {
		c := counts[types.NewPeerRef(p.Router, p.Distinguisher, p.Addr)]
		for _, rib := range types.AllRIBTypes {
			if c[rib] == 0 && rib != types.AdjRIBInPre {
				continue // every peer reports its Adj-RIB-In pre-policy count, even 0
			}
			result = append(result, ravenotel.PeerRouteCount{
				Router:            p.Router.String(),
				PeerDistinguisher: api.FormatRD(p.Distinguisher),
				PeerAddr:          p.Addr.String(),
				PeerASN:           p.ASN,
				RIB:               rib.String(),
				Posture:           "unverified", // per-peer posture not tracked; use "unverified"
				Count:             int64(c[rib]),
			})
		}
	}
	return result
}

// BMPSessionStates returns the up/down state for each known BMP router session.
func (s *Server) BMPSessionStates() []ravenotel.BMPSessionState {
	states := s.bmpListen.GetRouterStates()
	result := make([]ravenotel.BMPSessionState, 0, len(states))
	for routerID, state := range states {
		result = append(result, ravenotel.BMPSessionState{
			RouterID: routerID,
			State:    state,
		})
	}
	return result
}

// BMPMessageCounts returns BMP message counts.
// Currently returns nil — message counts are tracked only in Prometheus counters
// and are not re-exported to OTel to avoid double-counting.
func (s *Server) BMPMessageCounts() []ravenotel.BMPMessageCount {
	return nil
}

// RTRSessionStates returns the connection state of each configured RTR cache.
func (s *Server) RTRSessionStates() []ravenotel.RTRSessionState {
	s.rtrMu.RLock()
	defer s.rtrMu.RUnlock()

	result := make([]ravenotel.RTRSessionState, 0, len(s.rtrStates))
	for cache, state := range s.rtrStates {
		result = append(result, ravenotel.RTRSessionState{
			CacheName: cache,
			State:     state,
		})
	}
	return result
}

// RTRCacheCounts returns VRP/ASPA counts and last-sync timestamps.
// VRP and ASPA stores are shared across all caches; each cache entry
// reports the same totals.
func (s *Server) RTRCacheCounts() []ravenotel.RTRCacheCount {
	vrpCount := int64(s.vrpStore.Count())
	aspaCount := int64(s.aspaStore.Count())

	s.rtrMu.RLock()
	lastSync := make(map[string]int64, len(s.rtrLastSync))
	for k, v := range s.rtrLastSync {
		lastSync[k] = v
	}
	s.rtrMu.RUnlock()

	result := make([]ravenotel.RTRCacheCount, 0, len(s.cfg.RTR.Caches))
	for _, cache := range s.cfg.RTR.Caches {
		result = append(result, ravenotel.RTRCacheCount{
			CacheName: cache.Address,
			VRPCount:  vrpCount,
			ASPACount: aspaCount,
			LastSync:  lastSync[cache.Address],
		})
	}
	return result
}
