package whatif

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Simulator runs what-if policy simulations against the live Route Table.
type Simulator struct {
	table *routetable.Table
}

func NewSimulator(table *routetable.Table) *Simulator {
	return &Simulator{table: table}
}

// ─── Result types ─────────────────────────────────────────────────────────────

type RejectInvalidResult struct {
	TotalRoutes      int            `json:"total_routes"`
	RejectedRoutes   int            `json:"rejected_routes"`
	AffectedPrefixes int            `json:"affected_prefixes"`
	AffectedOrigins  int            `json:"affected_origins"`
	TopOrigins       []OriginImpact `json:"top_origins"`
	ByPeer           []PeerImpact   `json:"by_peer"`
	// ByReason breaks the rejected routes and prefixes down by ROV reason
	// code, in types.ROVReasonCodes order, codes with no route left out. A
	// prefix rejected for two reasons (from two peers) counts under both.
	ByReason []ReasonImpact `json:"by_reason"`
	// BlackholeRoutes and BlackholePrefixes are the rejected routes, and
	// their distinct prefixes, that carry BLACKHOLE (65535:666, RFC 7999):
	// a reject-invalid policy would drop these blackhole requests too.
	BlackholeRoutes   int           `json:"blackhole_routes"`
	BlackholePrefixes int           `json:"blackhole_prefixes"`
	RejectedRouteList []types.Route `json:"rejected_route_list,omitempty"`
}

// ReasonImpact counts the rejected routes with one ROV reason code.
type ReasonImpact struct {
	ReasonCode  string `json:"reason_code"`
	RouteCount  int    `json:"route_count"`
	PrefixCount int    `json:"prefix_count"`
}

type OriginImpact struct {
	OriginASN  uint32 `json:"origin_asn"`
	RouteCount int    `json:"route_count"`
	// PrefixCount is the origin's distinct rejected prefixes.
	PrefixCount int `json:"prefix_count"`
	// Reason is the ROV reason of the origin's first rejected route with
	// its most common reason code, ReasonCode; ReasonCodes counts its
	// rejected routes by code.
	Reason      string         `json:"reason"`
	ReasonCode  string         `json:"reason_code"`
	ReasonCodes map[string]int `json:"reason_codes"`
}

// ReasonSummary is the REASON column of the top-origins table: the reason
// codes of the origin's rejected routes, most common first, each with its
// count when there is more than one code ("invalid_length (3),
// invalid_origin (1)"). Ties go in types.ROVReasonCodes order.
func (o *OriginImpact) ReasonSummary() string {
	codes := make([]string, 0, len(o.ReasonCodes))
	for _, c := range reasonSlots {
		if o.ReasonCodes[reasonName(c)] > 0 {
			codes = append(codes, reasonName(c))
		}
	}
	if len(codes) == 0 {
		return o.Reason // a result from a daemon older than reason codes
	}
	if len(codes) == 1 {
		return codes[0]
	}
	sort.SliceStable(codes, func(i, j int) bool { return o.ReasonCodes[codes[i]] > o.ReasonCodes[codes[j]] })
	out := ""
	for i, c := range codes {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s (%d)", c, o.ReasonCodes[c])
	}
	return out
}

type PeerImpact struct {
	PeerAddr string `json:"peer_addr"`
	PeerASN  uint32 `json:"peer_asn"`
	Rejected int    `json:"rejected"`
	Total    int    `json:"total"`
}

type ASPAEnforceResult struct {
	TotalRoutes        int           `json:"total_routes"`
	RejectedRoutes     int           `json:"rejected_routes"`
	UnverifiableRoutes int           `json:"unverifiable_routes"`
	AffectedPrefixes   int           `json:"affected_prefixes"`
	AffectedOrigins    int           `json:"affected_origins"`
	TopFailingHops     []HopImpact   `json:"top_failing_hops"`
	RejectedRouteList  []types.Route `json:"rejected_route_list,omitempty"`
}

type HopImpact struct {
	CustomerASN uint32 `json:"customer_asn"`
	ProviderASN uint32 `json:"provider_asn"`
	RouteCount  int    `json:"route_count"`
}

type Options struct {
	MaxRouteList int
	TopN         int
	FilterPeer   string
	FilterAFI    string
}

func defaultOptions(o *Options) *Options {
	if o == nil {
		o = &Options{}
	}
	if o.MaxRouteList == 0 {
		o.MaxRouteList = 500
	}
	if o.TopN == 0 {
		o.TopN = 10
	}
	return o
}

// SimulateRejectInvalid computes what would be rejected under reject-invalid policy.
func (s *Simulator) SimulateRejectInvalid(ctx context.Context, opts *Options) (*RejectInvalidResult, error) {
	opts = defaultOptions(opts)

	routes, err := s.fetchRoutes(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("whatif: fetch routes: %w", err)
	}

	res := &RejectInvalidResult{TotalRoutes: len(routes)}

	prefixSet := make(map[string]struct{})
	originSet := make(map[uint32]struct{})
	originCount := make(map[uint32]*OriginImpact)
	peerCount := make(map[string]*PeerImpact)
	// Distinct prefixes per origin, per reason code, and with BLACKHOLE.
	originPrefixes := make(map[uint32]map[netip.Prefix]struct{})
	reasonRoutes := make([]int, len(reasonSlots))
	reasonPrefixes := make([]map[netip.Prefix]struct{}, len(reasonSlots))
	// The first rejected route's reason for each origin and code.
	originReasons := make(map[uint32]map[types.ROVReasonCode]string)
	blackhole := make(map[netip.Prefix]struct{})

	for i := range routes {
		r := &routes[i]
		peerKey := r.PeerAddr.String()

		if _, ok := peerCount[peerKey]; !ok {
			peerCount[peerKey] = &PeerImpact{PeerAddr: peerKey, PeerASN: r.PeerASN}
		}
		peerCount[peerKey].Total++

		if r.ROV.State != types.ROVInvalid {
			continue
		}

		res.RejectedRoutes++
		peerCount[peerKey].Rejected++
		prefixSet[r.Prefix.String()] = struct{}{}

		originASN := r.OriginASN()
		originSet[originASN] = struct{}{}

		o, ok := originCount[originASN]
		if !ok {
			o = &OriginImpact{OriginASN: originASN, ReasonCodes: map[string]int{}}
			originCount[originASN] = o
			originPrefixes[originASN] = map[netip.Prefix]struct{}{}
			originReasons[originASN] = map[types.ROVReasonCode]string{}
		}
		o.RouteCount++
		originPrefixes[originASN][r.Prefix] = struct{}{}
		code := r.ROV.Code
		o.ReasonCodes[reasonName(code)]++
		if _, ok := originReasons[originASN][code]; !ok {
			originReasons[originASN][code] = r.ROV.Reason
		}

		slot := reasonSlot(code)
		reasonRoutes[slot]++
		if reasonPrefixes[slot] == nil {
			reasonPrefixes[slot] = map[netip.Prefix]struct{}{}
		}
		reasonPrefixes[slot][r.Prefix] = struct{}{}

		if r.HasCommunity(types.CommunityBlackhole) {
			res.BlackholeRoutes++
			blackhole[r.Prefix] = struct{}{}
		}

		if len(res.RejectedRouteList) < opts.MaxRouteList {
			res.RejectedRouteList = append(res.RejectedRouteList, *r)
		}
	}

	res.AffectedPrefixes = len(prefixSet)
	res.AffectedOrigins = len(originSet)
	res.BlackholePrefixes = len(blackhole)
	res.ByReason = []ReasonImpact{}
	for slot, code := range reasonSlots {
		if reasonRoutes[slot] > 0 {
			res.ByReason = append(res.ByReason, ReasonImpact{
				ReasonCode: reasonName(code), RouteCount: reasonRoutes[slot], PrefixCount: len(reasonPrefixes[slot]),
			})
		}
	}

	origins := make([]OriginImpact, 0, len(originCount))
	for asn, o := range originCount {
		o.PrefixCount = len(originPrefixes[asn])
		// The most common code; ties to the first in reasonSlots order.
		best := -1
		for _, code := range reasonSlots {
			if n := o.ReasonCodes[reasonName(code)]; n > best {
				if _, ok := originReasons[asn][code]; ok {
					best, o.ReasonCode, o.Reason = n, reasonName(code), originReasons[asn][code]
				}
			}
		}
		origins = append(origins, *o)
	}
	// Most routes first; ties by ASN, so the table is the same run to run.
	sort.Slice(origins, func(i, j int) bool {
		if origins[i].RouteCount != origins[j].RouteCount {
			return origins[i].RouteCount > origins[j].RouteCount
		}
		return origins[i].OriginASN < origins[j].OriginASN
	})
	if len(origins) > opts.TopN {
		origins = origins[:opts.TopN]
	}
	res.TopOrigins = origins

	peers := make([]PeerImpact, 0, len(peerCount))
	for _, p := range peerCount {
		peers = append(peers, *p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Rejected > peers[j].Rejected })
	res.ByPeer = peers

	return res, nil
}

// reasonSlots are the reason codes the by-reason breakdown counts, in the
// order it lists them: the known codes, then ROVReasonUnknown for an Invalid
// route restored from a snapshot and not yet revalidated.
var reasonSlots = append(slices.Clone(types.ROVReasonCodes), types.ROVReasonUnknown)

// reasonSlot is code's index in reasonSlots.
func reasonSlot(code types.ROVReasonCode) int {
	if i := slices.Index(reasonSlots, code); i >= 0 {
		return i
	}
	return len(reasonSlots) - 1
}

// reasonName names a reason code in what-if output: its String, or
// "unknown" for ROVReasonUnknown.
func reasonName(code types.ROVReasonCode) string {
	if s := code.String(); s != "" {
		return s
	}
	return "unknown"
}

// SimulateASPAEnforce computes impact of dropping path-suspect routes.
func (s *Simulator) SimulateASPAEnforce(ctx context.Context, opts *Options) (*ASPAEnforceResult, error) {
	opts = defaultOptions(opts)

	routes, err := s.fetchRoutes(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("whatif: fetch routes: %w", err)
	}

	res := &ASPAEnforceResult{TotalRoutes: len(routes)}

	prefixSet := make(map[string]struct{})
	originSet := make(map[uint32]struct{})
	hopCount := make(map[[2]uint32]*HopImpact)

	for i := range routes {
		r := &routes[i]

		switch r.SecurityPosture {
		case types.PostureOriginOnly, types.PostureUnverified, types.PosturePathOnly:
			res.UnverifiableRoutes++
		}

		if r.SecurityPosture != types.PosturePathSuspect {
			continue
		}

		res.RejectedRoutes++
		prefixSet[r.Prefix.String()] = struct{}{}
		originSet[r.OriginASN()] = struct{}{}

		if r.ASPA.FailingHop != nil {
			key := [2]uint32{r.ASPA.FailingHop.CustomerASN, r.ASPA.FailingHop.ProviderASN}
			if _, ok := hopCount[key]; !ok {
				hopCount[key] = &HopImpact{
					CustomerASN: r.ASPA.FailingHop.CustomerASN,
					ProviderASN: r.ASPA.FailingHop.ProviderASN,
				}
			}
			hopCount[key].RouteCount++
		}

		if len(res.RejectedRouteList) < opts.MaxRouteList {
			res.RejectedRouteList = append(res.RejectedRouteList, *r)
		}
	}

	res.AffectedPrefixes = len(prefixSet)
	res.AffectedOrigins = len(originSet)

	hops := make([]HopImpact, 0, len(hopCount))
	for _, h := range hopCount {
		hops = append(hops, *h)
	}
	sort.Slice(hops, func(i, j int) bool { return hops[i].RouteCount > hops[j].RouteCount })
	if len(hops) > opts.TopN {
		hops = hops[:opts.TopN]
	}
	res.TopFailingHops = hops

	return res, nil
}

// fetchRoutes lists the Adj-RIB-In pre-policy routes the simulations run
// on: what an import policy would drop is a question about the routes
// received, before policy. Not the default view: a Loc-RIB route is one
// the router already selected, and a route reported in both RIBs would be
// counted twice.
func (s *Simulator) fetchRoutes(ctx context.Context, opts *Options) ([]types.Route, error) {
	filter := routetable.Filter{RIBs: types.RIBSetOf(types.AdjRIBInPre)}
	if opts.FilterPeer != "" {
		filter.PeerAddr = opts.FilterPeer
	}
	if opts.FilterAFI != "" {
		filter.AFI = opts.FilterAFI
	}
	return s.table.ListRoutes(ctx, filter)
}
