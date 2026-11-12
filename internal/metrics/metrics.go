package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// BMP session state: 1=up 0=down. Label: router (sysName or addr).
	BMPSessionState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_bmp_session_state",
		Help: "BMP session state (1=up, 0=down).",
	}, []string{"router"})

	// BMP messages processed. Labels: router, msg_type.
	BMPMessagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_bmp_messages_total",
		Help: "Total BMP messages processed.",
	}, []string{"router", "msg_type"})

	// BGP peer state via BMP: 1=established 0=down. Labels: router
	// (sysName, or its address), router_addr (BMP session source), peer,
	// peer_distinguisher (the VRF's RD; "" for a global-instance peer). The
	// same peer address on two routers, or in two VRFs, is two series.
	BMPPeerState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_bmp_peer_state",
		Help: "BGP peer state as seen via BMP (1=established, 0=down).",
	}, []string{"router", "router_addr", "peer", "peer_distinguisher"})

	// NLRI RAVEN does not decode: MP_REACH_NLRI / MP_UNREACH_NLRI for an
	// address family other than IPv4 or IPv6 unicast. Counted, not
	// silently dropped. Labels: afi, safi (decimal).
	BMPUnsupportedNLRITotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_bmp_unsupported_nlri_total",
		Help: "Total MP_REACH/MP_UNREACH NLRI attributes not decoded, by AFI and SAFI.",
	}, []string{"afi", "safi"})

	// BGP UPDATEs in Route Monitoring that RFC 7606 classes as malformed,
	// one per UPDATE, labelled with the approach RAVEN applied (the
	// strongest the UPDATE's errors call for, RFC 7606 §3 (h)) and the
	// error that called for it. Labels: action, reason; both bounded (see
	// MalformedUpdateReasons).
	BMPMalformedUpdatesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_bmp_malformed_updates_total",
		Help: "Total malformed BGP UPDATEs received via BMP, by RFC 7606 action and reason.",
	}, []string{"action", "reason"})

	// RTR session state: 1=connected 0=down. Label: cache.
	RTRSessionState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_session_state",
		Help: "RTR session state (1=connected, 0=disconnected).",
	}, []string{"cache"})

	// VRPs loaded from RTR cache. Label: cache.
	RTRVRPCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_vrp_count",
		Help: "Number of VRPs loaded from RTR cache.",
	}, []string{"cache"})

	// ASPA records loaded from RTR cache. Label: cache.
	RTRASPACount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_aspa_count",
		Help: "Number of ASPA records loaded from RTR cache.",
	}, []string{"cache"})

	// Unix timestamp of last successful RTR sync. Label: cache.
	RTRLastSync = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_last_sync_seconds",
		Help: "Unix timestamp of the last completed RTR sync (End of Data), whether or not the data changed.",
	}, []string{"cache"})

	// Unix timestamp of the last RTR sync that advanced the serial. Label: cache.
	RTRLastSerialChange = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_last_serial_change_seconds",
		Help: "Unix timestamp of the last RTR sync whose serial differed from the previous one.",
	}, []string{"cache"})

	// RTR data expiry: 1 when no sync has completed within the cache's
	// Expire Interval. Label: cache.
	RTRDataExpired = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_data_expired",
		Help: "1 if no RTR sync with the cache has completed within its Expire Interval, else 0.",
	}, []string{"cache"})

	// RTR protocol version of the current session. Label: cache.
	RTRProtocolVersion = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_protocol_version",
		Help: "RTR protocol version negotiated with the cache (0, 1 or 2; ASPA needs 2).",
	}, []string{"cache"})

	// RTR anomalies detected by the adaptive detector. Labels: cache, severity.
	RTRAnomalyTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_rtr_anomaly_total",
		Help: "Total RTR anomalies detected, by severity.",
	}, []string{"cache", "severity"})

	// Unix timestamp of the most recent RTR anomaly detected. Label: cache.
	RTRAnomalyLastTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_anomaly_last_timestamp",
		Help: "Unix timestamp of the most recent RTR anomaly detected.",
	}, []string{"cache"})

	// raven rtr monitor with several caches: the items a cache has disagreed
	// with the other compared caches on for longer than the settle window,
	// attributed to it. Labels: cache, kind (telemetry.DivergenceKinds).
	RTRDivergentItems = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_divergent_items",
		Help: "Items (VRPs, ASPA customer ASes) a cache persistently disagrees with the other compared RTR caches on, by kind (raven rtr monitor with several --cache).",
	}, []string{"cache", "kind"})

	// raven rtr monitor with several caches: 1 while the cache is in the
	// comparison (connected, and synced in its current session), 0
	// otherwise. Label: cache.
	RTRCompared = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_compared",
		Help: "1 while the RTR cache is in the cross-cache comparison (connected and synced in its current session), 0 otherwise (raven rtr monitor with several --cache).",
	}, []string{"cache"})

	// Route counts by security posture, AFI and RIB: the routes the routers
	// receive (rib adj-rib-in-pre, adj-rib-in-post) and select (loc-rib),
	// each RIB apart, so that a route reported in two RIBs is never added
	// up by accident: filter on rib. Adj-RIB-Out routes have their own
	// gauge. Labels: posture, afi, rib (RouteRIBs).
	RoutesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_routes_total",
		Help: "Number of routes by security posture, address family and RIB (adj-rib-in-pre, adj-rib-in-post, loc-rib).",
	}, []string{"posture", "afi", "rib"})

	// ASPA verifications run, on ingest and on revalidation. Labels:
	// procedure (upstream, downstream), source (default, config-address,
	// config-asn), state (Valid, Invalid, Unknown, Unverifiable).
	ASPAValidationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_aspa_validations_total",
		Help: "Total ASPA AS_PATH verifications, by procedure, procedure source and result.",
	}, []string{"procedure", "source", "state"})

	// Wall time of revalidation passes after RTR updates, from start to
	// finish (the pass is interleaved with ingest). Label: mode
	// (incremental, full).
	RevalidationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "raven_revalidation_duration_seconds",
		Help:    "Duration of route revalidation passes after RTR updates, by mode.",
		Buckets: []float64{.001, .01, .1, .5, 1, 2.5, 5, 10, 30, 60, 120},
	}, []string{"mode"})

	// Routes handled by revalidation passes. Labels: mode (incremental,
	// full), result (checked, changed).
	RevalidationRoutesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_revalidation_routes_total",
		Help: "Total routes revalidated after RTR updates, and how many of them changed, by mode.",
	}, []string{"mode", "result"})

	// BMP connections closed at accept, before reading anything. Label:
	// reason (not_allowed: source outside bmp.allowed-routers;
	// bad_remote_addr: the source address could not be read).
	BMPRejectedConnectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_bmp_rejected_connections_total",
		Help: "Total BMP connections rejected at accept, by reason.",
	}, []string{"reason"})

	// Adj-RIB-Out pre-policy routes (RFC 8671: what the routers send their
	// peers) by security posture and AFI. Kept out of raven_routes_total,
	// which counts what the routers receive, so that sums over it never
	// mix the two directions. Labels: posture, afi.
	AdjRIBOutRoutesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_adj_rib_out_routes_total",
		Help: "Number of Adj-RIB-Out pre-policy routes by security posture and address family.",
	}, []string{"posture", "afi"})

	// Routes in the route table by RIB, the RIBs raven_routes_total counts,
	// each apart: sum over the RIBs of the default view (adj-rib-in-pre and
	// loc-rib) for what route queries return. Label: rib (RouteRIBs).
	RouteTableSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_route_table_size",
		Help: "Number of routes in the route table by RIB (adj-rib-in-pre, adj-rib-in-post, loc-rib).",
	}, []string{"rib"})

	// External global-visibility correlations. Labels: source (e.g.
	// "ripestat"), result (match, divergent, local_only, inconclusive).
	GlobalCheckTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_global_check_total",
		Help: "Total external global-visibility correlations, by source and consensus result.",
	}, []string{"source", "result"})

	// Global-visibility lookups suppressed by the local rate limiter before
	// any provider was contacted. Label: source (e.g. "ripestat").
	//
	// Separate from raven_global_check_total on purpose: a rate-limit
	// rejection is a policy decision costing no network call, and folding it
	// into the inconclusive result label made it indistinguishable from a
	// provider RAVEN genuinely could not reach.
	GlobalCheckRateLimited = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_global_check_rate_limited_total",
		Help: "Total external global-visibility lookups suppressed by the local rate limiter, by source.",
	}, []string{"source"})

	// Global-visibility lookups the provider served from its in-process cache
	// without a network round-trip. Label: source (e.g. "ripestat").
	//
	// Like the rate-limited counter, this keeps a non-network event off
	// raven_global_check_latency_seconds while leaving cache activity
	// visible: rate(cache_hits) / rate(check_total) is the cache hit ratio.
	GlobalCheckCacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_global_check_cache_hits_total",
		Help: "Total global-visibility lookups served from the in-process cache, by source.",
	}, []string{"source"})

	// Latency of a global-visibility correlation that actually went to the
	// provider, successful or not.
	//
	// Cache hits and rate-limited lookups are both excluded: neither made a
	// network round-trip, and their near-zero timings would pull p50/p95
	// toward zero whenever the cache is warm, masking exactly the provider
	// latency degradation an operator alerts on.
	GlobalCheckLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "raven_global_check_latency_seconds",
		Help:    "Latency of external global-visibility correlations in seconds.",
		Buckets: []float64{.001, .005, .025, .1, .25, .5, 1, 2.5, 5, 10},
	})
)

// Label values with a known, fixed set. Their series are created at 0 when
// the package loads, so a scrape shows 0 rather than nothing before the first
// increment and an alert can tell "none yet" from "not exported".
var (
	// RouteRIBs are the rib label values of raven_routes_total and
	// raven_route_table_size.
	RouteRIBs = []string{"adj-rib-in-pre", "adj-rib-in-post", "loc-rib"}
	// Postures and AFIs are the posture and afi label values of
	// raven_routes_total and raven_adj_rib_out_routes_total.
	Postures = []string{"secured", "origin-only", "path-suspect", "path-only", "unverified", "origin-invalid"}
	AFIs     = []string{"ipv4", "ipv6"}
)

const (
	RejectReasonNotAllowed    = "not_allowed"
	RejectReasonBadRemoteAddr = "bad_remote_addr"

	// raven_bmp_malformed_updates_total actions: the RFC 7606 §2
	// approaches, weakest first.
	MalformedActionAttributeDiscard = "attribute_discard"
	MalformedActionTreatAsWithdraw  = "treat_as_withdraw"
	MalformedActionSessionReset     = "session_reset"

	// raven_bmp_malformed_updates_total reasons.
	MalformedReasonASPath           = "as_path"           // truncated, zero-length or unknown segment (§7.2)
	MalformedReasonAttrLength       = "attr_length"       // attribute running past the path attributes (§4)
	MalformedReasonAttrFlags        = "attr_flags"        // Optional/Transitive bits wrong (§3 (c))
	MalformedReasonOrigin           = "origin"            // §7.1
	MalformedReasonNextHop          = "next_hop"          // §7.3
	MalformedReasonMED              = "med"               // §7.4
	MalformedReasonLocalPref        = "local_pref"        // §7.5, from an internal peer
	MalformedReasonCommunities      = "communities"       // §7.8
	MalformedReasonOriginatorID     = "originator_id"     // §7.9, from an internal peer
	MalformedReasonClusterList      = "cluster_list"      // §7.10, from an internal peer
	MalformedReasonLargeCommunities = "large_communities" // RFC 8092 §6
	MalformedReasonMissingMandatory = "missing_mandatory" // §3 (d)
	MalformedReasonAS4Path          = "as4_path"          // RFC 6793 §6
	MalformedReasonAS4Aggregator    = "as4_aggregator"    // RFC 6793 §6
	MalformedReasonDuplicateAttr    = "duplicate_attr"    // §3 (g), all but the first discarded
	MalformedReasonNLRI             = "nlri"              // NLRI or Withdrawn Routes syntactically incorrect (§5.3)
	MalformedReasonMPReach          = "mp_reach"          // MP_REACH_NLRI too short or flags wrong (§5.3)
	MalformedReasonMPReachNextHop   = "mp_reach_next_hop" // next hop length not as expected (§7.11)
	MalformedReasonMPUnreach        = "mp_unreach"        // MP_UNREACH_NLRI too short or flags wrong (§5.3)
	MalformedReasonDuplicateMP      = "duplicate_mp"      // MP_REACH/MP_UNREACH more than once (§3 (g))
	MalformedReasonUpdateLength     = "update_length"     // UPDATE length fields overflow the message (§3 (b))

	RevalidationModeIncremental = "incremental"
	RevalidationModeFull        = "full"
	RevalidationResultChecked   = "checked"
	RevalidationResultChanged   = "changed"
)

// MalformedUpdateReasons lists, per action, the reasons that can carry it:
// the series of raven_bmp_malformed_updates_total. A treat-as-withdraw
// error in an UPDATE with no reachable NLRI is escalated to session reset
// (RFC 7606 §5.2), so those reasons appear under both.
var MalformedUpdateReasons = map[string][]string{
	MalformedActionAttributeDiscard: {MalformedReasonAS4Path, MalformedReasonAS4Aggregator, MalformedReasonDuplicateAttr},
	MalformedActionTreatAsWithdraw:  treatAsWithdrawReasons,
	MalformedActionSessionReset: append([]string{MalformedReasonNLRI, MalformedReasonMPReach,
		MalformedReasonMPReachNextHop, MalformedReasonMPUnreach, MalformedReasonDuplicateMP,
		MalformedReasonUpdateLength}, treatAsWithdrawReasons...),
}

var treatAsWithdrawReasons = []string{MalformedReasonASPath, MalformedReasonAttrLength, MalformedReasonAttrFlags,
	MalformedReasonOrigin, MalformedReasonNextHop, MalformedReasonMED, MalformedReasonLocalPref,
	MalformedReasonCommunities, MalformedReasonOriginatorID, MalformedReasonClusterList,
	MalformedReasonLargeCommunities, MalformedReasonMissingMandatory}

func init() {
	for action, reasons := range MalformedUpdateReasons {
		for _, reason := range reasons {
			BMPMalformedUpdatesTotal.WithLabelValues(action, reason)
		}
	}
	for _, reason := range []string{RejectReasonNotAllowed, RejectReasonBadRemoteAddr} {
		BMPRejectedConnectionsTotal.WithLabelValues(reason)
	}
	for _, mode := range []string{RevalidationModeIncremental, RevalidationModeFull} {
		RevalidationDuration.WithLabelValues(mode)
		for _, result := range []string{RevalidationResultChecked, RevalidationResultChanged} {
			RevalidationRoutesTotal.WithLabelValues(mode, result)
		}
	}
	for _, rib := range RouteRIBs {
		RouteTableSize.WithLabelValues(rib)
	}
	for _, posture := range Postures {
		for _, afi := range AFIs {
			AdjRIBOutRoutesTotal.WithLabelValues(posture, afi)
			for _, rib := range RouteRIBs {
				RoutesTotal.WithLabelValues(posture, afi, rib)
			}
		}
	}
}
