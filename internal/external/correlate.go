package external

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/metrics"
)

// Correlate compares the local BMP-observed origin for prefix against what
// provider observes globally.
//
// It never returns an error. A nil provider, a query failure, a timeout, a
// rate-limit rejection or a malformed response all resolve to
// ConsensusInconclusive with the cause in Error, so callers on the CLI path
// and in the Event Engine can attach the result unconditionally.
//
// The two cases where no provider was actually reached — a nil provider and a
// rate-limit rejection — leave Queried false, record no latency, and stay off
// raven_global_check_total; the latter is counted on
// raven_global_check_rate_limited_total instead.
//
// A cache hit did reach the provider, so it is a query and is counted, but it
// made no network round-trip: it lands on raven_global_check_cache_hits_total
// and contributes nothing to raven_global_check_latency_seconds.
//
// maxAge is passed through to the provider as a freshness requirement; zero
// means the provider's configured default.
func Correlate(
	ctx context.Context,
	provider GlobalVisibilityProvider,
	prefix netip.Prefix,
	localOrigin uint32,
	maxAge time.Duration,
) GlobalVisibilityResult {
	result := GlobalVisibilityResult{
		QueriedAt:   time.Now(),
		LocalOrigin: localOrigin,
	}

	if provider == nil {
		result.Consensus = ConsensusInconclusive
		result.Error = reasonNoProvider
		// Not counted in raven_global_check_total: nothing was checked.
		return result
	}

	result.Source = provider.Name()

	start := time.Now()
	summary, err := provider.GlobalOrigins(ctx, prefix, maxAge)
	elapsed := time.Since(start)

	// A lookup the provider's own rate limiter suppressed never reached the
	// network. Nothing was consulted, so Queried stays false, and elapsed is
	// the sub-microsecond cost of rejecting the call rather than a
	// measurement — feeding it to the latency histogram would pull the
	// distribution toward zero and hide real query latency. It gets its own
	// counter so this policy decision stays distinguishable from a provider
	// RAVEN could not reach.
	if errors.Is(err, ErrRateLimited) {
		result.Consensus = ConsensusInconclusive
		result.Error = err.Error()
		metrics.GlobalCheckRateLimited.WithLabelValues(result.Source).Inc()
		return result
	}

	result.Queried = true
	result.Latency = elapsed

	if err != nil {
		result.Consensus = ConsensusInconclusive
		result.Error = err.Error()
		// A failed query is still a round-trip — a timeout is precisely the
		// latency an operator wants in the histogram.
		observe(result, false)
		return result
	}

	SortObservations(summary.Origins)
	result.GlobalOrigins = summary.Origins
	result.CollectorCount = summary.CollectorCount
	result.Consensus, result.Error = Consensus(localOrigin, summary.Origins)

	observe(result, summary.CacheHit)
	return result
}

// InitMetrics creates provider source's global-visibility series at 0, one
// per consensus result, so they are exported before the first check.
func InitMetrics(source string) {
	for _, c := range []GlobalConsensus{ConsensusMatch, ConsensusDivergent, ConsensusLocalOnly, ConsensusInconclusive} {
		metrics.GlobalCheckTotal.WithLabelValues(source, string(c))
	}
	metrics.GlobalCheckRateLimited.WithLabelValues(source)
	metrics.GlobalCheckCacheHits.WithLabelValues(source)
}

// observe records the Prometheus series for a completed correlation: always
// the check counter, then either the latency histogram or the cache-hit
// counter.
//
// A cache hit is an in-process map read, not a network round-trip. Feeding
// one to the histogram pulls p50/p95 toward zero whenever the cache is warm,
// which is exactly when real provider latency degradation would otherwise
// show up. Counting it separately keeps cache activity visible without
// polluting the latency distribution.
func observe(r GlobalVisibilityResult, cacheHit bool) {
	metrics.GlobalCheckTotal.WithLabelValues(r.Source, string(r.Consensus)).Inc()
	if cacheHit {
		metrics.GlobalCheckCacheHits.WithLabelValues(r.Source).Inc()
		return
	}
	metrics.GlobalCheckLatency.Observe(r.Latency.Seconds())
}
