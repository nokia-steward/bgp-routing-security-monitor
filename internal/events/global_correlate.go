package events

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external"
)

// Enricher is an Action that annotates the event in place before the
// remaining actions of the same rule run. A rule's enrichers all complete
// first, so every downstream action — webhook, log, flowspec — observes the
// same fully annotated event.
type Enricher interface {
	Action
	// Enrich annotates event. It must not return an error: an enricher that
	// cannot do its job leaves a degraded annotation rather than failing the
	// rule.
	Enrich(ctx context.Context, event *Event)
}

// Default bounds for the global-correlate action.
const (
	// defaultCorrelateTimeout bounds one correlation, independent of the
	// engine's own context, so a slow provider cannot hold a rule open.
	defaultCorrelateTimeout = 10 * time.Second
	// defaultCorrelateConcurrency bounds in-flight correlations across all
	// rules sharing this action. A burst of posture changes queues here
	// rather than spawning an unbounded number of blocked goroutines. The
	// provider's own rate limiter is the real throttle; this just keeps
	// goroutine count and socket use bounded.
	defaultCorrelateConcurrency = 4
)

// GlobalCorrelateAction attaches a GlobalVisibilityResult to the event by
// querying an external looking-glass provider.
//
// It is an Enricher rather than a plain Action: the point is to annotate the
// event so the webhook and log actions carry the result, which requires it to
// run before them.
//
// It is deliberately fail-open. A nil provider, a query failure, a timeout or
// a rate-limit rejection all produce an Inconclusive annotation; nothing here
// can fail a rule or block the pipeline.
type GlobalCorrelateAction struct {
	provider external.GlobalVisibilityProvider
	// cacheTTL is this action's freshness requirement, passed to the
	// provider as maxAge. Zero means the provider's configured default.
	cacheTTL time.Duration
	timeout  time.Duration
	// sem bounds concurrent correlations.
	sem chan struct{}
	log *slog.Logger
}

func newGlobalCorrelateAction(
	provider external.GlobalVisibilityProvider,
	cacheTTL time.Duration,
	log *slog.Logger,
) *GlobalCorrelateAction {
	return &GlobalCorrelateAction{
		provider: provider,
		cacheTTL: cacheTTL,
		timeout:  defaultCorrelateTimeout,
		sem:      make(chan struct{}, defaultCorrelateConcurrency),
		log:      log,
	}
}

// Name implements Action.
func (a *GlobalCorrelateAction) Name() string { return "global-correlate" }

// Execute implements Action. Enrich does the work; by the time the engine
// reaches the action phase the annotation is already attached, so this is a
// no-op. It exists so GlobalCorrelateAction satisfies Action and can be
// reported by name in logs.
func (a *GlobalCorrelateAction) Execute(_ context.Context, _ Event) error { return nil }

// Enrich queries the provider for the event's prefix and attaches the result.
//
// Events without a route (a cache-unhealthy event, say) have no prefix to
// correlate and are left unannotated.
func (a *GlobalCorrelateAction) Enrich(ctx context.Context, event *Event) {
	if event.Route == nil {
		return
	}

	// Bound this correlation independently of the engine context so a slow
	// provider cannot hold the rule open indefinitely.
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	// Wait for a concurrency slot, but give up if the context expires first
	// rather than queueing behind a backlog that has already timed out.
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	case <-ctx.Done():
		event.GlobalVisibility = &external.GlobalVisibilityResult{
			QueriedAt:   time.Now(),
			LocalOrigin: event.Route.OriginASN(),
			Consensus:   external.ConsensusInconclusive,
			Error:       "correlation queue timed out: " + ctx.Err().Error(),
		}
		return
	}

	result := external.Correlate(ctx, a.provider, event.Route.Prefix, event.Route.OriginASN(), a.cacheTTL)
	event.GlobalVisibility = &result

	a.log.Debug("global visibility correlated",
		"event_id", event.ID,
		"prefix", event.Route.Prefix.String(),
		"source", result.Source,
		"consensus", string(result.Consensus),
		"collectors", result.CollectorCount,
		"latency", result.Latency,
	)
}
