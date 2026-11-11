package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Route state changes, watch delivery, the RTR bulk guard and RTR session
// ends in raven serve.

// Sources of a route state change: a BMP announcement or an RTR update
// (revalidation against new VRP or ASPA data).
const (
	SourceBMP = "bmp"
	SourceRTR = "rtr"
)

var (
	// Posture transitions of routes already in the table, as published to
	// watch and the event engine. A new route is not a transition. Labels:
	// source (bmp, rtr), from and to (Postures).
	RoutePostureChangesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_route_posture_changes_total",
		Help: "Total security posture transitions of routes in the table, by source (bmp, rtr) and posture before and after.",
	}, []string{"source", "from", "to"})

	// Watch events not delivered because the watcher's buffer was full.
	// No per-watcher label: watchers come and go.
	WatchEventsDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "raven_watch_events_dropped_total",
		Help: "Total raven watch events dropped because a watcher was not reading fast enough.",
	})

	// RTR updates whose posture changes exceeded events.rtr-bulk-threshold:
	// one rtr_bulk_change event each, in place of per-route events.
	EventsRTRBulkChangesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "raven_events_rtr_bulk_changes_total",
		Help: "Total RTR updates that changed more routes than events.rtr-bulk-threshold and were reported as one rtr_bulk_change event.",
	})

	// Per-route actions the bulk guard did not run: for each suppressed
	// route event, the actions of every rule whose trigger it matched.
	EventsRTRBulkSuppressedActionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "raven_events_rtr_bulk_suppressed_actions_total",
		Help: "Total per-route event actions (webhook, FlowSpec, log) suppressed by the RTR bulk guard.",
	})

	// RTR sessions that ended, in raven serve. Labels: cache, reason (the
	// rtr monitor NDJSON disconnect_reason set: eof, reset, error_report,
	// timeout, shutdown, version_upgrade, error).
	RTRDisconnectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_rtr_disconnects_total",
		Help: "Total RTR sessions that ended, by cache and reason.",
	}, []string{"cache", "reason"})
)

func init() {
	for _, source := range []string{SourceBMP, SourceRTR} {
		for _, from := range Postures {
			for _, to := range Postures {
				if from != to {
					RoutePostureChangesTotal.WithLabelValues(source, from, to)
				}
			}
		}
	}
}
