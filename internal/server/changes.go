package server

import (
	"slices"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/events"
	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Route state changes.
//
// A route's state changes two ways: a BMP announcement (ingestRoute) and
// revalidation after an RTR update (notifyRevalidated). Both hand the change
// to publishChange, the one place that fans it out to raven watch, the
// posture-transition metric and the event engine, so that no consumer can be
// left out of one path again (RTR-driven changes used to reach watch only).
//
// Both run on ingestLoop, the Route Table's only writer, and each compares
// with the route as the table holds it, so a change is published once: a
// BMP re-announcement of an unchanged route, or an RTR update that leaves a
// route as it is, publishes nothing, and a route that a BMP announcement has
// already revalidated against new data is unchanged when the revalidation
// pass reaches it.
//
// BMP changes go to the event engine at once. RTR changes are collected per
// revalidation pass in an events.RTRBatch, which applies the bulk guard
// (events.rtr-bulk-threshold) when the pass ends; watch gets every change at
// once either way.

// rtrUpdate is an RTR update that requested revalidation: its cache and the
// serial it brought.
type rtrUpdate struct {
	cache  string
	serial uint32
}

// publishChange publishes one route state change: old is the route as the
// table held it (nil for a new route, or one only restored from a snapshot),
// updated the route as it holds it now, source metrics.SourceBMP or
// metrics.SourceRTR. The caller has established that something changed.
func (s *Server) publishChange(old, updated *types.Route, source string) {
	s.apiSrv.NotifyRouteFrom(updated, source)

	if old != nil && old.SecurityPosture != updated.SecurityPosture &&
		old.SecurityPosture != "" && updated.SecurityPosture != "" {
		metrics.RoutePostureChangesTotal.WithLabelValues(source,
			string(old.SecurityPosture), string(updated.SecurityPosture)).Inc()
	}

	// Not for Adj-RIB-Out routes: the rules (and their actions, FlowSpec
	// mitigation included) are about routes the router receives. Not for
	// stale routes, which no rule sees until BMP confirms them.
	if s.eventEngine == nil || updated.RIBType.IsAdjRIBOut() || updated.Stale {
		return
	}
	ev := events.Event{
		ID:         events.NewID(),
		Timestamp:  updated.Timestamp,
		Type:       events.EventTypeNewRoute,
		Route:      updated,
		NewPosture: updated.SecurityPosture,
		RouterID:   updated.Router.String(), // the monitored router, not the peer's BGP ID
		Source:     source,
	}
	if old != nil {
		ev.Type = events.EventTypePostureChange
		ev.OldPosture = old.SecurityPosture
	}
	if source == metrics.SourceRTR {
		ev.Timestamp = time.Now()
		if s.rtrBatch != nil {
			s.rtrBatch.Add(ev)
			return
		}
	}
	s.emitEvent(ev)
}

// startRTRBatch starts collecting the event-engine side of a revalidation
// pass for the RTR updates it covers.
func (s *Server) startRTRBatch(updates []rtrUpdate) {
	if s.eventEngine == nil {
		return
	}
	var caches []string
	var serial uint32
	for _, u := range updates {
		if u.cache != "" && !slices.Contains(caches, u.cache) {
			caches = append(caches, u.cache)
		}
		serial = u.serial
	}
	s.rtrBatch = s.eventEngine.NewRTRBatch(caches, serial)
}

// flushRTRBatch ends the pass's batch: its per-route events, or one
// rtr_bulk_change event, go to the event engine.
func (s *Server) flushRTRBatch() {
	if s.rtrBatch == nil {
		return
	}
	s.rtrBatch.Flush(s.emitEvent)
	s.rtrBatch = nil
}

// sameRoute reports whether a BMP announcement b leaves the route a as it was
// in everything watch and the event rules see: the announcement's
// attributes and the validation results (state, reason, posture). It ignores
// when the route was received, which session owns it, whether it was stale
// (callers treat a stale route as not there) and validation detail that does
// not change a result (which VRPs matched, the per-hop ASPA breakdown).
func sameRoute(a, b *types.Route) bool {
	return a.Router == b.Router &&
		a.PeerDistinguisher == b.PeerDistinguisher &&
		a.PeerType == b.PeerType &&
		a.PeerAddr == b.PeerAddr &&
		a.PeerASN == b.PeerASN &&
		a.PathID == b.PathID &&
		a.LocalASN == b.LocalASN &&
		a.ConfedID == b.ConfedID &&
		a.RouterID == b.RouterID &&
		a.Prefix == b.Prefix &&
		slices.Equal(a.ASPath, b.ASPath) &&
		slices.EqualFunc(a.ASPathRaw, b.ASPathRaw, func(x, y types.ASSegment) bool {
			return x.Type == y.Type && slices.Equal(x.ASNs, y.ASNs)
		}) &&
		a.Origin == b.Origin &&
		a.NextHop == b.NextHop &&
		slices.Equal(a.Communities, b.Communities) &&
		slices.Equal(a.LargeCommunities, b.LargeCommunities) &&
		a.RIBType == b.RIBType &&
		a.ROV.State == b.ROV.State &&
		a.ROV.Code == b.ROV.Code &&
		a.ROV.Reason == b.ROV.Reason &&
		a.ASPA.State == b.ASPA.State &&
		hopEqual(a.ASPA.FailingHop, b.ASPA.FailingHop) &&
		a.ASPA.Procedure == b.ASPA.Procedure &&
		a.ASPA.ProcedureSource == b.ASPA.ProcedureSource &&
		a.ASPA.Reason == b.ASPA.Reason &&
		a.SecurityPosture == b.SecurityPosture
}

func hopEqual(a, b *types.ASPAHop) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
