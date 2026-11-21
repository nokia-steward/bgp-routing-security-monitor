package server

import (
	"context"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/events"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// dataGaugeEvery is how often each cache's data age is evaluated between
// syncs (DataTracker.Tick) and raven_rtr_data_age_seconds brought up to
// date, unless Server.dataTick says otherwise (tests).
const dataGaugeEvery = 15 * time.Second

// observeData feeds one RTR sync record to the data tracker, and reports
// what it found: a log line when a stale episode starts and ends and on a
// return to earlier data, the data gauges and regression counter, and the
// rtr_stale and rtr_data_regressed events (notification actions only, see
// events.Rule). It runs on the RTR client's goroutine.
func (s *Server) observeData(ev telemetry.SessionEvent) {
	s.reportData(s.data.Observe(ev), ev.Timestamp)
}

// reportData reports what the data tracker found at now (see observeData).
func (s *Server) reportData(found []telemetry.DataEvent, now time.Time) {
	for _, de := range found {
		if de.Kind == telemetry.DataRegressed {
			metrics.RTRDataRegressions.WithLabelValues(de.Cache).Inc()
		}
	}
	// Gauges first: whoever gets the event sees them current.
	s.updateDataGauges(now)
	for _, de := range found {
		switch de.Kind {
		case telemetry.DataStale:
			s.log.Warn("RTR cache data stale: syncing, but its data has not changed for longer than its threshold",
				"cache", de.Cache, "serial", de.Serial, "last_change", de.LastChange, "unchanged_for", de.Gap,
				"threshold", de.ExpectedGap, "threshold_source", de.ThresholdSource, "syncs_without_change", de.SyncsWithoutChange,
				"cache_state", de.CacheState)
			s.emitDataEvent(events.Event{
				ID: events.NewID(), Timestamp: de.Timestamp, Type: events.EventTypeRTRStale,
				CacheName: de.Cache, Serial: de.Serial, Source: events.SourceRTR,
				Data: &events.DataChange{LastChange: de.LastChange, Gap: de.Gap, Threshold: de.ExpectedGap,
					ThresholdSource: string(de.ThresholdSource), SyncsWithoutChange: de.SyncsWithoutChange,
					CacheState: de.CacheState},
			})
		case telemetry.DataStaleResolved:
			s.log.Info("RTR cache data changing again", "cache", de.Cache, "resolution", de.Resolution, "stale_for", de.Duration,
				"unchanged_for", de.Gap, "serial_before", de.SerialBefore, "serial_after", de.SerialAfter)
		case telemetry.DataRegressed:
			s.log.Warn("RTR cache returned to earlier data", "cache", de.Cache, "last_current", de.LastCurrent,
				"ago", de.Ago, "first_current", de.FirstCurrent, "serial_before", de.SerialBefore,
				"serial_after", de.SerialAfter, "sync_type", de.SyncType)
			s.emitDataEvent(events.Event{
				ID: events.NewID(), Timestamp: de.Timestamp, Type: events.EventTypeRTRDataRegressed,
				CacheName: de.Cache, Serial: de.SerialAfter, Source: events.SourceRTR,
				Data: &events.DataChange{SerialBefore: de.SerialBefore, SerialAfter: de.SerialAfter,
					FirstCurrent: de.FirstCurrent, LastCurrent: de.LastCurrent, Ago: de.Ago},
			})
		}
	}
}

// emitDataEvent hands an rtr_stale or rtr_data_regressed event to the event
// engine, if there is one.
func (s *Server) emitDataEvent(ev events.Event) {
	if s.eventEngine == nil {
		return
	}
	s.emitEvent(ev)
}

// updateDataGauges sets every cache's data age and stale flag as of now.
func (s *Server) updateDataGauges(now time.Time) {
	for _, cache := range s.data.Caches() {
		if st, ok := s.data.Status(cache, now); ok {
			metrics.SetRTRData(cache, st.Age, st.CacheState)
		}
	}
}

// runDataGauges evaluates every cache's data age between syncs until ctx is
// done: a cache goes stale when its data outlasts its threshold, not at its
// next sync, and one that stops syncing goes stale too.
func (s *Server) runDataGauges(ctx context.Context) {
	if s.data == nil {
		return
	}
	every := dataGaugeEvery
	if s.dataTick > 0 {
		every = s.dataTick
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			s.reportData(s.data.Tick(now), now)
		}
	}
}
