// Package events implements the RAVEN Phase 3 active-response event engine.
// It defines event types, triggers, actions, rules, and the engine that
// evaluates them in response to BGP security state changes.
package events

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// EventType distinguishes what triggered the event.
type EventType string

const (
	// EventTypeNewRoute fires when a route is seen for the first time.
	EventTypeNewRoute EventType = "new_route"
	// EventTypePostureChange fires when an existing route changes security posture.
	EventTypePostureChange EventType = "posture_change"
	// EventTypeRouteWithdraw fires when a route is withdrawn via BMP.
	EventTypeRouteWithdraw EventType = "route_withdraw"
	// EventTypeCacheUnhealthy fires when an RTR cache goes stale or unreachable.
	EventTypeCacheUnhealthy EventType = "cache_unhealthy"
	// EventTypeRTRBulkChange stands for one RTR update (one revalidation
	// pass) that changed many routes at once. It goes, once per pass, to
	// the rules with an rtr_bulk_change trigger when the pass changed the
	// posture of more routes than events.rtr-bulk-threshold, and, when more
	// than that matched rules with actions (Bulk.Suppressed), to those
	// rules in place of their per-route events. Bulk says what changed;
	// Route is nil. Only notification actions run for it.
	EventTypeRTRBulkChange EventType = "rtr_bulk_change"
	// EventTypeRTRStale fires once when an RTR cache's data starts a stale
	// episode: the cache syncs, but its data (VRPs and ASPAs) has not
	// changed for longer than its staleness threshold. Data says how long;
	// Route is nil. Only notification actions run for it.
	EventTypeRTRStale EventType = "rtr_stale"
	// EventTypeRTRDataRegressed fires when an RTR cache returns to a data
	// set it served earlier (an anycast reconnect to a lagging node, say).
	// Data says which; Route is nil. Only notification actions run for it.
	EventTypeRTRDataRegressed EventType = "rtr_data_regressed"
)

// notificationOnly reports whether events of type t reach notification
// actions only (webhook, log), never FlowSpec: they are about an RTR cache
// or many routes, not one route.
func notificationOnly(t EventType) bool {
	return t == EventTypeRTRBulkChange || t == EventTypeRTRStale || t == EventTypeRTRDataRegressed
}

// DataChange is what an rtr_stale or rtr_data_regressed event reports about
// the cache's data (see telemetry.DataTracker).
type DataChange struct {
	// rtr_stale: when the current data became current, how long ago, the
	// threshold it outlasted and where that came from, and the syncs that
	// saw no change.
	LastChange         time.Time
	Gap                time.Duration
	Threshold          time.Duration
	ThresholdSource    string
	SyncsWithoutChange int
	// CacheState is connected (serving frozen data) or disconnected
	// (unreachable while its last data ages), as the episode began.
	CacheState string
	// rtr_data_regressed: the serials before and after, and when the set
	// returned to was first and last current, and how long ago that was.
	SerialBefore, SerialAfter uint32
	FirstCurrent, LastCurrent time.Time
	Ago                       time.Duration
}

// Source says what produced an event's route state change.
const (
	// SourceBMP is a BMP announcement or withdrawal.
	SourceBMP = "bmp"
	// SourceRTR is an RTR update: revalidation against new VRP or ASPA
	// data.
	SourceRTR = "rtr"
)

// BulkChange is what one RTR update changed, on an rtr_bulk_change event.
type BulkChange struct {
	// Threshold is events.rtr-bulk-threshold.
	Threshold int
	// Changes is every posture change in the pass. More than Threshold
	// fires the rtr_bulk_change rules.
	Changes BulkCounts
	// Matched is the changes that matched a rule with an action. More than
	// Threshold suppresses their per-route events (Suppressed).
	Matched BulkCounts
	// Suppressed says the matched changes' per-route actions were not run.
	Suppressed bool
}

// BulkCounts is a set of route changes: how many, by posture transition
// ("old-posture->new-posture"), and the prefixes of up to MaxBulkSamples of
// them, in the order they changed (a prefix appears once).
type BulkCounts struct {
	Routes         int
	Transitions    map[string]int
	SamplePrefixes []string
}

// MaxBulkSamples is how many prefixes an rtr_bulk_change event lists.
const MaxBulkSamples = 20

// Event is the payload passed to every trigger and action.
type Event struct {
	// ID is a UUID v4 generated at event creation.
	ID        string
	Timestamp time.Time
	Type      EventType
	// Route is the BGP route associated with this event. Nil for CacheUnhealthy events.
	Route *types.Route
	// OldPosture is the security posture before the change; empty for EventTypeNewRoute.
	OldPosture types.SecurityPosture
	// NewPosture is the current security posture after validation.
	NewPosture types.SecurityPosture
	// CacheName is populated for EventTypeCacheUnhealthy events.
	CacheName string
	// RouterID is the router that sourced this event.
	RouterID string
	// Source is SourceBMP or SourceRTR for route events, SourceRTR for an
	// rtr_bulk_change event; empty for events that are about neither.
	Source string
	// Serial is the RTR cache's serial after the update, on RTR-driven
	// events (SourceRTR); 0 otherwise. With several caches' updates in one
	// revalidation pass it is the last one's.
	Serial uint32
	// Bulk is set on EventTypeRTRBulkChange events only. CacheName then
	// names the cache, or the caches comma-separated, whose update it was.
	Bulk *BulkChange
	// Data is set on EventTypeRTRStale and EventTypeRTRDataRegressed events
	// only. CacheName names the cache; Serial is its serial.
	Data *DataChange
	// GlobalVisibility is attached by the global-correlate action when a
	// matching rule includes one. Nil when no correlation ran, which is the
	// case for every rule that does not opt in.
	//
	// It is a standalone annotation and does not affect NewPosture.
	GlobalVisibility *external.GlobalVisibilityResult

	// targets, if not nil, are the indexes of the rules this event is
	// delivered to without their trigger being asked (an rtr_bulk_change
	// event's rules); every other rule still sees it through its trigger.
	targets []bool
}

// NewID returns a random UUID v4 string suitable for use as an event identifier.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
