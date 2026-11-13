package telemetry

import (
	"encoding/json"
	"time"
)

// SyncType indicates whether a sync cycle was triggered by a Reset Query
// (full table dump) or a Serial Query (incremental update).
type SyncType string

const (
	SyncTypeFull        SyncType = "full"
	SyncTypeIncremental SyncType = "incremental"
)

// ResetReason classifies why an RTR session was reset or reconnected.
type ResetReason string

const (
	ResetReasonCacheResetPDU      ResetReason = "cache_reset_pdu"     // cache sent PDUCacheReset mid-session
	ResetReasonReconnectError     ResetReason = "reconnect_error"     // session failed and reconnected
	ResetReasonReconnectTimeout   ResetReason = "reconnect_timeout"   // TCP stall or read deadline
	ResetReasonVersionNegotiation ResetReason = "version_negotiation" // fell back to lower RTR version
)

// EventType classifies a SessionEvent.
type EventType string

const (
	EventConnected    EventType = "connected"
	EventDisconnected EventType = "disconnected"
	EventSync         EventType = "sync"
	EventReset        EventType = "reset"
	EventError        EventType = "error"
	// EventCacheNotReady is an Error Report with code 2 (No Data Available):
	// the cache is still building its first data set, e.g. Routinator's
	// "Running initial validation" at startup. Not a fault; the client
	// retries at the same version. Carries ErrorCode and ErrorText.
	EventCacheNotReady EventType = "cache_not_ready"
	// EventVersionDowngrade is a step of RTR version negotiation: the cache
	// turned down ProtoVersion before answering any query on the session,
	// and the client retries at NextProtoVersion. DowngradeReason says how
	// the cache turned it down: an Error Report code 4 (with ErrorCode and
	// ErrorText) or a dropped connection (with DisconnectReason).
	// Informational, not a fault and not an anomaly.
	EventVersionDowngrade EventType = "version_downgrade"
)

// ErrorOriginClient marks an error event RAVEN raised itself, about PDUs the
// cache sent (see SessionEvent.ErrorOrigin).
const ErrorOriginClient = "client"

// ErrorCodeDuplicateAnnouncement is RTR error code 7, Duplicate Announcement
// Received (RFC 8210 §12).
const ErrorCodeDuplicateAnnouncement uint16 = 7

// DisconnectReason says why a session ended (disconnected events).
type DisconnectReason string

const (
	DisconnectReasonEOF            DisconnectReason = "eof"             // the cache closed the connection (FIN)
	DisconnectReasonReset          DisconnectReason = "reset"           // the connection was reset (RST, broken pipe)
	DisconnectReasonErrorReport    DisconnectReason = "error_report"    // the cache sent an Error Report; error_code says which
	DisconnectReasonTimeout        DisconnectReason = "timeout"         // no response within the Retry Interval, or a TCP timeout
	DisconnectReasonShutdown       DisconnectReason = "shutdown"        // the client is stopping
	DisconnectReasonVersionUpgrade DisconnectReason = "version_upgrade" // a re-probe found the configured version; reconnecting at it
	DisconnectReasonError          DisconnectReason = "error"           // any other read, write or protocol error; error_text says which
)

// DisconnectReasons lists every DisconnectReason, for metric labels.
var DisconnectReasons = []DisconnectReason{
	DisconnectReasonEOF, DisconnectReasonReset, DisconnectReasonErrorReport, DisconnectReasonTimeout,
	DisconnectReasonShutdown, DisconnectReasonVersionUpgrade, DisconnectReasonError,
}

// Why the client lowered the RTR version (version_downgrade events).
const (
	DowngradeReasonUnsupportedVersion = "unsupported_version" // Error Report code 4
	DowngradeReasonSessionDropped     = "session_dropped"     // closed or reset before any response
)

// NDJSONSchemaVersion is the version of the NDJSON contract (the
// schema_version field of every record raven rtr monitor writes), documented
// in docs/reference/telemetry-ndjson.md and schema/rtr-monitor-ndjson.v1.json.
// Within a version, changes are additive only; removing, renaming or
// retyping anything needs a new version.
const NDJSONSchemaVersion = 1

// SessionEvent captures a single RTR session lifecycle or sync event.
// It is the atomic unit written to the NDJSON log and emitted on the
// event channel consumed by the anomaly detector.
type SessionEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Cache     string    `json:"cache"`
	EventType EventType `json:"event_type"`
	// SchemaVersion is NDJSONSchemaVersion, set by the Recorder on every
	// record it writes.
	SchemaVersion int `json:"schema_version"`

	// Sync fields — populated when EventType == EventSync.
	Serial        uint32        `json:"serial,omitempty"`
	VRPTotal      int           `json:"vrp_total,omitempty"`
	VRPAnnounced  int           `json:"vrp_announced,omitempty"`
	VRPWithdrawn  int           `json:"vrp_withdrawn,omitempty"`
	ASPATotal     int           `json:"aspa_total,omitempty"`
	ASPAAnnounced int           `json:"aspa_announced,omitempty"`
	ASPAWithdrawn int           `json:"aspa_withdrawn,omitempty"`
	SyncDuration  time.Duration `json:"sync_duration_ns,omitempty"`
	IntervalSince time.Duration `json:"interval_since_ns,omitempty"`
	SyncType      SyncType      `json:"sync_type,omitempty"`

	// SerialChanged is set on sync events: whether the serial differs from
	// the previous sync's, i.e. whether the cache had anything new. A poll
	// of a quiet cache completes a sync with SerialChanged false.
	SerialChanged *bool `json:"serial_changed,omitempty"`

	// Reset fields — populated when EventType == EventReset.
	ResetReason ResetReason `json:"reset_reason,omitempty"`

	// Error fields — populated when EventType is EventError,
	// EventCacheNotReady or EventVersionDowngrade (code 4), and on
	// EventDisconnected (error_code for an Error Report, error_text for any
	// failure).
	ErrorText string  `json:"error_text,omitempty"`
	ErrorCode *uint16 `json:"error_code,omitempty"` // RFC 8210 §12 error code

	// ErrorOrigin is ErrorOriginClient on an error RAVEN found in what the
	// cache sent, rather than an Error Report from the cache (absent). Such
	// an error does not end the session: RAVEN ignores the PDUs in error.
	// ErrorCount is how many PDUs of the sync had it.
	ErrorOrigin string `json:"error_origin,omitempty"`
	ErrorCount  int    `json:"error_count,omitempty"`

	// ProtoVersion is the session's RTR protocol version, on every event
	// the RTR client records. Always present, 0 included: version 0 means
	// the cache serves no ASPA. On connected and version_downgrade it is the
	// version the client asked for.
	ProtoVersion uint8 `json:"proto_version"`

	// Disconnect fields — populated when EventType == EventDisconnected
	// (one of the DisconnectReason values), and on a version_downgrade
	// caused by a dropped connection.
	DisconnectReason string `json:"disconnect_reason,omitempty"`

	// Version negotiation fields — populated when EventType ==
	// EventVersionDowngrade: the version the client retries at, and why.
	NextProtoVersion *uint8 `json:"next_proto_version,omitempty"`
	DowngradeReason  string `json:"downgrade_reason,omitempty"`
}

// MarshalJSON writes the event as its NDJSON record. A sync record carries
// its serial, counts and duration always, 0 included (the struct tags'
// omitempty applies to the other record types, which have none of them);
// interval_since_ns stays absent on the first sync. Older RAVENs omitted
// these when 0.
func (e SessionEvent) MarshalJSON() ([]byte, error) {
	type plain SessionEvent // without this method
	if e.EventType != EventSync {
		return json.Marshal(plain(e))
	}
	// The outer fields, shallower than the embedded ones of the same name,
	// are the ones encoded.
	return json.Marshal(struct {
		plain
		Serial        uint32        `json:"serial"`
		VRPTotal      int           `json:"vrp_total"`
		VRPAnnounced  int           `json:"vrp_announced"`
		VRPWithdrawn  int           `json:"vrp_withdrawn"`
		ASPATotal     int           `json:"aspa_total"`
		ASPAAnnounced int           `json:"aspa_announced"`
		ASPAWithdrawn int           `json:"aspa_withdrawn"`
		SyncDuration  time.Duration `json:"sync_duration_ns"`
	}{
		plain:         plain(e),
		Serial:        e.Serial,
		VRPTotal:      e.VRPTotal,
		VRPAnnounced:  e.VRPAnnounced,
		VRPWithdrawn:  e.VRPWithdrawn,
		ASPATotal:     e.ASPATotal,
		ASPAAnnounced: e.ASPAAnnounced,
		ASPAWithdrawn: e.ASPAWithdrawn,
		SyncDuration:  e.SyncDuration,
	})
}
