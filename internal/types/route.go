package types

import (
	"fmt"
	"net/netip"
	"time"
)

// ─── Route ───
// The central data object flowing through RAVEN's pipeline.
// Created by BMP Ingest, annotated by Validation Engine, stored in Route Table.

type Route struct {
	// Populated by BMP Ingest
	// Timestamp is when the route was received: the BMP per-peer header's
	// timestamp, the router's receive time, or RAVEN's if the router sent 0.
	Timestamp time.Time
	// Router is the monitored router the route was learned on: the source
	// address of its BMP session, IPv4 in plain form.
	Router netip.Addr
	// PeerDistinguisher is the BMP per-peer header's Peer Distinguisher
	// (RFC 7854 §4.2): zero for global-instance peers, the VRF's RD for
	// RD-instance peers. PeerType is that header's peer type.
	PeerDistinguisher uint64
	PeerType          uint8
	PeerAddr          netip.Addr
	PeerASN           uint32
	// PathID is the ADD-PATH path identifier (RFC 7911), or 0 when ADD-PATH
	// is not in effect for the peer and address family.
	PathID uint32
	// LocalASN is the monitoring router's own AS on the BMP session this
	// route was learned over (from the Peer Up message's Sent OPEN). Zero
	// if unknown. Not used by ASPA verification: the draft never checks the
	// neighbor-to-verifier edge. It is the origin AS of a route with an
	// empty AS_PATH (see OriginAS). Whatever learns the route may set it;
	// BMP sets it from Peer Up, and on a Loc-RIB route from the Loc-RIB
	// per-peer header's Peer AS (RFC 9069 §4.1).
	LocalASN uint32
	// ConfedID is the monitored router's AS confederation identifier
	// (RFC 5065), the AS its confederation is known by outside it, when
	// known; zero otherwise, including for a router not in a confederation.
	// When set, it is the origin AS of an empty AS_PATH or one ending in a
	// confederation segment (see OriginAS).
	ConfedID uint32

	RouterID         netip.Addr
	Prefix           netip.Prefix
	ASPath           []uint32    // flattened (AS_SETs expanded)
	ASPathRaw        []ASSegment // preserving segment types for ASPA
	Origin           OriginType  // IGP/EGP/Incomplete
	NextHop          netip.Addr
	Communities      []Community
	LargeCommunities []LargeCommunity
	RIBType          RIBType

	// Populated by Validation Engine
	ROV             ROVResult
	ASPA            ASPAResult
	SecurityPosture SecurityPosture

	// Stale is set on routes restored from a snapshot. It is cleared
	// when a live BMP Route Monitoring message confirms the route is
	// still active. Stale routes are excluded from Event Engine
	// evaluation.
	Stale bool

	// OwnerSession is the ID of the BMP session that last announced this
	// route (see IngestEvent.Session). Withdraw-alls only remove routes
	// their own session owns. Zero means no live session owns the route,
	// e.g. one restored from a snapshot.
	OwnerSession uint64
}

// Withdrawal represents a BGP route withdrawal received via BMP.
type Withdrawal struct {
	Router            netip.Addr
	PeerDistinguisher uint64
	PeerAddr          netip.Addr
	Prefix            netip.Prefix
	PathID            uint32
	// RIBType is the withdrawn route's RIB. On a WithdrawAll it is the
	// scope: LocRIB withdraws the peer's Loc-RIB routes (a Loc-RIB
	// instance's Peer Down), any other value the peer's Adj-RIB-In and
	// Adj-RIB-Out routes (a BGP peer's Peer Down). Neither removes the
	// other's routes.
	RIBType     RIBType
	WithdrawAll bool // if true, withdraw all of the session's routes from the peer
	// SessionEnd withdraws every route the session owns, from any peer.
	// PeerAddr and Prefix are ignored.
	SessionEnd bool
}

// IngestEvent is one item on the BMP ingest stream. Exactly one of Route or
// Withdrawal is set, unless Superseded is.
//
// Routes and withdrawals share one channel so the Route Table applies them in
// the order the router sent them. On separate channels a peer-down could be
// applied while that peer's routes were still queued, and those routes were
// then re-inserted after the wipe and never removed.
type IngestEvent struct {
	Route      *Route
	Withdrawal *Withdrawal
	// Session is the ID of the BMP session the event came from. IDs are
	// unique and increase with each accepted connection; zero is never
	// assigned to a live session.
	//
	// A router that reconnects while its old socket is still open has two
	// sessions at once. Without the ID, the old session's withdraw-all on
	// close removed routes the new session had just re-announced.
	Session uint64
	// Superseded marks a control event, with neither Route nor Withdrawal
	// set: a newer session from the same router has replaced Session. The
	// Route Table drops any later event from Session except its final
	// SessionEnd withdrawal.
	Superseded bool
}

// OriginSource says where a route's origin AS comes from (see OriginAS).
type OriginSource uint8

const (
	// OriginFromPath: the rightmost AS of the final AS_SEQUENCE.
	OriginFromPath OriginSource = iota
	// OriginNone: the final segment is an AS_SET, so the origin is NONE.
	OriginNone
	// OriginLocalAS: the AS_PATH is empty, so the origin is the router's
	// own AS (LocalASN).
	OriginLocalAS
	// OriginLocalConfedID: as OriginLocalAS, but the router is in a
	// confederation whose identifier (ConfedID) is known, and that is the
	// origin.
	OriginLocalConfedID
	// OriginConfedID: the final segment is a confederation segment, so the
	// origin is the router's own AS, taken as its confederation identifier
	// (ConfedID).
	OriginConfedID
	// OriginConfedMember: as OriginConfedID, but with the identifier
	// unknown the origin is the router's member AS (LocalASN). ROAs are
	// registered under the confederation identifier, so a VRP may not match.
	OriginConfedMember
)

// OriginAS returns the route's origin AS per RFC 6811 §2, and where it came
// from. It is the rightmost AS of the AS_PATH's final segment if that is an
// AS_SEQUENCE. If the AS_PATH is empty or its final segment is an
// AS_CONFED_SEQUENCE or AS_CONFED_SET, it is the BGP speaker's own AS: here
// the monitored router's confederation identifier (ConfedID) if known,
// since ROAs for a confederation name the AS it is known by, else its own
// AS on the session (LocalASN), the member AS inside a confederation.
// After a final AS_SET the origin is NONE (see OriginIsNone) and the AS 0.
//
// The AS is 0 when the router's own AS is needed but not known. A route
// with no ASPathRaw (one built without segments) uses the last AS of ASPath,
// or the local AS if that is empty too.
//
// A Loc-RIB path that holds only the router's own AS counts as empty (see
// EmptyPath): some routers (FRR 10.2) put their AS first in a Loc-RIB
// AS_PATH, so a locally originated route arrives as [LocalASN].
func (r *Route) OriginAS() (uint32, OriginSource) {
	if r.onlyLocalAS() {
		if r.ConfedID != 0 {
			return r.ConfedID, OriginLocalConfedID
		}
		return r.LocalASN, OriginLocalAS
	}
	if n := len(r.ASPathRaw); n > 0 {
		last := r.ASPathRaw[n-1]
		switch {
		case last.Type.IsConfed():
			if r.ConfedID != 0 {
				return r.ConfedID, OriginConfedID
			}
			return r.LocalASN, OriginConfedMember
		case last.Type != ASSegmentSequence:
			return 0, OriginNone
		case len(last.ASNs) == 0:
			return 0, OriginFromPath
		}
		return last.ASNs[len(last.ASNs)-1], OriginFromPath
	}
	if len(r.ASPath) == 0 {
		if r.ConfedID != 0 {
			return r.ConfedID, OriginLocalConfedID
		}
		return r.LocalASN, OriginLocalAS
	}
	return r.ASPath[len(r.ASPath)-1], OriginFromPath
}

// EmptyPath reports whether the route's AS_PATH is empty for the origin
// rule (OriginAS): it has no AS, or it is a Loc-RIB route's and holds only
// the router's own AS (LocalASN), in AS_SEQUENCE segments, once or
// prepended.
func (r *Route) EmptyPath() bool {
	return (len(r.ASPathRaw) == 0 && len(r.ASPath) == 0) || r.onlyLocalAS()
}

// onlyLocalAS reports whether the route is a Loc-RIB route whose AS_PATH
// is not empty and holds only LocalASN, in AS_SEQUENCE segments.
func (r *Route) onlyLocalAS() bool {
	if r.RIBType != LocRIB || r.LocalASN == 0 || len(r.ASPath) == 0 {
		return false
	}
	for _, seg := range r.ASPathRaw {
		if seg.Type != ASSegmentSequence {
			return false
		}
	}
	for _, asn := range r.ASPath {
		if asn != r.LocalASN {
			return false
		}
	}
	return true
}

// OriginASN returns the route's origin AS (see OriginAS), 0 if it is NONE
// or not known.
func (r *Route) OriginASN() uint32 {
	asn, _ := r.OriginAS()
	return asn
}

// OriginIsNone reports whether the route's origin is RFC 6811's NONE: the
// AS_PATH's final segment is an AS_SET (any type other than AS_SEQUENCE or
// a confederation segment). No VRP matches a NONE origin, so such a route
// is Invalid wherever a VRP covers it.
func (r *Route) OriginIsNone() bool {
	n := len(r.ASPathRaw)
	if n == 0 {
		return false
	}
	t := r.ASPathRaw[n-1].Type
	return t != ASSegmentSequence && !t.IsConfed()
}

// HasConfedSegment reports whether the AS_PATH has an AS_CONFED_SEQUENCE
// or AS_CONFED_SET segment. A router only accepts those from a peer inside
// its own AS confederation (RFC 5065 §5); outside it they are stripped
// (§4.1).
func (r *Route) HasConfedSegment() bool {
	for _, seg := range r.ASPathRaw {
		if seg.Type.IsConfed() {
			return true
		}
	}
	return false
}

// PeerRef identifies a BGP peer as one monitored router sees it: the router,
// the peer's instance (Peer Distinguisher) and its address. The same peer
// address on two routers, or in two VRFs of one router, is two peers.
// Addresses are IPv4 in plain form (see NewPeerRef).
type PeerRef struct {
	Router        netip.Addr
	Distinguisher uint64
	Addr          netip.Addr
}

// NewPeerRef returns the PeerRef for a peer, normalising IPv4-mapped
// addresses to plain IPv4.
func NewPeerRef(router netip.Addr, distinguisher uint64, addr netip.Addr) PeerRef {
	return PeerRef{Router: router.Unmap(), Distinguisher: distinguisher, Addr: addr.Unmap()}
}

// RouteKey uniquely identifies a route in the Route Table: one path (PathID,
// with ADD-PATH) to one prefix from one peer, in one RIB.
type RouteKey struct {
	Peer    PeerRef
	Prefix  netip.Prefix
	PathID  uint32
	RIBType RIBType
}

// Peer returns the route's peer.
func (r *Route) Peer() PeerRef {
	return NewPeerRef(r.Router, r.PeerDistinguisher, r.PeerAddr)
}

// Key returns the route's Route Table key.
func (r *Route) Key() RouteKey {
	return RouteKey{Peer: r.Peer(), Prefix: r.Prefix, PathID: r.PathID, RIBType: r.RIBType}
}

// Peer returns the withdrawal's peer.
func (w *Withdrawal) Peer() PeerRef {
	return NewPeerRef(w.Router, w.PeerDistinguisher, w.PeerAddr)
}

// Key returns the Route Table key of the route the withdrawal removes.
func (w *Withdrawal) Key() RouteKey {
	return RouteKey{Peer: w.Peer(), Prefix: w.Prefix, PathID: w.PathID, RIBType: w.RIBType}
}

// BMP peer types (RFC 7854 §4.2, RFC 9069 §4.1), as Route.PeerType holds them.
const (
	PeerTypeGlobal uint8 = 0
	PeerTypeRD     uint8 = 1
	PeerTypeLocal  uint8 = 2
	PeerTypeLocRIB uint8 = 3
)

// PeerTypeName names a BMP peer type: global, rd, local or loc-rib.
func PeerTypeName(t uint8) string {
	switch t {
	case PeerTypeGlobal:
		return "global"
	case PeerTypeRD:
		return "rd"
	case PeerTypeLocal:
		return "local"
	case PeerTypeLocRIB:
		return "loc-rib"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

// ─── AS_PATH types ───

type ASSegmentType uint8

const (
	ASSegmentSet            ASSegmentType = 1 // AS_SET
	ASSegmentSequence       ASSegmentType = 2 // AS_SEQUENCE
	ASSegmentConfedSequence ASSegmentType = 3 // AS_CONFED_SEQUENCE (RFC 5065)
	ASSegmentConfedSet      ASSegmentType = 4 // AS_CONFED_SET (RFC 5065)
)

// IsConfed reports whether t is a confederation segment type.
func (t ASSegmentType) IsConfed() bool {
	return t == ASSegmentConfedSequence || t == ASSegmentConfedSet
}

type ASSegment struct {
	Type ASSegmentType
	ASNs []uint32
}

// HasASSet returns true if the AS_PATH contains any AS_SET segments.
func (r *Route) HasASSet() bool {
	for _, seg := range r.ASPathRaw {
		if seg.Type == ASSegmentSet {
			return true
		}
	}
	return false
}

// ─── BGP Origin ───

type OriginType uint8

const (
	OriginIGP        OriginType = 0
	OriginEGP        OriginType = 1
	OriginIncomplete OriginType = 2
)

// ─── Communities ───

type Community struct {
	High uint16
	Low  uint16
}

// CommunityBlackhole is the well-known BLACKHOLE community, 65535:666
// (RFC 7999 §5).
var CommunityBlackhole = Community{High: 65535, Low: 666}

// String formats the community as "high:low", e.g. "65535:666".
func (c Community) String() string { return fmt.Sprintf("%d:%d", c.High, c.Low) }

type LargeCommunity struct {
	GlobalAdmin uint32
	LocalData1  uint32
	LocalData2  uint32
}

// String formats the large community as "global:local1:local2"
// (RFC 8092), e.g. "6695:1911:172".
func (c LargeCommunity) String() string {
	return fmt.Sprintf("%d:%d:%d", c.GlobalAdmin, c.LocalData1, c.LocalData2)
}

// HasCommunity reports whether the route carries community c.
func (r *Route) HasCommunity(c Community) bool {
	for _, x := range r.Communities {
		if x == c {
			return true
		}
	}
	return false
}

// ─── BMP RIB types ───

type RIBType uint8

const (
	AdjRIBInPre  RIBType = 0
	AdjRIBInPost RIBType = 1
	LocRIB       RIBType = 2
	// Adj-RIB-Out (RFC 8671, per-peer header O flag): routes the monitored
	// router sends to the peer, before or after its outbound policy.
	AdjRIBOutPre  RIBType = 3
	AdjRIBOutPost RIBType = 4
)

// AllRIBTypes lists every RIB type, in order.
var AllRIBTypes = []RIBType{AdjRIBInPre, AdjRIBInPost, LocRIB, AdjRIBOutPre, AdjRIBOutPost}

// RIBCounts holds a route count per RIB type, indexed by RIBType.
type RIBCounts [5]uint64

// RIBSet is a set of RIB types.
type RIBSet uint8

// RIBSetOf returns the set of the given RIB types.
func RIBSetOf(ribs ...RIBType) RIBSet {
	var s RIBSet
	for _, r := range ribs {
		s |= 1 << r
	}
	return s
}

// Has reports whether rib is in the set.
func (s RIBSet) Has(rib RIBType) bool { return rib < 8 && s&(1<<rib) != 0 }

// RIBs lists the set's RIB types, in RIBType order.
func (s RIBSet) RIBs() []RIBType {
	var out []RIBType
	for _, r := range AllRIBTypes {
		if s.Has(r) {
			out = append(out, r)
		}
	}
	return out
}

// Names lists the set's RIB names, in RIBType order.
func (s RIBSet) Names() []string {
	var out []string
	for _, r := range s.RIBs() {
		out = append(out, r.String())
	}
	return out
}

// DefaultView is the RIBs route queries return when none is named: what the
// routers received before import policy (Adj-RIB-In pre-policy) and what
// they selected (Loc-RIB). A router that sends only its Loc-RIB still shows
// its routes. Post-policy stays out: a router that sends it sends the same
// routes pre-policy too, and each would be listed twice. Adj-RIB-Out routes
// are sent, not received.
var DefaultView = RIBSetOf(AdjRIBInPre, LocRIB)

// ribAliases are other names ParseRIBType accepts: the pre-policy and
// post-policy names of the BMP Adj-RIB-In.
var ribAliases = map[string]RIBType{
	"pre-policy":  AdjRIBInPre,
	"post-policy": AdjRIBInPost,
}

// ParseRIBType returns the RIB type a name gives: a RIBType.String name, or
// an alias, pre-policy (adj-rib-in-pre) or post-policy (adj-rib-in-post).
func ParseRIBType(name string) (RIBType, error) {
	for _, r := range AllRIBTypes {
		if r.String() == name {
			return r, nil
		}
	}
	if r, ok := ribAliases[name]; ok {
		return r, nil
	}
	return 0, fmt.Errorf("unknown RIB %q: want adj-rib-in-pre (or pre-policy), adj-rib-in-post (or post-policy), loc-rib, adj-rib-out-pre or adj-rib-out-post", name)
}

// ParseRIBSet returns the set of the RIBs named, each as ParseRIBType takes
// it. No names is an error.
func ParseRIBSet(names []string) (RIBSet, error) {
	if len(names) == 0 {
		return 0, fmt.Errorf("no RIB given")
	}
	var s RIBSet
	for _, n := range names {
		r, err := ParseRIBType(n)
		if err != nil {
			return 0, err
		}
		s |= RIBSetOf(r)
	}
	return s, nil
}

// IsAdjRIBOut reports whether routes of this RIB are outbound: sent to the
// peer, not received from it.
func (t RIBType) IsAdjRIBOut() bool { return t == AdjRIBOutPre || t == AdjRIBOutPost }

func (t RIBType) String() string {
	switch t {
	case AdjRIBInPre:
		return "adj-rib-in-pre"
	case AdjRIBInPost:
		return "adj-rib-in-post"
	case LocRIB:
		return "loc-rib"
	case AdjRIBOutPre:
		return "adj-rib-out-pre"
	case AdjRIBOutPost:
		return "adj-rib-out-post"
	}
	return "unknown"
}

// ─── ROV (RFC 6811) ───

type ROVState uint8

const (
	ROVValid    ROVState = 0
	ROVInvalid  ROVState = 1
	ROVNotFound ROVState = 2
)

func (s ROVState) String() string {
	switch s {
	case ROVValid:
		return "Valid"
	case ROVInvalid:
		return "Invalid"
	case ROVNotFound:
		return "NotFound"
	default:
		return "Unknown"
	}
}

// ROVResult is a route's ROV annotation.
//
// MatchedVRPs is the VRP store's shared covering list (FindCovering), not a
// copy, so it costs a slice header per route. Code is one byte that sits in
// the padding after State, so adding it did not grow the struct: the route
// table holds millions of these. Which VRPs matched, and how, is worked out
// again at query time (rov.Annotator.Explain) rather than stored.
type ROVResult struct {
	State       ROVState
	Code        ROVReasonCode
	MatchedVRPs []VRP
	Reason      string
}

// ROVReasonCode says why a route has its ROV state, as RFC 6811 and
// Routinator's validity API classify it. The zero value, ROVReasonUnknown,
// is a route not validated since it was restored from a snapshot (snapshots
// keep only the state).
type ROVReasonCode uint8

const (
	ROVReasonUnknown ROVReasonCode = iota
	// ROVReasonValid: a covering VRP has the route's origin AS and a
	// maxLength at least the route's prefix length.
	ROVReasonValid
	// ROVReasonNotFound: no VRP covers the prefix, or the origin is not
	// known (an empty AS_PATH from a router whose AS RAVEN does not know).
	ROVReasonNotFound
	// ROVReasonInvalidLength: a covering VRP has the route's origin AS, but
	// the prefix is longer than its maxLength. It takes precedence over
	// ROVReasonInvalidOrigin when other covering VRPs name other ASes.
	ROVReasonInvalidLength
	// ROVReasonInvalidOrigin: covering VRPs exist, none has the route's
	// origin AS, and not all of them are AS0.
	ROVReasonInvalidOrigin
	// ROVReasonInvalidAS0: every covering VRP is AS0 (RFC 6483 §4, RFC
	// 7607): the holder says the prefix should not be routed at all.
	ROVReasonInvalidAS0
	// ROVReasonInvalidASSet: the AS_PATH ends in an AS_SET, so the origin
	// is NONE (RFC 6811 §2), which no covering VRP matches.
	ROVReasonInvalidASSet
)

var rovReasonNames = [...]string{
	ROVReasonUnknown:       "",
	ROVReasonValid:         "valid",
	ROVReasonNotFound:      "not_found",
	ROVReasonInvalidLength: "invalid_length",
	ROVReasonInvalidOrigin: "invalid_origin",
	ROVReasonInvalidAS0:    "invalid_as0",
	ROVReasonInvalidASSet:  "invalid_as_set",
}

// String names the code as the API's rov_reason_code gives it: valid,
// not_found, invalid_length, invalid_origin, invalid_as0 or invalid_as_set;
// "" for ROVReasonUnknown.
func (c ROVReasonCode) String() string {
	if int(c) < len(rovReasonNames) {
		return rovReasonNames[c]
	}
	return "unknown"
}

// ROVReasonCodes lists the known codes, ROVReasonUnknown excluded, in order.
var ROVReasonCodes = []ROVReasonCode{
	ROVReasonValid, ROVReasonNotFound, ROVReasonInvalidLength,
	ROVReasonInvalidOrigin, ROVReasonInvalidAS0, ROVReasonInvalidASSet,
}

type VRP struct {
	Prefix    netip.Prefix
	ASN       uint32
	MaxLength uint8
}

// ─── ASPA (draft-ietf-sidrops-aspa-verification) ───

type ASPAState uint8

const (
	ASPAValid        ASPAState = 0
	ASPAInvalid      ASPAState = 1
	ASPAUnknown      ASPAState = 2
	ASPAUnverifiable ASPAState = 3
)

func (s ASPAState) String() string {
	switch s {
	case ASPAValid:
		return "Valid"
	case ASPAInvalid:
		return "Invalid"
	case ASPAUnknown:
		return "Unknown"
	case ASPAUnverifiable:
		return "Unverifiable"
	default:
		return "Unknown"
	}
}

type ASPAProcedure uint8

const (
	ASPAUpstream   ASPAProcedure = 0
	ASPADownstream ASPAProcedure = 1
)

func (p ASPAProcedure) String() string {
	if p == ASPADownstream {
		return "downstream"
	}
	return "upstream"
}

// ASPAProcedureSource records where a route's ASPA procedure came from.
type ASPAProcedureSource uint8

const (
	ASPASourceDefault       ASPAProcedureSource = 0 // validation.aspa-default-procedure
	ASPASourceConfigAddress ASPAProcedureSource = 1 // validation.aspa-peers entry by address
	ASPASourceConfigASN     ASPAProcedureSource = 2 // validation.aspa-peers entry by asn
)

func (s ASPAProcedureSource) String() string {
	switch s {
	case ASPASourceConfigAddress:
		return "config-address"
	case ASPASourceConfigASN:
		return "config-asn"
	default:
		return "default"
	}
}

type HopAuth uint8

const (
	HopAuthorized    HopAuth = 0
	HopNotAuthorized HopAuth = 1
	HopNoASPA        HopAuth = 2
	HopSkipped       HopAuth = 3 // AS_SET segment in best-effort mode
)

type ASPAHop struct {
	CustomerASN   uint32
	ProviderASN   uint32
	Authorization HopAuth
	Reason        string // human-readable (e.g., "AS_SET segment skipped")
}

type ASPAResult struct {
	State      ASPAState
	FailingHop *ASPAHop  // non-nil if State == Invalid
	HopDetails []ASPAHop // per-hop breakdown
	Procedure  ASPAProcedure
	// ProcedureSource says whether Procedure came from aspa-peers or the default.
	ProcedureSource ASPAProcedureSource
	// Reason explains an Invalid that no hop accounts for (neighbor-AS check).
	Reason string
}

// ASPARecord is a snapshot-friendly representation of a validated ASPA object.
// ProviderASNs is a sorted slice (not a map) for deterministic serialisation.
type ASPARecord struct {
	CustomerASN  uint32
	ProviderASNs []uint32
}

// ─── Security Posture (§2.4.3) ───
// Combined ROV × ASPA result

type SecurityPosture string

const (
	PostureSecured       SecurityPosture = "secured"
	PostureOriginOnly    SecurityPosture = "origin-only"
	PosturePathSuspect   SecurityPosture = "path-suspect"
	PosturePathOnly      SecurityPosture = "path-only"
	PostureUnverified    SecurityPosture = "unverified"
	PostureOriginInvalid SecurityPosture = "origin-invalid"
)

// ComputePosture derives the combined security posture from ROV and ASPA states.
// This implements the matrix from Architecture doc §2.4.3.
func ComputePosture(rov ROVState, aspa ASPAState) SecurityPosture {
	if rov == ROVInvalid {
		return PostureOriginInvalid
	}
	switch {
	case rov == ROVValid && aspa == ASPAValid:
		return PostureSecured
	case rov == ROVValid && (aspa == ASPAUnknown || aspa == ASPAUnverifiable):
		return PostureOriginOnly
	case rov == ROVValid && aspa == ASPAInvalid:
		return PosturePathSuspect
	case rov == ROVNotFound && aspa == ASPAValid:
		return PosturePathOnly
	case rov == ROVNotFound && aspa == ASPAInvalid:
		return PosturePathSuspect
	default:
		// ROVNotFound + ASPAUnknown/Unverifiable
		return PostureUnverified
	}
}

// FormatRD renders a Peer Distinguisher as a route distinguisher (RFC 4364
// §4.2): type 0 "ASN:n", type 1 "IPv4:n", type 2 "ASN4L:n"; any other value
// in hex. Zero (a global-instance peer) renders as "". The L after a type 2
// AS number keeps it apart from the type 0 RD with the same numbers:
// 65000L:1 and 65000:1 are two instances, and the text is used as a key
// (metric labels, event cooldown, audit rows).
func FormatRD(rd uint64) string {
	if rd == 0 {
		return ""
	}
	switch rd >> 48 {
	case 0:
		return fmt.Sprintf("%d:%d", (rd>>32)&0xffff, rd&0xffffffff)
	case 1:
		ip := netip.AddrFrom4([4]byte{byte(rd >> 40), byte(rd >> 32), byte(rd >> 24), byte(rd >> 16)})
		return fmt.Sprintf("%s:%d", ip, rd&0xffff)
	case 2:
		return fmt.Sprintf("%dL:%d", (rd>>16)&0xffffffff, rd&0xffff)
	}
	return fmt.Sprintf("0x%016x", rd)
}
