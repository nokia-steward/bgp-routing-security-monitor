package rov

import (
	"strconv"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Annotator performs Route Origin Validation per RFC 6811.
type Annotator struct {
	vrpStore *store.VRPStore
}

// NewAnnotator creates a ROV annotator backed by the given VRP store.
func NewAnnotator(vrpStore *store.VRPStore) *Annotator {
	return &Annotator{vrpStore: vrpStore}
}

// Validate performs ROV on a single route and returns the result.
//
// Algorithm (RFC 6811 §2):
//  1. Take the route's origin AS (types.Route.OriginAS): the last AS of a
//     final AS_SEQUENCE; NONE after a final AS_SET; the router's own AS for
//     an empty AS_PATH or one ending in a confederation segment.
//  2. Find all VRPs whose prefix covers the route's prefix.
//  3. If no covering VRPs exist → NotFound.
//  4. If any covering VRP matches the origin ASN AND the route's
//     prefix length ≤ VRP's maxLength → Valid. A NONE origin matches none.
//  5. Otherwise → Invalid.
//
// The result's Code says which case decided it (see decide), and Reason
// names the VRP that did. Before codes existed every Invalid with a known
// origin was reported as an origin mismatch, including routes Invalid only
// because they were longer than their own AS's VRP allowed.
//
// An origin that is the router's own AS is validated like any other, and
// the Reason says where it came from. If RAVEN does not know that AS the
// route is NotFound (localASUnknownReason).
func (a *Annotator) Validate(route *types.Route) types.ROVResult {
	c := a.classify(route)
	res := types.ROVResult{State: c.v.state, Code: c.v.code, MatchedVRPs: c.covering}
	note := localOriginNotes[c.src]
	switch c.v.code {
	case types.ROVReasonInvalidASSet:
		res.Reason = noneOriginInvalidReason
	case types.ROVReasonNotFound:
		res.MatchedVRPs = nil
		switch {
		case c.src == types.OriginNone:
			res.Reason = noneOriginNotFoundReason
		case c.origin == 0 && c.src == types.OriginFromPath:
			res.Reason = "no origin ASN in AS_PATH"
		case c.origin == 0:
			res.Reason = localASUnknownReason
		case note != "":
			res.Reason = localOriginNotFoundReasons[c.src]
		default:
			res.Reason = "no covering VRPs found"
		}
	default:
		res.Reason = reason(c.v.code, c.covering[c.v.vrp], c.origin, route.Prefix.Bits(), note)
	}
	return res
}

// Explanation is a route's ROV worked out again against the VRP store as it
// is now, with the covering VRPs split as Routinator's validity API splits
// them. It is built at query time, not stored on the route: a table of
// millions of routes keeps only the reason code. Until revalidation after an
// RTR update has reached a route, its stored code can lag what Explain says.
type Explanation struct {
	Code types.ROVReasonCode
	// Deciding is the VRP the reason names; HasDeciding is false when no VRP
	// decided the route (not_found).
	Deciding    types.VRP
	HasDeciding bool
	// Matched have the route's origin AS and allow its length;
	// UnmatchedLength have its origin AS but a shorter maxLength;
	// UnmatchedAS name another AS (AS0 included). A route whose origin is
	// NONE or not known has every covering VRP in UnmatchedAS. Each list is
	// shortest VRP prefix first, then in store order.
	Matched, UnmatchedAS, UnmatchedLength []types.VRP
}

// Explain classifies route against the current VRP store and lists the
// covering VRPs by how they relate to it. Unlike Validate it allocates the
// lists, so it is meant for the routes a query returns.
func (a *Annotator) Explain(route *types.Route) Explanation {
	c := a.classify(route)
	e := Explanation{Code: c.v.code}
	if c.v.vrp >= 0 {
		e.Deciding, e.HasDeciding = c.covering[c.v.vrp], true
	}
	known := c.src != types.OriginNone && c.origin != 0
	bits := route.Prefix.Bits()
	for _, v := range c.covering {
		switch {
		case !known || v.ASN != c.origin:
			e.UnmatchedAS = append(e.UnmatchedAS, v)
		case bits <= int(v.MaxLength):
			e.Matched = append(e.Matched, v)
		default:
			e.UnmatchedLength = append(e.UnmatchedLength, v)
		}
	}
	return e
}

// classified is a route's origin, its covering VRPs and their verdict.
type classified struct {
	v        verdict
	origin   uint32
	src      types.OriginSource
	covering []types.VRP
}

// classify works out route's verdict against the published VRP set. The
// covering list is the store's, shared; it is looked up even for a route
// whose origin is not known, for Explain.
func (a *Annotator) classify(route *types.Route) classified {
	origin, src := route.OriginAS()
	c := classified{origin: origin, src: src, covering: a.vrpStore.FindCovering(route.Prefix)}
	switch {
	case len(c.covering) == 0 || (origin == 0 && src != types.OriginNone):
		c.v = verdict{types.ROVNotFound, types.ROVReasonNotFound, -1}
	case src == types.OriginNone:
		c.v = verdict{types.ROVInvalid, types.ROVReasonInvalidASSet, len(c.covering) - 1}
	default:
		c.v = decide(c.covering, origin, route.Prefix.Bits())
	}
	return c
}

// verdict is how the covering VRPs decide a route: its state, the reason
// code, and the index in the covering list of the VRP that decided it, -1
// if none did.
type verdict struct {
	state types.ROVState
	code  types.ROVReasonCode
	vrp   int
}

// decide classifies a route with a known, non-zero origin AS and prefix
// length bits against its covering VRPs (at least one), in Routinator's
// precedence:
//
//   - valid: a VRP has the origin and maxLength ≥ bits; the first one, in
//     covering order, decides.
//   - invalid_length: a VRP has the origin but every such maxLength is
//     shorter. This wins over invalid_origin even when other VRPs name other
//     ASes: the holder did authorize this origin, just not this length. The
//     VRP with the origin and the longest maxLength decides (the first, on a
//     tie).
//   - invalid_origin: no VRP has the origin, and at least one names an AS
//     other than AS0. The most specific such VRP decides.
//   - invalid_as0: every covering VRP is AS0 (RFC 6483 §4). The most
//     specific decides.
//
// An AS0 VRP never matches: origin is not 0 here.
func decide(covering []types.VRP, origin uint32, bits int) verdict {
	length, other := -1, -1
	for i, v := range covering {
		switch {
		case v.ASN == origin && bits <= int(v.MaxLength):
			return verdict{types.ROVValid, types.ROVReasonValid, i}
		case v.ASN == origin:
			if length < 0 || v.MaxLength > covering[length].MaxLength {
				length = i
			}
		case v.ASN != 0:
			other = i // covering is shortest first: the last is most specific
		}
	}
	switch {
	case length >= 0:
		return verdict{types.ROVInvalid, types.ROVReasonInvalidLength, length}
	case other >= 0:
		return verdict{types.ROVInvalid, types.ROVReasonInvalidOrigin, other}
	}
	return verdict{types.ROVInvalid, types.ROVReasonInvalidAS0, len(covering) - 1}
}

// localASUnknownReason is the ROV Reason when the origin is the router's own
// AS (an empty AS_PATH, or one ending in a confederation segment; RFC 6811
// §2) and RAVEN does not know it: no Peer Up OPEN gave it.
const localASUnknownReason = "origin unknown: local AS not known"

// localOriginNotes say, at the end of the ROV Reason, why the origin is the
// router's own AS (RFC 6811 §2), by types.OriginSource. RAVEN used to give
// such routes no origin and call them NotFound, wrongly citing §2 for the
// confederation case.
var localOriginNotes = [...]string{
	types.OriginLocalAS: "origin is the router's own AS: empty AS_PATH (RFC 6811 §2)",
	types.OriginLocalConfedID: "origin is the router's own AS, its confederation identifier: " +
		"empty AS_PATH (RFC 6811 §2)",
	types.OriginConfedID: "origin is the router's own AS, its confederation identifier: " +
		"AS_PATH ends in a confederation segment (RFC 6811 §2)",
	types.OriginConfedMember: "origin is the router's own AS, its member AS: AS_PATH ends in a " +
		"confederation segment (RFC 6811 §2) and the confederation identifier is not known",
}

// localOriginNotFoundReasons are the NotFound Reasons for those origins,
// built once so a NotFound result allocates nothing.
var localOriginNotFoundReasons = func() (r [len(localOriginNotes)]string) {
	for i, n := range localOriginNotes {
		if n != "" {
			r[i] = "no covering VRPs found; " + n
		}
	}
	return r
}()

// The ROV Reasons for a route whose AS_PATH ends in an AS_SET: its origin is
// NONE (RFC 6811 §2), Invalid under any covering VRP, NotFound otherwise.
// RAVEN used to take the set's last member as the origin, which a VRP could
// match.
const (
	noneOriginInvalidReason  = "origin is NONE: AS_PATH ends in an AS_SET (RFC 6811 §2), which no covering VRP can match"
	noneOriginNotFoundReason = "origin is NONE: AS_PATH ends in an AS_SET (RFC 6811 §2); no covering VRPs found"
)

// reason builds the Reason for a route decided by VRP v with a single
// allocation (fmt.Sprintf boxed each argument as well), then "; " and note
// if note is not empty:
//
//	valid:          matches VRP {94.177.129.0/24, AS202744, /24}
//	invalid_length: prefix length /32 exceeds maxLength /24 of VRP 94.177.129.0/24 AS202744
//	invalid_origin: origin AS64666 not authorized by any covering VRP; nearest VRP 198.51.100.0/24 AS13335 maxLength /24
//	invalid_as0:    every covering VRP is AS0 (RFC 6483 §4); nearest VRP 192.0.2.0/24 AS0 maxLength /24
//
// The valid text is the same as before codes existed.
func reason(code types.ROVReasonCode, v types.VRP, origin uint32, bits int, note string) string {
	var buf [256]byte
	b := buf[:0]
	switch code {
	case types.ROVReasonValid:
		b = append(b, "matches VRP {"...)
		b = v.Prefix.AppendTo(b)
		b = append(b, ", AS"...)
		b = strconv.AppendUint(b, uint64(v.ASN), 10)
		b = append(b, ", /"...)
		b = strconv.AppendUint(b, uint64(v.MaxLength), 10)
		b = append(b, '}')
	case types.ROVReasonInvalidLength:
		b = append(b, "prefix length /"...)
		b = strconv.AppendInt(b, int64(bits), 10)
		b = append(b, " exceeds maxLength /"...)
		b = strconv.AppendUint(b, uint64(v.MaxLength), 10)
		b = append(b, " of VRP "...)
		b = v.Prefix.AppendTo(b)
		b = append(b, " AS"...)
		b = strconv.AppendUint(b, uint64(v.ASN), 10)
	case types.ROVReasonInvalidOrigin:
		b = append(b, "origin AS"...)
		b = strconv.AppendUint(b, uint64(origin), 10)
		b = append(b, " not authorized by any covering VRP; nearest VRP "...)
		b = appendVRP(b, v)
	case types.ROVReasonInvalidAS0:
		b = append(b, "every covering VRP is AS0 (RFC 6483 §4); nearest VRP "...)
		b = appendVRP(b, v)
	}
	if note != "" {
		b = append(b, "; "...)
		b = append(b, note...)
	}
	return string(b)
}

func appendVRP(b []byte, v types.VRP) []byte {
	b = v.Prefix.AppendTo(b)
	b = append(b, " AS"...)
	b = strconv.AppendUint(b, uint64(v.ASN), 10)
	b = append(b, " maxLength /"...)
	return strconv.AppendUint(b, uint64(v.MaxLength), 10)
}

// FormatVRP formats a VRP as "prefix-maxLength ASn", e.g.
// "94.177.129.0/24-24 AS202744", the form route listings show it in.
func FormatVRP(v types.VRP) string {
	b := v.Prefix.AppendTo(make([]byte, 0, 64))
	b = append(b, '-')
	b = strconv.AppendUint(b, uint64(v.MaxLength), 10)
	b = append(b, " AS"...)
	return string(strconv.AppendUint(b, uint64(v.ASN), 10))
}
