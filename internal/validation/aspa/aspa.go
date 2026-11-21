// Package aspa implements AS_PATH verification per
// draft-ietf-sidrops-aspa-verification-24.
package aspa

import (
	"fmt"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Annotator performs ASPA AS_PATH verification.
type Annotator struct {
	aspaStore *store.ASPAStore
}

// NewAnnotator creates an ASPA annotator backed by the given store.
func NewAnnotator(aspaStore *store.ASPAStore) *Annotator {
	return &Annotator{aspaStore: aspaStore}
}

// Validate performs upstream AS_PATH verification on a route (draft §5.4,
// for routes received from a customer, lateral peer, RS or RS-client).
func (a *Annotator) Validate(route *types.Route) types.ASPAResult {
	return a.ValidateProcedure(route, types.ASPAUpstream)
}

// ValidateSelection verifies a route with the selected procedure. When the
// selection asks for it, the neighbor-AS check (§5.4/§5.5 step 2) runs first:
// if the most recently added AS is not the peer's ASN, the route is Invalid.
// Prepend collapsing never changes the most recently added AS. Routes with an
// empty AS_PATH or an unknown peer ASN skip the check.
func (a *Annotator) ValidateSelection(route *types.Route, sel Selection) types.ASPAResult {
	var res types.ASPAResult
	if route.HasConfedSegment() {
		res = confedResult(sel.Procedure)
	} else if sel.NeighborCheck && len(route.ASPath) > 0 && route.PeerASN != 0 && route.ASPath[0] != route.PeerASN {
		res = types.ASPAResult{
			State:     types.ASPAInvalid,
			Procedure: sel.Procedure,
			Reason: fmt.Sprintf("neighbor-AS check failed: first AS in AS_PATH is AS%d, peer is AS%d",
				route.ASPath[0], route.PeerASN),
		}
	} else {
		res = a.ValidateProcedure(route, sel.Procedure)
	}
	res.ProcedureSource = sel.Source
	return res
}

// ValidateProcedure performs AS_PATH verification on a route using the given
// procedure. Returns an ASPAResult with State, per-hop details, and failing
// hop if any.
//
// Algorithm per draft-ietf-sidrops-aspa-verification-24 §5:
//
//  0. If AS_PATH contains a confederation segment → Unverifiable, not
//     verified (§6.2; see confedResult).
//  1. If AS_PATH contains an AS_SET → Unverifiable. (The draft says Invalid;
//     RAVEN reports these separately.)
//  2. Empty AS_PATH (self-originated / iBGP) → Unknown. (The draft says
//     Invalid, but it only defines verification for eBGP-learned routes.)
//  3. Collapse prepends into COMPRESSED_AS_PATH {AS(N), ..., AS(1)}, where
//     AS(1) is the origin and AS(N) is the neighbor the route was learned
//     from (§5.1). The verifying AS itself is not part of the path: the
//     relationship with AS(N) is what selects the procedure, so the
//     AS(N)→verifier edge is never checked.
//  4. Compute the up-ramp and down-ramp lengths from authorized() (§5.2,
//     §5.3), then:
//     - upstream (§5.4): max_up_ramp < N → Invalid; min_up_ramp < N →
//     Unknown; else Valid.
//     - downstream (§5.5): max_up_ramp + max_down_ramp < N → Invalid;
//     min_up_ramp + min_down_ramp < N → Unknown; else Valid.
//
// A path with N=1 therefore always verifies as Valid under both procedures.
//
// The neighbor-AS check (§5.4/§5.5 step 2) is not performed here; see
// ValidateSelection.
func (a *Annotator) ValidateProcedure(route *types.Route, proc types.ASPAProcedure) types.ASPAResult {
	if route.HasConfedSegment() {
		return confedResult(proc)
	}
	// Check for AS_SET segments — unverifiable per the draft
	for _, seg := range route.ASPathRaw {
		if seg.Type == types.ASSegmentSet {
			return types.ASPAResult{
				State:     types.ASPAUnverifiable,
				Procedure: proc,
			}
		}
	}

	path := compress(route.ASPath)
	n := len(path)
	if n == 0 {
		// Self-originated route — no path to verify
		return types.ASPAResult{
			State:     types.ASPAUnknown,
			Procedure: proc,
			Reason:    EmptyPathReason,
		}
	}

	hops := make([]types.ASPAHop, 0, 2*(n-1))

	// Up-ramp (§5.3): walk authorized(AS(I), AS(I+1)) from the origin.
	// max_up_ramp is the first I that is "Not Provider+", min_up_ramp the
	// first I that is "No Attestation" or "Not Provider+"; N if none.
	maxUp, minUp := n, n
	var upFail *types.ASPAHop
	for i := 1; i < n; i++ {
		hop := a.checkHop(path[i-1], path[i])
		hops = append(hops, hop)
		if hop.Authorization != types.HopAuthorized && minUp == n {
			minUp = i
		}
		if hop.Authorization == types.HopNotAuthorized && maxUp == n {
			maxUp = i
			upFail = &hop
		}
	}

	result := types.ASPAResult{Procedure: proc}

	if proc == types.ASPADownstream {
		// Down-ramp (§5.3): walk authorized(AS(J), AS(J-1)) from the neighbor.
		// max_down_ramp is N-J+1 for the largest J that is "Not Provider+",
		// min_down_ramp likewise for "No Attestation" or "Not Provider+"; N if
		// none.
		maxDown, minDown := n, n
		for j := n; j > 1; j-- {
			hop := a.checkHop(path[j-1], path[j-2])
			hops = append(hops, hop)
			if hop.Authorization != types.HopAuthorized && minDown == n {
				minDown = n - j + 1
			}
			if hop.Authorization == types.HopNotAuthorized && maxDown == n {
				maxDown = n - j + 1
			}
		}
		switch {
		case maxUp+maxDown < n:
			result.State = types.ASPAInvalid
			result.FailingHop = upFail
		case minUp+minDown < n:
			result.State = types.ASPAUnknown
		default:
			result.State = types.ASPAValid
		}
	} else {
		switch {
		case maxUp < n:
			result.State = types.ASPAInvalid
			result.FailingHop = upFail
		case minUp < n:
			result.State = types.ASPAUnknown
		default:
			result.State = types.ASPAValid
		}
	}

	result.HopDetails = hops
	return result
}

// EmptyPathReason is the ASPA Reason on a route with an empty AS_PATH: Unknown,
// not verified. The draft only defines verification of an AS_PATH received
// over eBGP; a route without one was originated by the monitored router or
// learned over iBGP from a speaker in its AS that originated it. (ROV gives
// such a route the router's own AS as origin, RFC 6811 §2.)
const EmptyPathReason = "not ASPA-verified: empty AS_PATH; the route is locally originated or iBGP-learned without an AS_PATH"

// ConfedReason is the ASPA Reason on a route whose AS_PATH has
// confederation segments.
const ConfedReason = "not ASPA-verified: learned over a session internal to an AS confederation " +
	"(draft-ietf-sidrops-aspa-verification-24 §6.2)"

// confedResult is the result for a route whose AS_PATH has an
// AS_CONFED_SEQUENCE or AS_CONFED_SET segment: Unverifiable, not verified.
//
// The draft defines no handling of confederation segments in the AS_PATH.
// What it says about confederations is that verification is meant for
// routers at the confederation's boundary facing external ASes and is NOT
// RECOMMENDED on "eBGP sessions internal to an AS Confederation" (§6.2),
// and that boundary ASes register ASPAs under the confederation's global
// ASN (§4). Confederation segments only arrive over such internal sessions:
// they are removed before a route leaves the confederation (RFC 5065
// §4.1 (c)), and a router treats them from any other peer as a malformed
// AS_PATH (§5), so such a route never reaches the table. Verifying the
// path anyway would treat member ASes as hops.
func confedResult(proc types.ASPAProcedure) types.ASPAResult {
	return types.ASPAResult{State: types.ASPAUnverifiable, Procedure: proc, Reason: ConfedReason}
}

// compress returns the AS_PATH as COMPRESSED_AS_PATH (draft §5.1) in
// verification order: consecutive duplicates (prepends) collapsed, origin
// first, neighbor last. AS_PATH is stored as [neighbor, ..., origin].
func compress(asPath []uint32) []uint32 {
	out := make([]uint32, 0, len(asPath))
	for i := len(asPath) - 1; i >= 0; i-- {
		if len(out) > 0 && out[len(out)-1] == asPath[i] {
			continue
		}
		out = append(out, asPath[i])
	}
	return out
}

// checkHop implements authorized(customer, provider) (draft §5.2) against
// the ASPA store.
func (a *Annotator) checkHop(customerASN, providerASN uint32) types.ASPAHop {
	hop := types.ASPAHop{
		CustomerASN: customerASN,
		ProviderASN: providerASN,
	}

	if !a.aspaStore.HasRecord(customerASN) {
		// No ASPA object for this customer — "No Attestation"
		hop.Authorization = types.HopNoASPA
	} else if a.aspaStore.HasProvider(customerASN, providerASN) {
		// Provider is authorized — "Provider+"
		hop.Authorization = types.HopAuthorized
	} else {
		// ASPA exists but provider not in set — "Not Provider+"
		hop.Authorization = types.HopNotAuthorized
	}
	return hop
}
