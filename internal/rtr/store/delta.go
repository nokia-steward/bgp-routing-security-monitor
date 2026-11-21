package store

import (
	"net/netip"
	"slices"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Delta describes how an RTR sync changed the VRP and ASPA stores, so only
// the routes it can affect need revalidating (ARCHITECTURE.md §2.2, the
// "dirty set").
//
// A Full delta carries no incremental information: the stores were rebuilt
// (Cache Reset, Reset Query, a new session, a session-ID change) rather than
// patched, and every route must be revalidated.
type Delta struct {
	Full bool

	// VRPs announced and withdrawn. A maxLength change arrives as a
	// withdrawal of the old VRP and an announcement of the new one.
	VRPAnnounced []types.VRP
	VRPWithdrawn []types.VRP

	// ASPACustomers are the customer ASNs whose ASPA record was added,
	// removed, or had its provider set changed. Sorted, no duplicates.
	ASPACustomers []uint32
}

// FullDelta returns a delta that requires a full revalidation.
func FullDelta() *Delta { return &Delta{Full: true} }

// Empty reports whether the delta requires no revalidation at all.
func (d *Delta) Empty() bool {
	return d != nil && !d.Full && len(d.VRPAnnounced) == 0 && len(d.VRPWithdrawn) == 0 && len(d.ASPACustomers) == 0
}

// Merge folds o into d. Either being Full makes d Full, and a Full delta
// drops its incremental detail.
func (d *Delta) Merge(o *Delta) {
	if o == nil {
		return
	}
	if d.Full || o.Full {
		*d = Delta{Full: true}
		return
	}
	d.VRPAnnounced = append(d.VRPAnnounced, o.VRPAnnounced...)
	d.VRPWithdrawn = append(d.VRPWithdrawn, o.VRPWithdrawn...)
	if len(o.ASPACustomers) > 0 {
		d.ASPACustomers = append(d.ASPACustomers, o.ASPACustomers...)
		slices.Sort(d.ASPACustomers)
		d.ASPACustomers = slices.Compact(d.ASPACustomers)
	}
}

// VRPPrefixes returns the distinct prefixes of the delta's VRPs: the routes a
// changed VRP can affect are those at or more specific than its prefix.
func (d *Delta) VRPPrefixes() []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(d.VRPAnnounced)+len(d.VRPWithdrawn))
	out := make([]netip.Prefix, 0, len(seen))
	for _, list := range [][]types.VRP{d.VRPAnnounced, d.VRPWithdrawn} {
		for _, v := range list {
			p := v.Prefix.Masked()
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	return out
}

// DeltaRecorder accumulates one sync's changes into a Delta.
type DeltaRecorder struct {
	d    Delta
	aspa map[uint32]struct{}
}

// NewDeltaRecorder starts recording a sync; full marks it Full from the start.
func NewDeltaRecorder(full bool) *DeltaRecorder {
	return &DeltaRecorder{d: Delta{Full: full}, aspa: make(map[uint32]struct{})}
}

// MarkFull records that the stores were rebuilt rather than patched.
func (r *DeltaRecorder) MarkFull() { r.d.Full = true }

// VRP records an announced or withdrawn VRP.
func (r *DeltaRecorder) VRP(v types.VRP, withdrawn bool) {
	if r.d.Full {
		return
	}
	if withdrawn {
		r.d.VRPWithdrawn = append(r.d.VRPWithdrawn, v)
	} else {
		r.d.VRPAnnounced = append(r.d.VRPAnnounced, v)
	}
}

// ASPA records a customer ASN whose record changed.
func (r *DeltaRecorder) ASPA(customerASN uint32) {
	if !r.d.Full {
		r.aspa[customerASN] = struct{}{}
	}
}

// Delta returns the recorded delta.
func (r *DeltaRecorder) Delta() *Delta {
	d := r.d
	if d.Full {
		return &Delta{Full: true}
	}
	for asn := range r.aspa {
		d.ASPACustomers = append(d.ASPACustomers, asn)
	}
	slices.Sort(d.ASPACustomers)
	return &d
}
