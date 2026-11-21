package aspa

import (
	"net/netip"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Selection is the verification procedure chosen for a route.
type Selection struct {
	Procedure types.ASPAProcedure
	Source    types.ASPAProcedureSource
	// NeighborCheck applies the neighbor-AS check (draft §5.4/§5.5 step 2).
	// Only set when the neighbor's role is configured and is not a route
	// server, whose clients' ASes lead the AS_PATH instead of its own.
	NeighborCheck bool
}

// Selector picks the ASPA procedure for each route from its BMP peer:
// an aspa-peers entry for the peer address, then one for the peer ASN, then
// aspa-default-procedure. Its maps are built once and only read afterwards.
type Selector struct {
	byAddr map[netip.Addr]Selection
	byASN  map[uint32]Selection
	def    Selection
}

// NewSelector builds a Selector from config that has passed config
// validation. "auto" (and an unset default) select upstream: nothing supplies
// BGP Roles yet.
func NewSelector(defaultProcedure string, peers []config.ASPAPeer) *Selector {
	s := &Selector{
		byAddr: make(map[netip.Addr]Selection),
		byASN:  make(map[uint32]Selection),
		def:    Selection{Procedure: types.ASPAUpstream, Source: types.ASPASourceDefault},
	}
	if defaultProcedure == "downstream" {
		s.def.Procedure = types.ASPADownstream
	}
	for _, p := range peers {
		sel := Selection{
			Procedure:     types.ASPAUpstream,
			NeighborCheck: p.NeighborRole != "rs",
		}
		if p.NeighborRole == "provider" {
			sel.Procedure = types.ASPADownstream
		}
		if p.ASN != 0 {
			sel.Source = types.ASPASourceConfigASN
			s.byASN[p.ASN] = sel
			continue
		}
		if a, err := p.ParsedAddress(); err == nil {
			sel.Source = types.ASPASourceConfigAddress
			s.byAddr[a] = sel
		}
	}
	return s
}

// Select returns the procedure for a route learned from the given peer.
func (s *Selector) Select(peerAddr netip.Addr, peerASN uint32) Selection {
	if s == nil {
		return Selection{}
	}
	if sel, ok := s.byAddr[peerAddr.Unmap()]; ok {
		return sel
	}
	if sel, ok := s.byASN[peerASN]; ok {
		return sel
	}
	return s.def
}

// SelectASN returns the procedure for a route learned from a neighbor known
// by its AS alone: an aspa-peers entry for the ASN, then the default. A
// Loc-RIB route has no neighbor address (RFC 9069), only the first AS of
// its path. The neighbor-AS check is never selected: the neighbor AS is
// that first AS, so the check could not fail.
func (s *Selector) SelectASN(neighborASN uint32) Selection {
	if s == nil {
		return Selection{}
	}
	sel, ok := s.byASN[neighborASN]
	if !ok {
		sel = s.def
	}
	sel.NeighborCheck = false
	return sel
}
