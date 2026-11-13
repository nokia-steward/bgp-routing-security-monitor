package api

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// routeFilter is the route query of /api/v1/routes and /api/v1/watch: every
// filter given must match. Each used to be honoured only when no filter
// before it in a fixed order was given, so --prefix with --peer returned the
// prefix from every peer.
type routeFilter struct {
	prefix netip.Prefix // invalid = any
	// pmatch says how prefix matches: exactly, or also its less specifics
	// (covering) or more specifics (longer).
	pmatch  prefixMatch
	origin  uint32     // origin ASN; 0 = any
	peer    netip.Addr // BMP peer, unmapped; invalid = any
	posture types.SecurityPosture
	// afi is the address family a route's prefix must be of: 4, 6, or 0
	// for either.
	afi uint8
	// routers, when byRouter, are the monitored routers a route must come
	// from: the one router address given, or the routers whose sysName is
	// the name given (none, if no router has it).
	byRouter bool
	routers  []netip.Addr
	// ribs are the RIBs to list: the rib parameter's, or the default view
	// (types.DefaultView: adj-rib-in-pre and loc-rib) when it is absent,
	// for routes and watch alike.
	ribs types.RIBSet
}

// prefixMatch is the match query parameter: how a route's prefix must
// relate to the prefix parameter.
type prefixMatch uint8

const (
	// matchExact: the route's prefix is the prefix. The default.
	matchExact prefixMatch = iota
	// matchCovering: the prefix or any less specific prefix covering it.
	matchCovering
	// matchLonger: the prefix or any more specific prefix within it.
	matchLonger
)

// parsePrefixMatch reads a match value: exact (or empty), covering or
// longer.
func parsePrefixMatch(v string) (prefixMatch, error) {
	switch v {
	case "", "exact":
		return matchExact, nil
	case "covering":
		return matchCovering, nil
	case "longer":
		return matchLonger, nil
	}
	return 0, fmt.Errorf("invalid match %q: want exact, covering or longer", v)
}

// matches reports whether p relates to want as m says. Prefixes of
// different address families never match.
func (m prefixMatch) matches(want, p netip.Prefix) bool {
	switch m {
	case matchCovering:
		return p.Bits() <= want.Bits() && p.Contains(want.Addr())
	case matchLonger:
		return want.Bits() <= p.Bits() && want.Contains(p.Addr())
	}
	return p == want
}

// parseRouter reads the router query parameter, as routes, watch, peers and
// status take it: a router address, or a BMP sysName that named resolves to
// the routers that have it (none, if no router has it). given is false when
// the parameter is absent.
func parseRouter(q url.Values, named func(string) []netip.Addr) (given bool, routers []netip.Addr) {
	v := q.Get("router")
	if v == "" {
		return false, nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return true, []netip.Addr{a.Unmap()}
	}
	if named != nil {
		routers = named(v)
	}
	return true, routers
}

// parseRIBs reads the rib query parameter: RIB names (types.ParseRIBType,
// so pre-policy and post-policy are accepted too), comma-separated or
// repeated. Absent, it is the default view.
func parseRIBs(q url.Values) (types.RIBSet, error) {
	var names []string
	for _, v := range q["rib"] {
		for _, n := range strings.Split(v, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
	}
	if len(names) == 0 {
		return types.DefaultView, nil
	}
	return types.ParseRIBSet(names)
}

// ParseAFI reads an address family, as the afi query parameter and the CLI's
// --afi take it: ipv4 or ipv6 (v4 and v6, 4 and 6 also do), or empty for
// either. It returns 4, 6 or 0.
func ParseAFI(v string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return 0, nil
	case "ipv4", "v4", "4":
		return 4, nil
	case "ipv6", "v6", "6":
		return 6, nil
	}
	return 0, fmt.Errorf("invalid afi %q: want ipv4 or ipv6", v)
}

// parseRouteFilter reads the prefix, match, origin-asn, peer, posture, afi,
// router and rib query parameters. router is a router address or a BMP sysName; named
// resolves a sysName to the routers that have it.
func parseRouteFilter(q url.Values, named func(string) []netip.Addr) (routeFilter, error) {
	var f routeFilter
	f.byRouter, f.routers = parseRouter(q, named)
	if v := q.Get("prefix"); v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return f, fmt.Errorf("invalid prefix: %w", err)
		}
		f.prefix = p
	}
	m, err := parsePrefixMatch(q.Get("match"))
	if err != nil {
		return f, err
	}
	if m != matchExact {
		if !f.prefix.IsValid() {
			return f, fmt.Errorf("match %s needs a prefix", q.Get("match"))
		}
		// Containment is about the network, not host bits a user typed.
		f.prefix = f.prefix.Masked()
	}
	f.pmatch = m
	if v := q.Get("origin-asn"); v != "" {
		asn, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return f, fmt.Errorf("invalid ASN: %w", err)
		}
		f.origin = uint32(asn)
	}
	if v := q.Get("peer"); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return f, fmt.Errorf("invalid peer address: %w", err)
		}
		f.peer = a.Unmap()
	}
	f.posture = types.SecurityPosture(q.Get("posture"))
	afi, err := ParseAFI(q.Get("afi"))
	if err != nil {
		return f, err
	}
	f.afi = afi
	ribs, err := parseRIBs(q)
	if err != nil {
		return f, fmt.Errorf("invalid rib: %w", err)
	}
	f.ribs = ribs
	return f, nil
}

// match reports whether r passes every filter. A peer matches in either its
// plain IPv4 or its IPv4-mapped IPv6 form.
func (f *routeFilter) match(r *types.Route) bool {
	ribs := f.ribs
	if ribs == 0 {
		ribs = types.DefaultView // a filter not from parseRouteFilter
	}
	return (!f.prefix.IsValid() || f.pmatch.matches(f.prefix, r.Prefix)) &&
		(f.origin == 0 || r.OriginASN() == f.origin) &&
		(!f.peer.IsValid() || r.PeerAddr.Unmap() == f.peer) &&
		(f.posture == "" || r.SecurityPosture == f.posture) &&
		(f.afi == 0 || routeAFI(r.Prefix) == f.afi) &&
		(!f.byRouter || slices.Contains(f.routers, r.Router.Unmap())) &&
		ribs.Has(r.RIBType)
}

// routeAFI is the address family of a route's prefix: 4 or 6. An
// IPv4-mapped IPv6 prefix is IPv6, as the NLRI that carried it was.
func routeAFI(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return 4
	}
	return 6
}

// routes returns the table's routes of the filter's RIBs (the default view
// unless the rib parameter names others) that pass the filter, starting from
// the most selective index the filter allows. The prefix and origin indexes
// hold every RIB and are looked up for the filter's; the posture index holds
// the default view only, so for RIBs outside it a posture filter scans them.
func (f *routeFilter) routes(t *routetable.Table) []*types.Route {
	var candidates []*types.Route
	switch {
	case f.prefix.IsValid() && f.pmatch == matchCovering:
		candidates = t.GetCoveringIn(f.prefix, f.ribs)
	case f.prefix.IsValid() && f.pmatch == matchLonger:
		candidates = t.GetWithinIn(f.prefix, f.ribs)
	case f.prefix.IsValid():
		candidates = t.GetByPrefixIn(f.prefix, f.ribs)
	case f.origin != 0:
		candidates = t.GetByOriginASNIn(f.origin, f.ribs)
	case f.peer.IsValid():
		candidates = t.GetByPeerIn(f.peer, f.ribs)
	case f.posture != "" && routetable.PostureIndexed(f.ribs):
		candidates = t.GetByPostureIn(f.posture, f.ribs)
	case f.posture != "" || f.byRouter || f.afi != 0:
		candidates = t.AllIn(f.ribs)
	default:
		return t.AllIn(f.ribs)
	}
	// Every candidate source above is of the filter's RIBs alone.
	out := candidates[:0]
	for _, r := range candidates {
		if f.match(r) {
			out = append(out, r)
		}
	}
	return out
}
