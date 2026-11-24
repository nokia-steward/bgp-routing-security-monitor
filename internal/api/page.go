package api

import (
	"cmp"
	"container/heap"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// routePage is the page query of /api/v1/routes: at most limit routes, in
// route key order, after the route the cursor names. Paging by key keeps a
// route withdrawn or added between two requests from shifting the next page.
type routePage struct {
	limit    int // 0: no limit
	after    types.RouteKey
	hasAfter bool
}

// parseRoutePage reads the limit and after query parameters.
func parseRoutePage(q url.Values) (routePage, error) {
	var p routePage
	if q.Has("limit") {
		n, err := strconv.Atoi(q.Get("limit"))
		if err != nil || n < 1 {
			return p, fmt.Errorf("invalid limit %q: want a positive integer", q.Get("limit"))
		}
		p.limit = n
	}
	if q.Has("after") {
		k, err := decodeCursor(q.Get("after"))
		if err != nil {
			return p, fmt.Errorf("invalid after %q: want the cursor of a Link header", q.Get("after"))
		}
		p.after, p.hasAfter = k, true
	}
	return p, nil
}

// paged reports whether the query asks for a page rather than every route.
func (p routePage) paged() bool { return p.limit > 0 || p.hasAfter }

// cut returns the page's routes, in key order, and whether routes remain
// after it. With a limit, one pass keeps the page in a heap: a page costs
// O(n log limit) time and O(limit) memory, most of it reading each route's
// key.
func (p routePage) cut(routes []*types.Route) ([]*types.Route, bool) {
	if p.limit == 0 {
		if p.hasAfter {
			routes = slices.DeleteFunc(routes, func(r *types.Route) bool {
				return compareRouteKeys(r.Key(), p.after) <= 0
			})
		}
		slices.SortFunc(routes, func(a, b *types.Route) int { return compareRouteKeys(a.Key(), b.Key()) })
		return routes, false
	}
	h := make(lastKeyFirst, 0, min(p.limit, len(routes)))
	more := false
	for _, r := range routes {
		k := r.Key()
		switch {
		case p.hasAfter && compareRouteKeys(k, p.after) <= 0:
		case len(h) < p.limit:
			h = append(h, keyedRoute{k, r})
			if len(h) == p.limit {
				heap.Init(&h)
			}
		default:
			more = true
			if compareRouteKeys(k, h[0].key) < 0 {
				h[0] = keyedRoute{k, r}
				heap.Fix(&h, 0)
			}
		}
	}
	slices.SortFunc(h, func(a, b keyedRoute) int { return compareRouteKeys(a.key, b.key) })
	page := make([]*types.Route, len(h))
	for i, kr := range h {
		page[i] = kr.route
	}
	return page, more
}

type keyedRoute struct {
	key   types.RouteKey
	route *types.Route
}

// lastKeyFirst is a heap of routes whose root has the largest key: the
// route that a route with a smaller key takes the place of.
type lastKeyFirst []keyedRoute

func (h lastKeyFirst) Len() int           { return len(h) }
func (h lastKeyFirst) Less(i, j int) bool { return compareRouteKeys(h[i].key, h[j].key) > 0 }
func (h lastKeyFirst) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *lastKeyFirst) Push(x any)        { *h = append(*h, x.(keyedRoute)) }
func (h *lastKeyFirst) Pop() any {
	old := *h
	kr := old[len(old)-1]
	*h = old[:len(old)-1]
	return kr
}

// compareRouteKeys orders route keys by prefix first, so that pages follow
// the address space. It returns at the first difference, as it runs for
// each route of each page.
func compareRouteKeys(a, b types.RouteKey) int {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()); c != 0 {
		return c
	}
	if c := a.Peer.Router.Compare(b.Peer.Router); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Peer.Distinguisher, b.Peer.Distinguisher); c != 0 {
		return c
	}
	if c := a.Peer.Addr.Compare(b.Peer.Addr); c != 0 {
		return c
	}
	if c := cmp.Compare(a.PathID, b.PathID); c != 0 {
		return c
	}
	return cmp.Compare(a.RIBType, b.RIBType)
}

// nextLink is the Link header value of the page after the route keyed last.
func nextLink(r *http.Request, last types.RouteKey) string {
	q := r.URL.Query()
	q.Set("after", encodeCursor(last))
	return "<" + r.URL.Path + "?" + q.Encode() + `>; rel="next"`
}

// encodeCursor makes k an opaque, URL-safe cursor. The RIB goes by name, so
// that a cursor still means the same RIB if the RIB numbering changes; an
// unset address is an empty field, which netip.Addr.UnmarshalText reads
// back as unset.
func encodeCursor(k types.RouteKey) string {
	router, _ := k.Peer.Router.MarshalText()
	peer, _ := k.Peer.Addr.MarshalText()
	text := strings.Join([]string{
		k.Prefix.String(),
		string(router),
		strconv.FormatUint(k.Peer.Distinguisher, 10),
		string(peer),
		strconv.FormatUint(uint64(k.PathID), 10),
		k.RIBType.String(),
	}, ",")
	return base64.RawURLEncoding.EncodeToString([]byte(text))
}

func decodeCursor(s string) (types.RouteKey, error) {
	var k types.RouteKey
	text, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return k, err
	}
	f := strings.Split(string(text), ",")
	if len(f) != 6 {
		return k, errors.New("want 6 fields")
	}
	prefix, err := netip.ParsePrefix(f[0])
	if err != nil {
		return k, err
	}
	var router, peer netip.Addr
	if err := router.UnmarshalText([]byte(f[1])); err != nil {
		return k, err
	}
	if err := peer.UnmarshalText([]byte(f[3])); err != nil {
		return k, err
	}
	rd, err := strconv.ParseUint(f[2], 10, 64)
	if err != nil {
		return k, err
	}
	pathID, err := strconv.ParseUint(f[4], 10, 32)
	if err != nil {
		return k, err
	}
	rib, err := types.ParseRIBType(f[5])
	if err != nil {
		return k, err
	}
	return types.RouteKey{
		Peer:    types.PeerRef{Router: router, Distinguisher: rd, Addr: peer},
		Prefix:  prefix,
		PathID:  uint32(pathID),
		RIBType: rib,
	}, nil
}
