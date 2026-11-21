package routetable

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Index queries must be safe to run while routes are withdrawn. A prefix's
// key list used to be shortened in place on a withdrawal, while
// GetByPrefixIn read the list after releasing the index lock: a reader could
// see a key twice and miss another, and the race detector flags it. Run
// with -race.
func TestIndexQueriesConcurrentWithWithdrawals(t *testing.T) {
	const (
		peers  = 8
		rounds = 300
		origin = 13335
	)
	prefix := netip.MustParsePrefix("1.0.0.0/24")
	route := func(p int) *types.Route {
		return &types.Route{
			PeerAddr:        netip.AddrFrom4([4]byte{192, 0, 2, byte(1 + p)}),
			Prefix:          prefix,
			ASPath:          []uint32{64500, origin},
			RIBType:         types.AdjRIBInPre,
			SecurityPosture: types.PostureOriginOnly,
			OwnerSession:    1,
		}
	}

	tbl := New()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// noDuplicates reports, once, a query that returned the same route key
	// twice, what a reader of a list being shifted under it sees.
	noDuplicates := func(query string, routes []*types.Route) bool {
		seen := make(map[types.RouteKey]bool, len(routes))
		for _, r := range routes {
			if seen[r.Key()] {
				t.Errorf("%s returned %v twice", query, r.Key())
				return false
			}
			seen[r.Key()] = true
		}
		return true
	}
	// Each reader reports whether to keep going.
	readers := []func() bool{
		func() bool {
			return noDuplicates("GetByPrefixIn", tbl.GetByPrefixIn(prefix, types.RIBSetOf(types.AdjRIBInPre)))
		},
		func() bool { return noDuplicates("GetByOriginASN", tbl.GetByOriginASN(origin)) },
		func() bool { return noDuplicates("GetByPosture", tbl.GetByPosture(types.PostureOriginOnly)) },
		func() bool {
			routes, err := tbl.ListRoutes(context.Background(), Filter{Prefix: prefix.String()})
			if err != nil {
				t.Error(err)
				return false
			}
			ptrs := make([]*types.Route, len(routes))
			for i := range routes {
				ptrs[i] = &routes[i]
			}
			return noDuplicates("ListRoutes", ptrs)
		},
		func() bool { tbl.KeysWithin(prefix, func(types.RouteKey) {}); return true },
		func() bool { tbl.CountByPosture(); return true },
	}
	for _, read := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if !read() {
						return
					}
				}
			}
		}()
	}

	// Fill the prefix with every peer, then withdraw them front first, so
	// each withdrawal removes from the head of the list, by key and by
	// peer-down in turn.
	for round := 0; round < rounds; round++ {
		for p := 0; p < peers; p++ {
			tbl.Insert(route(p))
		}
		for p := 0; p < peers; p++ {
			r := route(p)
			if p%2 == 0 {
				tbl.Withdraw(r.Key())
			} else {
				tbl.WithdrawAllFromPeer(r.Peer(), 1, types.AdjRIBInPre)
			}
		}
	}
	close(stop)
	wg.Wait()

	if n := tbl.Count(); n != 0 {
		t.Errorf("table holds %d routes after withdrawing them all, want 0", n)
	}
}
