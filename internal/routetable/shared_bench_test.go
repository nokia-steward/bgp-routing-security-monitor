package routetable

import (
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// sharedRoutes builds routes for 25k prefixes, each carried by the same 4
// peers, a BMP feed's shape. Every prefix's key list holds 4 keys, so a
// withdrawal removes from a list rather than deleting the prefix, which the
// one-route-per-prefix bench tables never do.
func sharedRoutes() []*types.Route {
	const prefixes, peers = 25_000, 4
	routes := make([]*types.Route, 0, prefixes*peers)
	for i := 0; i < prefixes; i++ {
		for p := 0; p < peers; p++ {
			routes = append(routes, &types.Route{
				PeerAddr:        netip.AddrFrom4([4]byte{192, 0, 2, byte(p)}),
				Prefix:          netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32),
				ASPath:          []uint32{64500, uint32(65000 + i%1000)},
				RIBType:         types.AdjRIBInPre,
				SecurityPosture: types.PostureOriginOnly,
				OwnerSession:    benchSession,
			})
		}
	}
	return routes
}

// BenchmarkSharedPrefixChurn measures steady-state ingest on prefixes several
// peers carry: a route withdrawn, then re-announced. It is what copying a
// prefix's key list on every removal would cost ingest.
//
//	go test -run '^$' -bench SharedPrefixChurn -benchmem ./internal/routetable/
func BenchmarkSharedPrefixChurn(b *testing.B) {
	routes := sharedRoutes()
	tbl := buildTable(routes)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := routes[i%len(routes)]
		tbl.Withdraw(r.Key())
		tbl.Insert(r)
	}
}

// BenchmarkSharedPrefixQuery measures a prefix query on a prefix 4 peers
// carry, including the copy of its key list taken under the index lock.
//
//	go test -run '^$' -bench SharedPrefixQuery -benchmem ./internal/routetable/
func BenchmarkSharedPrefixQuery(b *testing.B) {
	routes := sharedRoutes()
	tbl := buildTable(routes)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.GetByPrefix(routes[(i*4)%len(routes)].Prefix)
	}
}
