package routetable

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

func TestKeysWithinAndMatchScan(t *testing.T) {
	tbl := New()
	peer := netip.MustParseAddr("192.0.2.1")
	add := func(prefix string, path ...uint32) {
		tbl.Insert(&types.Route{PeerAddr: peer, Prefix: netip.MustParsePrefix(prefix), ASPath: path, RIBType: types.AdjRIBInPre})
	}
	add("10.0.0.0/8", 1)
	add("10.1.0.0/16", 2, 7)
	add("10.1.2.0/24", 3)
	add("10.2.0.0/16", 4)
	add("2001:db8::/32", 5, 7)
	add("2001:db8:1::/48", 6)

	within := func(p string) []string {
		var out []string
		tbl.KeysWithin(netip.MustParsePrefix(p), func(k types.RouteKey) { out = append(out, k.Prefix.String()) })
		slices.Sort(out)
		return out
	}
	for p, want := range map[string][]string{
		"10.1.0.0/16":   {"10.1.0.0/16", "10.1.2.0/24"}, // equal and more specific, not the /8
		"10.0.0.0/8":    {"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.2.0.0/16"},
		"10.1.2.128/25": nil,
		"2001:db8::/32": {"2001:db8:1::/48", "2001:db8::/32"},
		"10.1.2.0/16":   {"10.1.0.0/16", "10.1.2.0/24"}, // unmasked input is masked
	} {
		if got := within(p); !slices.Equal(got, want) {
			t.Errorf("KeysWithin(%s) = %v, want %v", p, got, want)
		}
	}

	ms := tbl.NewMatchScan(func(r *types.Route) bool { return slices.Contains(r.ASPath, 7) })
	var matched []string
	examined := 0
	for {
		m, n, done := ms.Next()
		examined += n
		for _, r := range m {
			matched = append(matched, r.Prefix.String())
		}
		if done {
			break
		}
	}
	slices.Sort(matched)
	if want := []string{"10.1.0.0/16", "2001:db8::/32"}; !slices.Equal(matched, want) || examined != 6 {
		t.Errorf("MatchScan matched %v after examining %d, want %v after 6", matched, examined, want)
	}
}
