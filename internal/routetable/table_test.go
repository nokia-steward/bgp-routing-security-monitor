package routetable

import (
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

func makeRoute(peer string, prefix string, asPath []uint32) *types.Route {
	return &types.Route{
		PeerAddr: netip.MustParseAddr(peer),
		Prefix:   netip.MustParsePrefix(prefix),
		ASPath:   asPath,
		RIBType:  types.AdjRIBInPre,
	}
}

func TestInsertAndGetByPrefix(t *testing.T) {
	tbl := New()

	r := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	tbl.Insert(r)

	if tbl.Count() != 1 {
		t.Fatalf("count = %d, want 1", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 1 {
		t.Fatalf("GetByPrefix returned %d routes, want 1", len(routes))
	}
	if routes[0].Prefix != r.Prefix {
		t.Errorf("prefix = %s, want %s", routes[0].Prefix, r.Prefix)
	}
}

func TestMultiplePeersSamePrefix(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.2", "1.0.0.0/24", []uint32{64502, 13335})
	tbl.Insert(r1)
	tbl.Insert(r2)

	if tbl.Count() != 2 {
		t.Fatalf("count = %d, want 2", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 2 {
		t.Fatalf("GetByPrefix returned %d routes, want 2", len(routes))
	}
}

func TestGetByOriginASN(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.1", "8.8.8.0/24", []uint32{64501, 15169})
	tbl.Insert(r1)
	tbl.Insert(r2)

	routes := tbl.GetByOriginASN(13335)
	if len(routes) != 1 {
		t.Fatalf("GetByOriginASN(13335) returned %d routes, want 1", len(routes))
	}
	if routes[0].Prefix.String() != "1.0.0.0/24" {
		t.Errorf("prefix = %s, want 1.0.0.0/24", routes[0].Prefix)
	}
}

func TestGetByPeer(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.2", "8.8.8.0/24", []uint32{64502, 15169})
	tbl.Insert(r1)
	tbl.Insert(r2)

	routes := tbl.GetByPeer(netip.MustParseAddr("192.0.2.1"))
	if len(routes) != 1 {
		t.Fatalf("GetByPeer returned %d routes, want 1", len(routes))
	}
}

func TestWithdraw(t *testing.T) {
	tbl := New()

	r := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	tbl.Insert(r)

	if tbl.Count() != 1 {
		t.Fatalf("count before withdraw = %d, want 1", tbl.Count())
	}

	tbl.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: netip.MustParseAddr("192.0.2.1")}, Prefix: netip.MustParsePrefix("1.0.0.0/24")})

	if tbl.Count() != 0 {
		t.Fatalf("count after withdraw = %d, want 0", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 0 {
		t.Errorf("GetByPrefix after withdraw returned %d routes, want 0", len(routes))
	}
}

func TestWithdrawAllFromPeer(t *testing.T) {
	tbl := New()

	tbl.Insert(makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335}))
	tbl.Insert(makeRoute("192.0.2.1", "8.8.8.0/24", []uint32{64501, 15169}))
	tbl.Insert(makeRoute("192.0.2.2", "10.0.0.0/8", []uint32{64502, 3356}))

	if tbl.Count() != 3 {
		t.Fatalf("count = %d, want 3", tbl.Count())
	}

	removed := tbl.WithdrawAllFromPeer(types.PeerRef{Addr: netip.MustParseAddr("192.0.2.1")}, 0, types.AdjRIBInPre)
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if tbl.Count() != 1 {
		t.Errorf("count after withdraw = %d, want 1", tbl.Count())
	}
}

// A peer going down must leave no trace of its routes anywhere: not in the
// primary map, and not in the prefix, origin-ASN or posture indexes. The
// public Get* queries skip index keys whose route is gone from the primary
// map, so a stale index entry would be invisible through them; this test
// inspects the indexes directly.
func TestWithdrawAllFromPeerCleansAllIndexes(t *testing.T) {
	tbl := New()
	down := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")

	const n = 50
	for i := 0; i < n; i++ {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(i), 0}), 24).String()
		for _, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost} {
			r := makeRoute(down.String(), prefix, []uint32{64501, 65000 + uint32(i%5)})
			r.RIBType = rib
			r.SecurityPosture = types.PostureOriginOnly
			if i%2 == 0 {
				r.SecurityPosture = types.PostureOriginInvalid
			}
			tbl.Insert(r)
		}
	}
	// The other peer shares one prefix and one origin ASN with the downed peer.
	shared := makeRoute(other.String(), "10.1.0.0/24", []uint32{64502, 65000})
	shared.SecurityPosture = types.PostureOriginInvalid
	tbl.Insert(shared)
	tbl.Insert(makeRoute(other.String(), "8.8.8.0/24", []uint32{64502, 15169}))

	if got := tbl.Count(); got != 2*n+2 {
		t.Fatalf("count before peer down = %d, want %d", got, 2*n+2)
	}

	if removed := tbl.WithdrawAllFromPeer(types.PeerRef{Addr: down}, 0, types.AdjRIBInPre); removed != 2*n {
		t.Errorf("removed = %d, want %d", removed, 2*n)
	}

	if got := tbl.Count(); got != 2 {
		t.Errorf("count after peer down = %d, want 2 (the other peer's routes)", got)
	}
	if got := tbl.GetByPeer(down); len(got) != 0 {
		t.Errorf("GetByPeer(down) returned %d routes, want 0", len(got))
	}

	// Prefix (BART) index: the downed peer's own prefixes are gone entirely;
	// the shared prefix keeps only the other peer's key.
	for i := 0; i < n; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(i), 0}), 24)
		keys, ok := tbl.prefixIdx.Get(p)
		for _, k := range keys {
			if k.Peer.Addr == down {
				t.Errorf("prefix index still holds %v", k)
			}
		}
		if i != 0 && ok {
			t.Errorf("prefix index still has an entry for %s, want it deleted", p)
		}
	}
	if keys, _ := tbl.prefixIdx.Get(netip.MustParsePrefix("10.1.0.0/24")); len(keys) != 1 || keys[0].Peer.Addr != other {
		t.Errorf("shared prefix keys = %v, want only the other peer's", keys)
	}

	// Origin-ASN and posture indexes hold no key for the downed peer.
	for asn, keys := range tbl.asnIdx {
		for k := range keys {
			if k.Peer.Addr == down {
				t.Errorf("ASN index AS%d still holds %v", asn, k)
			}
		}
	}
	for posture, keys := range tbl.postureIdx {
		for k := range keys {
			if k.Peer.Addr == down {
				t.Errorf("posture index %q still holds %v", posture, k)
			}
		}
	}
	if got := tbl.CountByPosture()[types.PostureOriginInvalid]; got != 1 {
		t.Errorf("origin-invalid count after peer down = %d, want 1 (the other peer's shared route)", got)
	}
	if got := tbl.CountByPosture()[types.PostureOriginOnly]; got != 0 {
		t.Errorf("origin-only count after peer down = %d, want 0", got)
	}
}

// postureListings returns every posture whose index entry lists key.
func postureListings(tbl *Table, key types.RouteKey) []types.SecurityPosture {
	var out []types.SecurityPosture
	for posture, set := range tbl.postureIdx {
		if _, ok := set[key]; ok {
			out = append(out, posture)
		}
	}
	return out
}

// asnListings returns every origin ASN whose index entry lists key.
func asnListings(tbl *Table, key types.RouteKey) []uint32 {
	var out []uint32
	for asn, set := range tbl.asnIdx {
		if _, ok := set[key]; ok {
			out = append(out, asn)
		}
	}
	return out
}

// The pattern RevalidateAll used to follow: the stored route's posture is
// changed in place and the same pointer re-inserted, so Insert cannot read
// the old posture off the old route. Nothing does this any more (revalidation
// goes through Replace), but Insert stays safe against it: the key must still
// end up listed under the new posture only.
func TestInsertPostureChangedInPlaceLeavesNoStaleKey(t *testing.T) {
	tbl := New()
	r := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r.SecurityPosture = types.PostureSecured
	tbl.Insert(r)
	key := types.RouteKey{Peer: types.PeerRef{Addr: r.PeerAddr}, Prefix: r.Prefix, RIBType: r.RIBType}

	flips := []types.SecurityPosture{
		types.PosturePathSuspect, types.PostureSecured,
		types.PosturePathSuspect, types.PostureSecured, types.PosturePathSuspect,
	}
	for i, p := range flips {
		r.SecurityPosture = p // in place, as RevalidateAll did
		tbl.Insert(r)
		if got := postureListings(tbl, key); len(got) != 1 || got[0] != p {
			t.Fatalf("after flip %d to %s: key listed under %v, want only [%s]", i+1, p, got, p)
		}
	}

	tbl.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: r.PeerAddr}, Prefix: r.Prefix})
	if got := postureListings(tbl, key); len(got) != 0 {
		t.Errorf("after withdrawal: key still listed under %v, want nowhere", got)
	}
	for posture, n := range tbl.CountByPosture() {
		if n != 0 {
			t.Errorf("after withdrawal: CountByPosture()[%s] = %d, want 0", posture, n)
		}
	}
}

// A re-announcement with a different origin arrives as a new route for the
// same key. The key must move to the new origin's ASN index entry, not be
// listed under both.
func TestInsertOriginChangeLeavesNoStaleASNKey(t *testing.T) {
	tbl := New()
	tbl.Insert(makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335}))
	tbl.Insert(makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 64666})) // new origin
	key := types.RouteKey{
		Peer:    types.PeerRef{Addr: netip.MustParseAddr("192.0.2.1")},
		Prefix:  netip.MustParsePrefix("1.0.0.0/24"),
		RIBType: types.AdjRIBInPre,
	}

	if got := asnListings(tbl, key); len(got) != 1 || got[0] != 64666 {
		t.Fatalf("key listed under ASNs %v, want only [64666]", got)
	}
	for _, r := range tbl.GetByOriginASN(13335) {
		t.Errorf("GetByOriginASN(13335) returned %s with origin AS%d", r.Prefix, r.OriginASN())
	}

	tbl.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: key.Peer.Addr}, Prefix: key.Prefix})
	if got := asnListings(tbl, key); len(got) != 0 {
		t.Errorf("after withdrawal: key still listed under ASNs %v, want none", got)
	}
}

func TestGetByPosture(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r1.SecurityPosture = types.PostureSecured
	tbl.Insert(r1)

	r2 := makeRoute("192.0.2.1", "10.0.0.0/8", []uint32{64501, 64666})
	r2.SecurityPosture = types.PostureOriginInvalid
	tbl.Insert(r2)

	secured := tbl.GetByPosture(types.PostureSecured)
	if len(secured) != 1 {
		t.Errorf("secured routes = %d, want 1", len(secured))
	}

	invalid := tbl.GetByPosture(types.PostureOriginInvalid)
	if len(invalid) != 1 {
		t.Errorf("origin-invalid routes = %d, want 1", len(invalid))
	}
}

// The prefix and origin indexes hold every RIB; the lookups return the ones
// asked for, the default view (Adj-RIB-In pre-policy and Loc-RIB) by
// default.
func TestIndexLookupsByRIB(t *testing.T) {
	tbl := New()
	p := netip.MustParsePrefix("1.1.1.0/24")
	for _, rib := range types.AllRIBTypes {
		tbl.Insert(&types.Route{PeerAddr: netip.MustParseAddr("192.0.2.9"), Prefix: p,
			ASPath: []uint32{64501, 13335}, RIBType: rib, SecurityPosture: types.PostureSecured})
	}
	for _, rib := range types.AllRIBTypes {
		for name, got := range map[string][]*types.Route{
			"prefix": tbl.GetByPrefixIn(p, types.RIBSetOf(rib)),
			"origin": tbl.GetByOriginASNIn(13335, types.RIBSetOf(rib)),
		} {
			if len(got) != 1 || got[0].RIBType != rib {
				t.Errorf("%s lookup in %s: %d routes", name, rib, len(got))
			}
		}
	}
	for name, got := range map[string][]*types.Route{
		"GetByPrefix":    tbl.GetByPrefix(p),
		"GetByOriginASN": tbl.GetByOriginASN(13335),
		"GetByPosture":   tbl.GetByPosture(types.PostureSecured),
		"GetByPeer":      tbl.GetByPeer(netip.MustParseAddr("192.0.2.9")),
		"AllDefaultView": tbl.AllDefaultView(),
	} {
		var ribs types.RIBSet
		for _, r := range got {
			ribs |= types.RIBSetOf(r.RIBType)
		}
		if len(got) != 2 || ribs != types.DefaultView {
			t.Errorf("%s: %d routes in %v, want one Adj-RIB-In pre-policy and one Loc-RIB route",
				name, len(got), ribs.Names())
		}
	}
	// The posture index holds the default view only.
	if got := tbl.GetByPostureIn(types.PostureSecured, types.RIBSetOf(types.AdjRIBInPost)); len(got) != 0 {
		t.Errorf("GetByPostureIn(adj-rib-in-post) = %d routes, want none: not indexed", len(got))
	}
	if PostureIndexed(types.RIBSetOf(types.AdjRIBInPost)) || !PostureIndexed(types.DefaultView) {
		t.Error("PostureIndexed: want true for the default view only")
	}
	if got := tbl.CountByPosture()[types.PostureSecured]; got != 2 {
		t.Errorf("CountByPosture()[secured] = %d, want 2: the default view's", got)
	}
}
