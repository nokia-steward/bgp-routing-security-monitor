package validation

import (
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// incFixture is an engine over a table whose routes are validated against
// its stores, as ingest leaves them.
type incFixture struct {
	t     testing.TB
	vrps  *store.VRPStore
	aspas *store.ASPAStore
	table *routetable.Table
	e     *Engine
}

func newIncFixture(t testing.TB) *incFixture {
	f := &incFixture{t: t, vrps: store.NewVRPStore(), aspas: store.NewASPAStore(), table: routetable.New()}
	f.e = NewEngine(f.vrps, f.aspas, nil, f.table, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return f
}

// add validates and inserts a route, as ingest does.
func (f *incFixture) add(peer, prefix string, path ...uint32) types.RouteKey {
	r := &types.Route{
		PeerAddr: netip.MustParseAddr(peer),
		Prefix:   netip.MustParsePrefix(prefix),
		ASPath:   path,
		RIBType:  types.AdjRIBInPre,
	}
	f.e.ValidateRoute(r)
	f.table.Insert(r)
	return types.RouteKey{Peer: types.PeerRef{Addr: r.PeerAddr}, Prefix: r.Prefix, RIBType: r.RIBType}
}

func (f *incFixture) get(k types.RouteKey) *types.Route { return f.table.Get(k) }

// run completes a pass for d in small steps.
func (f *incFixture) run(d *store.Delta) *Revalidation {
	rv := f.e.NewDeltaRevalidation(d)
	for !rv.Step(3) {
	}
	return rv
}

func vrp(prefix string, maxLen uint8, asn uint32) types.VRP {
	return types.VRP{Prefix: netip.MustParsePrefix(prefix), MaxLength: maxLen, ASN: asn}
}

// The tests below change the stores in two ways: through the delta the pass
// is given, and, for the routes the delta must not touch, behind its back.
// A route the pass revalidated picks up a hidden change; one it left alone
// keeps its old results. That is what shows a route was not touched.

func TestIncremental_VRPAddedCoversRoute(t *testing.T) {
	f := newIncFixture(t)
	covered := f.add("192.0.2.1", "10.1.2.0/24", 64500, 65001)
	unrelated := f.add("192.0.2.1", "172.16.0.0/24", 64500, 65002)
	before := f.get(unrelated)

	added := vrp("10.1.0.0/16", 24, 65001)
	f.vrps.AddVRP(added)
	f.vrps.AddVRP(vrp("172.16.0.0/24", 24, 65002)) // hidden: not in the delta
	f.vrps.RebuildIndex()

	rv := f.run(&store.Delta{VRPAnnounced: []types.VRP{added}})
	if got := f.get(covered).ROV.State; got != types.ROVValid {
		t.Errorf("covered route ROV = %s, want Valid", got)
	}
	if f.get(unrelated) != before || before.ROV.State != types.ROVNotFound {
		t.Errorf("unrelated route was revalidated: %+v", f.get(unrelated).ROV)
	}
	if rv.Full || rv.Candidates != 1 || rv.Checked != 1 || rv.Changed != 1 {
		t.Errorf("pass full=%v candidates=%d checked=%d changed=%d, want incremental 1/1/1",
			rv.Full, rv.Candidates, rv.Checked, rv.Changed)
	}
}

func TestIncremental_VRPWithdrawn(t *testing.T) {
	f := newIncFixture(t)
	v := vrp("10.1.2.0/24", 24, 65001)
	f.vrps.ReplaceAll([]types.VRP{v}, 1, 1)
	k := f.add("192.0.2.1", "10.1.2.0/24", 64500, 65001)
	if f.get(k).ROV.State != types.ROVValid {
		t.Fatal("setup: route not Valid")
	}
	f.vrps.RemoveVRP(v)
	f.vrps.RebuildIndex() // End of Data
	f.run(&store.Delta{VRPWithdrawn: []types.VRP{v}})
	if got := f.get(k).ROV.State; got != types.ROVNotFound {
		t.Errorf("ROV after withdrawal = %s, want NotFound", got)
	}
}

// A maxLength change arrives as the old VRP withdrawn and the new announced,
// for the same prefix.
func TestIncremental_MaxLengthOnlyChange(t *testing.T) {
	f := newIncFixture(t)
	old := vrp("10.1.0.0/16", 16, 65001)
	f.vrps.ReplaceAll([]types.VRP{old}, 1, 1)
	k := f.add("192.0.2.1", "10.1.2.0/24", 64500, 65001)
	if f.get(k).ROV.State != types.ROVInvalid {
		t.Fatal("setup: route not Invalid (too specific)")
	}
	updated := vrp("10.1.0.0/16", 24, 65001)
	f.vrps.RemoveVRP(old)
	f.vrps.AddVRP(updated)
	f.vrps.RebuildIndex()
	f.run(&store.Delta{VRPWithdrawn: []types.VRP{old}, VRPAnnounced: []types.VRP{updated}})
	if got := f.get(k).ROV.State; got != types.ROVValid {
		t.Errorf("ROV after maxLength 16→24 = %s, want Valid", got)
	}
}

// A changed VRP affects routes at or more specific than its prefix: a /8 VRP
// reaches a /24 route, and a /16 VRP does not reach a /8 route.
func TestIncremental_VRPLessSpecificThanRoute(t *testing.T) {
	f := newIncFixture(t)
	specific := f.add("192.0.2.1", "10.200.3.0/24", 64500, 65001)
	equal := f.add("192.0.2.2", "10.0.0.0/8", 64500, 65001)
	wide := f.add("192.0.2.3", "10.0.0.0/7", 64500, 65001)
	beforeWide := f.get(wide)

	v8 := vrp("10.0.0.0/8", 24, 65001)
	f.vrps.AddVRP(v8)
	f.vrps.AddVRP(vrp("10.0.0.0/7", 7, 65001)) // hidden
	f.vrps.RebuildIndex()
	rv := f.run(&store.Delta{VRPAnnounced: []types.VRP{v8}})
	if got := f.get(specific).ROV.State; got != types.ROVValid {
		t.Errorf("/24 under the /8 VRP: ROV = %s, want Valid", got)
	}
	if got := f.get(equal).ROV.State; got != types.ROVValid {
		t.Errorf("/8 equal to the VRP: ROV = %s, want Valid", got)
	}
	if f.get(wide) != beforeWide {
		t.Error("/7 route, less specific than the VRP, was revalidated")
	}
	if rv.Candidates != 2 {
		t.Errorf("candidates = %d, want 2", rv.Candidates)
	}
}

// An ASPA change for an AS in the middle of a path reaches the route; a
// route without that AS is not touched.
func TestIncremental_ASPAMidPath(t *testing.T) {
	f := newIncFixture(t)
	// [64500 64510 64520]: AS(1)=64520, AS(2)=64510, AS(3)=64500.
	with := f.add("192.0.2.1", "10.1.2.0/24", 64500, 64510, 64520)
	without := f.add("192.0.2.1", "10.9.9.0/24", 64500, 64999)
	beforeWithout := f.get(without)

	// draft-24 §5.4: authorized(64510, 64500) = Not Provider+, so
	// max_up_ramp = 2 < 3: Invalid.
	f.aspas.AddProvider(64510, 64999)
	f.aspas.AddProvider(64999, 1) // hidden: would make `without` Invalid
	rv := f.run(&store.Delta{ASPACustomers: []uint32{64510}})
	if got := f.get(with).ASPA.State; got != types.ASPAInvalid {
		t.Errorf("route through AS64510: ASPA = %s, want Invalid", got)
	}
	if f.get(without) != beforeWithout {
		t.Errorf("route without AS64510 was revalidated: ASPA %s", f.get(without).ASPA.State)
	}
	if rv.Candidates != 1 || rv.ASPAScanned != 2 {
		t.Errorf("candidates=%d aspa_scanned=%d, want 1 and 2", rv.Candidates, rv.ASPAScanned)
	}
}

// A route both a VRP change and an ASPA change select is revalidated once.
func TestIncremental_UnionIsDeduplicated(t *testing.T) {
	f := newIncFixture(t)
	f.add("192.0.2.1", "10.1.2.0/24", 64500, 64510)
	v := vrp("10.1.0.0/16", 24, 64510)
	f.vrps.AddVRP(v)
	f.vrps.RebuildIndex()
	f.aspas.AddProvider(64510, 64500)
	rv := f.run(&store.Delta{VRPAnnounced: []types.VRP{v}, ASPACustomers: []uint32{64510}})
	if rv.Candidates != 1 || rv.Checked != 1 {
		t.Errorf("candidates=%d checked=%d, want 1 and 1", rv.Candidates, rv.Checked)
	}
}

func TestIncremental_FullDeltaRunsFullPass(t *testing.T) {
	f := newIncFixture(t)
	a := f.add("192.0.2.1", "10.1.2.0/24", 64500, 65001)
	b := f.add("192.0.2.1", "172.16.0.0/24", 64500, 65002)
	f.vrps.ReplaceAll([]types.VRP{vrp("10.0.0.0/8", 24, 65001), vrp("172.16.0.0/12", 24, 65002)}, 2, 1)
	for _, d := range []*store.Delta{store.FullDelta(), nil} {
		rv := f.run(d)
		if !rv.Full || rv.Checked != 2 {
			t.Errorf("delta %+v: full=%v checked=%d, want a full pass over 2 routes", d, rv.Full, rv.Checked)
		}
	}
	if f.get(a).ROV.State != types.ROVValid || f.get(b).ROV.State != types.ROVValid {
		t.Error("full pass did not revalidate every route")
	}
}

// Property: after any sequence of RTR deltas, each followed by an
// incremental pass, the table is exactly what a full revalidation would make
// it. Routes are also announced and withdrawn between a pass's steps, as
// ingest does.
func TestIncremental_EquivalentToFull(t *testing.T) {
	for seed := uint64(1); seed <= 20; seed++ {
		rng := rand.New(rand.NewPCG(seed, 99))
		f := newIncFixture(t)

		// A small universe so prefixes nest and paths share ASes.
		prefixes := make([]netip.Prefix, 0, 120)
		for i := 0; i < 40; i++ {
			base := netip.AddrFrom4([4]byte{10, byte(rng.IntN(4)), byte(rng.IntN(4) * 64), 0})
			for _, bits := range []int{14, 18, 24} {
				p, _ := base.Prefix(bits)
				prefixes = append(prefixes, p)
			}
		}
		asns := []uint32{64500, 64501, 64502, 64503, 64504, 64505, 64506, 64507}
		peers := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
		randRoute := func() *types.Route {
			path := make([]uint32, 1+rng.IntN(4))
			for i := range path {
				path[i] = asns[rng.IntN(len(asns))]
			}
			return &types.Route{
				PeerAddr: peers[rng.IntN(len(peers))],
				Prefix:   prefixes[rng.IntN(len(prefixes))],
				ASPath:   path,
				RIBType:  types.AdjRIBInPre,
			}
		}
		ingest := func() {
			r := randRoute()
			if rng.IntN(4) == 0 {
				f.table.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: r.PeerAddr}, Prefix: r.Prefix})
				return
			}
			f.e.ValidateRoute(r)
			f.table.Insert(r)
		}
		for i := 0; i < 300; i++ {
			ingest()
		}

		var live []types.VRP
		for round := 0; round < 25; round++ {
			// Change the stores as an RTR sync does, recording the delta.
			rec := store.NewDeltaRecorder(false)
			for n := rng.IntN(5); n > 0; n-- {
				if len(live) > 0 && rng.IntN(2) == 0 {
					i := rng.IntN(len(live))
					f.vrps.RemoveVRP(live[i])
					rec.VRP(live[i], true)
					live = append(live[:i], live[i+1:]...)
					continue
				}
				p := prefixes[rng.IntN(len(prefixes))]
				v := types.VRP{Prefix: p, ASN: asns[rng.IntN(len(asns))], MaxLength: uint8(p.Bits() + rng.IntN(32-p.Bits()+1))}
				f.vrps.AddVRP(v)
				rec.VRP(v, false)
				live = append(live, v)
			}
			f.vrps.RebuildIndex()
			for n := rng.IntN(3); n > 0; n-- {
				c, p := asns[rng.IntN(len(asns))], asns[rng.IntN(len(asns))]
				var changed bool
				if rng.IntN(2) == 0 {
					changed = f.aspas.AddProvider(c, p)
				} else {
					changed = f.aspas.RemoveProvider(c, p)
				}
				if changed {
					rec.ASPA(c)
				}
			}

			rv := f.e.NewDeltaRevalidation(rec.Delta())
			for !rv.Step(1 + rng.IntN(7)) {
				for n := rng.IntN(3); n > 0; n-- {
					ingest()
				}
			}

			for _, r := range f.table.All() {
				if _, changed := f.e.Revalidated(r); changed {
					t.Fatalf("seed %d round %d: route %s via %s path %v is stale after the incremental pass",
						seed, round, r.Prefix, r.PeerAddr, r.ASPath)
				}
			}
		}
	}
}

// The ASPA scan reaches every shard: with the changed customer in every path,
// every route is a candidate and every route's result changes.
func TestIncremental_ASPAScanCoversEveryShard(t *testing.T) {
	f := newIncFixture(t)
	const n = 4000
	for i := 0; i < n; i++ {
		f.add("192.0.2.1", netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24).String(), 64500, 64510)
	}
	f.aspas.AddProvider(64510, 64500) // Unknown → Valid for every route
	rv := f.run(&store.Delta{ASPACustomers: []uint32{64510}})
	if rv.Candidates != n || rv.Changed != n || rv.ASPAScanned != n {
		t.Fatalf("candidates=%d changed=%d scanned=%d, want %d each", rv.Candidates, rv.Changed, rv.ASPAScanned, n)
	}
	for _, r := range f.table.All() {
		if r.ASPA.State != types.ASPAValid {
			t.Fatalf("route %s ASPA = %s after the pass, want Valid", r.Prefix, r.ASPA.State)
		}
	}
}
