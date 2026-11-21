package validation

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/validation/aspa"
)

// revalidateAll runs one revalidation pass to completion, in small chunks.
func revalidateAll(e *Engine) *Revalidation {
	rv := e.NewRevalidation()
	for !rv.Step(7) {
	}
	return rv
}

// Revalidation replaces a route whose posture changed with a revalidated
// copy. The posture index must follow: the route is listed under its current
// posture only, however many times it flips, and nothing is left behind once
// the route is withdrawn. Leaked keys here grow memory with every RTR-driven
// posture change and inflate the per-posture counts. The route objects the
// table held before are never changed: readers may still hold them.
func TestRevalidationPostureFlipsLeaveNoStaleIndexKeys(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	matching := []types.VRP{{Prefix: prefix, ASN: 65000, MaxLength: 24}} // → origin-only
	other := []types.VRP{{Prefix: prefix, ASN: 65999, MaxLength: 24}}    // → origin-invalid

	vrps := store.NewVRPStore()
	vrps.ReplaceAll(matching, 1, 1)
	table := routetable.New()
	e := NewEngine(vrps, store.NewASPAStore(), nil, table, slog.New(slog.NewTextHandler(io.Discard, nil)))

	route := &types.Route{
		PeerAddr: netip.MustParseAddr("198.51.100.1"),
		Prefix:   prefix,
		ASPath:   []uint32{64500, 65000},
		RIBType:  types.AdjRIBInPre,
	}
	e.ValidateRoute(route)
	table.Insert(route)
	if route.SecurityPosture != types.PostureOriginOnly {
		t.Fatalf("initial posture = %s, want %s", route.SecurityPosture, types.PostureOriginOnly)
	}

	checkIndexed := func(step string, want types.SecurityPosture) {
		t.Helper()
		var total uint64
		for posture, n := range table.CountByPosture() {
			total += n
			if posture != want && n != 0 {
				t.Errorf("%s: posture index %q still counts %d route(s); the route is %s", step, posture, n, want)
			}
		}
		if total != 1 {
			t.Errorf("%s: posture index counts %d entries in total, want 1 (one route)", step, total)
		}
		for _, r := range table.GetByPosture(want) {
			if r.SecurityPosture != want {
				t.Errorf("%s: GetByPosture(%s) returned a route whose posture is %s", step, want, r.SecurityPosture)
			}
		}
	}

	key := types.RouteKey{Peer: types.PeerRef{Addr: route.PeerAddr}, Prefix: route.Prefix, RIBType: route.RIBType}
	flip := func(step string, want types.SecurityPosture) {
		t.Helper()
		before := table.Get(key)
		beforePosture := before.SecurityPosture
		if rv := revalidateAll(e); rv.Changed != 1 {
			t.Errorf("%s: pass changed %d routes, want 1", step, rv.Changed)
		}
		checkIndexed(step, want)
		if after := table.Get(key); after == before || after.SecurityPosture != want {
			t.Errorf("%s: table holds %p with posture %s, want a new route with %s", step, after, after.SecurityPosture, want)
		}
		if before.SecurityPosture != beforePosture {
			t.Errorf("%s: the replaced route was changed in place to %s", step, before.SecurityPosture)
		}
	}
	for i := 0; i < 4; i++ {
		vrps.ReplaceAll(other, uint32(2*i+2), 1)
		flip("flip to origin-invalid", types.PostureOriginInvalid)

		vrps.ReplaceAll(matching, uint32(2*i+3), 1)
		flip("flip back to origin-only", types.PostureOriginOnly)
	}
	if rv := revalidateAll(e); rv.Changed != 0 {
		t.Errorf("a pass with no store change replaced %d routes, want 0", rv.Changed)
	}

	table.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: route.PeerAddr}, Prefix: route.Prefix})
	for posture, n := range table.CountByPosture() {
		if n != 0 {
			t.Errorf("after withdrawal: posture index %q still counts %d route(s), want 0", posture, n)
		}
	}
}

// midPassFixture is a table of n routes owned by session 1, validated
// against VRPs they match, and a revalidation pass that has made its first
// step after the VRPs changed so every route's posture changes. The pass has
// read part of the table and not yet applied it.
func midPassFixture(t *testing.T, n int) (*Engine, *routetable.Table, *store.VRPStore, []*types.Route, *Revalidation) {
	t.Helper()
	vrps := store.NewVRPStore()
	vrps.ReplaceAll([]types.VRP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), ASN: 65000, MaxLength: 24}}, 1, 1)
	table := routetable.New()
	e := NewEngine(vrps, store.NewASPAStore(), nil, table, slog.New(slog.NewTextHandler(io.Discard, nil)))
	routes := make([]*types.Route, n)
	for i := range routes {
		r := &types.Route{
			PeerAddr:     netip.MustParseAddr("198.51.100.1"),
			Prefix:       netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24),
			ASPath:       []uint32{64500, 65000},
			NextHop:      netip.MustParseAddr("198.51.100.1"),
			RIBType:      types.AdjRIBInPre,
			OwnerSession: 1,
		}
		e.ValidateRoute(r)
		table.Insert(r)
		routes[i] = r
	}
	vrps.ReplaceAll([]types.VRP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), ASN: 65999, MaxLength: 24}}, 2, 1)
	rv := e.NewRevalidation()
	if rv.Step(1) {
		t.Fatal("pass finished after one route")
	}
	return e, table, vrps, routes, rv
}

// Routes withdrawn while a revalidation pass is in progress stay withdrawn,
// including those the pass had already read.
func TestRevalidationKeepsMidPassWithdrawalsWithdrawn(t *testing.T) {
	const n = 3000
	_, table, _, routes, rv := midPassFixture(t, n)
	for _, r := range routes {
		table.Withdraw(types.RouteKey{Peer: types.PeerRef{Addr: r.PeerAddr}, Prefix: r.Prefix})
	}
	for !rv.Step(64) {
	}
	if got := table.Count(); got != 0 {
		t.Errorf("table holds %d routes after the pass, want 0: withdrawn routes were brought back", got)
	}
	if rv.Skipped == 0 {
		t.Error("no read-then-withdrawn route was skipped; the test did not exercise that case")
	}
	if got := table.WithdrawSession(1); got != 0 {
		t.Errorf("owner index still held %d withdrawn routes", got)
	}
}

// Routes re-announced by a newer session while a pass is in progress keep
// the newer announcement: its owner, its attributes, and a route object
// that is not the old one.
func TestRevalidationKeepsMidPassReannouncements(t *testing.T) {
	const n = 3000
	e, table, _, routes, rv := midPassFixture(t, n)
	newHop := netip.MustParseAddr("198.51.100.2")
	for _, r := range routes {
		cp := *r
		cp.OwnerSession = 2
		cp.NextHop = newHop
		e.ValidateRoute(&cp) // as ingest does, against the current stores
		table.Insert(&cp)
	}
	for !rv.Step(64) {
	}
	for i, old := range routes {
		cur := table.Get(types.RouteKey{Peer: types.PeerRef{Addr: old.PeerAddr}, Prefix: old.Prefix, RIBType: old.RIBType})
		if cur == nil || cur == old || cur.OwnerSession != 2 || cur.NextHop != newHop {
			t.Fatalf("route %d = %+v after the pass, want session 2's announcement", i, cur)
		}
		if cur.SecurityPosture != types.PostureOriginInvalid {
			t.Fatalf("route %d posture = %s, want %s from the current VRPs", i, cur.SecurityPosture, types.PostureOriginInvalid)
		}
	}
	if rv.Skipped == 0 {
		t.Error("no read-then-replaced route was skipped; the test did not exercise that case")
	}
	if got := table.WithdrawSession(1); got != 0 {
		t.Errorf("session 1 still owns %d routes, want 0", got)
	}
	if got := table.WithdrawSession(2); got != n {
		t.Errorf("session 2's end removed %d routes, want %d", got, n)
	}
}

// aspaValidations reads raven_aspa_validations_total for one label set.
func aspaValidations(t *testing.T, procedure, source, state string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "raven_aspa_validations_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["procedure"] == procedure && labels["source"] == source && labels["state"] == state {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("no raven_aspa_validations_total{procedure=%q,source=%q,state=%q}", procedure, source, state)
	return 0
}

// Revalidation picks the ASPA procedure exactly as ingest does. The route
// [P X O] comes from a provider-mapped peer, so it is verified downstream
// (draft-24 §5.5). After the ASPA change (O lists X, X lists only AS64999) it
// is Valid downstream but would be Invalid upstream (§5.4: max_up_ramp 2 < 3),
// so a pass that fell back to upstream shows up as Invalid.
func TestRevalidationUsesSelectedASPAProcedure(t *testing.T) {
	const p, x, o = 174, 3356, 13335
	aspas := store.NewASPAStore()
	sel := aspa.NewSelector("upstream", []config.ASPAPeer{{Address: "198.51.100.1", NeighborRole: "provider"}})
	table := routetable.New()
	e := NewEngine(store.NewVRPStore(), aspas, sel, table, slog.New(slog.NewTextHandler(io.Discard, nil)))

	route := &types.Route{
		PeerAddr: netip.MustParseAddr("198.51.100.1"),
		PeerASN:  p,
		Prefix:   netip.MustParsePrefix("192.0.2.0/24"),
		ASPath:   []uint32{p, x, o},
		RIBType:  types.AdjRIBInPre,
	}
	before := aspaValidations(t, "downstream", "config-address", "Unknown")
	e.ValidateRoute(route)
	table.Insert(route)
	// §5.5 with no ASPA: min_up 1 + min_down 1 < 3 → Unknown.
	if got := route.ASPA; got.State != types.ASPAUnknown || got.Procedure != types.ASPADownstream ||
		got.ProcedureSource != types.ASPASourceConfigAddress {
		t.Fatalf("initial ASPA = %s/%s/%s, want Unknown/downstream/config-address", got.State, got.Procedure, got.ProcedureSource)
	}
	if got := aspaValidations(t, "downstream", "config-address", "Unknown") - before; got != 1 {
		t.Errorf("raven_aspa_validations_total{downstream,config-address,Unknown} rose by %v, want 1", got)
	}

	aspas.AddProvider(o, x)
	aspas.AddProvider(x, 64999)
	if rv := revalidateAll(e); rv.Changed != 1 {
		t.Fatalf("pass changed %d routes, want 1", rv.Changed)
	}
	got := table.Get(types.RouteKey{Peer: types.PeerRef{Addr: route.PeerAddr}, Prefix: route.Prefix, RIBType: route.RIBType}).ASPA
	if got.State != types.ASPAValid || got.Procedure != types.ASPADownstream || got.ProcedureSource != types.ASPASourceConfigAddress {
		t.Fatalf("revalidated ASPA = %s/%s/%s, want Valid/downstream/config-address", got.State, got.Procedure, got.ProcedureSource)
	}
}

// The demo leaks stay Invalid through the engine with the shipped default
// (upstream, no aspa-peers): [65000 1199] with AS1199 → {AS1103}, and
// [65000 64496] with AS64496 → {AS3333}.
func TestEngineDemoLeaksStillInvalid(t *testing.T) {
	aspas := store.NewASPAStore()
	aspas.AddProvider(1199, 1103)
	aspas.AddProvider(64496, 3333)
	sel := aspa.NewSelector("upstream", nil)
	e := NewEngine(store.NewVRPStore(), aspas, sel, routetable.New(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, path := range [][]uint32{{65000, 1199}, {65000, 64496}} {
		r := &types.Route{PeerAddr: netip.MustParseAddr("10.0.0.1"), PeerASN: 65000, ASPath: path}
		e.ValidateRoute(r)
		if r.ASPA.State != types.ASPAInvalid || r.ASPA.FailingHop == nil || r.ASPA.FailingHop.CustomerASN != path[1] {
			t.Errorf("path %v: ASPA = %s failing %+v, want Invalid at AS%d", path, r.ASPA.State, r.ASPA.FailingHop, path[1])
		}
	}
}
