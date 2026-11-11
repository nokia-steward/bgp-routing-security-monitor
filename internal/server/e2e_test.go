package server

import (
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/bmp/bmptest"
	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/events"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

var (
	e2eP      = netip.MustParsePrefix("203.0.113.0/24")
	e2eQ      = netip.MustParsePrefix("198.51.100.0/24")
	e2eR      = netip.MustParsePrefix("100.64.10.0/24")
	unrelated = rtrtest.VRP{Prefix: netip.MustParsePrefix("100.127.0.0/16"), MaxLen: 16, ASN: 65111}
)

func invalidRule() config.RuleConfig {
	r := webhookRule("invalid", postureChange("origin-invalid"))
	r.Actions = append(r.Actions, config.ActionConfig{Type: "flowspec", DryRun: true, MaxRules: 1000})
	return r
}

func fromRTR(wp webhookPost) bool { return wp.Body["source"] == "rtr" }

// The gap this suite was written for: an RTR update that invalidates a BMP
// route used to reach raven watch only. A route NotFound, then a VRP for
// another origin covers it: it turns Invalid, and watch, the webhook and
// FlowSpec each see that exactly once, as an RTR-driven change.
func TestE2ERTRUpdateInvalidatesRoute(t *testing.T) {
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, rules: []config.RuleConfig{invalidRule()}})
	h.ready()
	w := h.watch("")
	h.announce(bmptest.Route{Prefix: e2eP, ASPath: []uint32{64501, 65010}})
	if got := h.route(e2eP).SecurityPosture; got != types.PostureUnverified {
		t.Fatalf("before the update: posture %s, want unverified (NotFound)", got)
	}
	h.sendMarker(1)
	w.until(t)

	serial := h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: []rtrtest.VRP{{Prefix: e2eP, MaxLen: 24, ASN: 65999}}})
	h.sendMarker(2)
	evs := forWatchPrefix(w.until(t), e2eP)
	if len(evs) != 1 || evs[0].Source != "rtr" || evs[0].Posture != "origin-invalid" || evs[0].ROV != "Invalid" {
		t.Fatalf("watch events for %s after the update: %+v, want one, source rtr, origin-invalid", e2eP, evs)
	}
	h.hooks.await(t, 1, "the invalidated route", forPrefix(e2eP))
	waitUntil(t, "a FlowSpec rule for the route", func() bool { return len(h.flowspecRules()) == 1 })
	h.stop()

	posts := h.hooks.matching(forPrefix(e2eP))
	if len(posts) != 1 {
		t.Fatalf("%d webhook posts for %s, want exactly 1: %+v", len(posts), e2eP, posts)
	}
	b := posts[0].Body
	if b["source"] != "rtr" || b["type"] != "posture_change" || b["old_posture"] != "unverified" ||
		b["new_posture"] != "origin-invalid" || b["serial"] != float64(serial) || posts[0].Rule != "invalid" {
		t.Errorf("webhook payload %v, want rule invalid, source rtr, posture_change unverified -> origin-invalid, serial %d", b, serial)
	}
	rtrEvents := 0
	for _, ev := range h.emittedFor(e2eP) {
		if ev.Source == events.SourceRTR {
			rtrEvents++
		}
	}
	if rtrEvents != 1 {
		t.Errorf("%d RTR-driven events for %s handed to the engine, want 1", rtrEvents, e2eP)
	}
	rules := h.s.fsManagers[0].ActiveRules()
	if len(rules) != 1 || rules[0].Prefix != e2eP || !rules[0].DryRun {
		t.Errorf("FlowSpec rules %+v, want one dry-run rule for %s", rules, e2eP)
	}
}

// An RTR withdrawal makes a Valid route NotFound: one watch event, and one
// event per rule it matches (a posture rule and a source rule here).
func TestE2ERTRWithdrawalMakesRouteNotFound(t *testing.T) {
	vrp := rtrtest.VRP{Prefix: e2eQ, MaxLen: 24, ASN: 65020}
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{vrp}, rules: []config.RuleConfig{
		webhookRule("notfound", postureChange("unverified")),
		webhookRule("from-rtr", config.TriggerConfig{Type: "source", Sources: []string{"rtr"}}),
	}})
	h.ready()
	w := h.watch("")
	h.announce(bmptest.Route{Prefix: e2eQ, ASPath: []uint32{64501, 65020}})
	if got := h.route(e2eQ).SecurityPosture; got != types.PostureOriginOnly {
		t.Fatalf("before the withdrawal: posture %s, want origin-only (Valid)", got)
	}
	h.sendMarker(1)
	w.until(t)

	h.rtrUpdate(rtrtest.Delta{WithdrawVRPs: []rtrtest.VRP{vrp}})
	h.sendMarker(2)
	if evs := forWatchPrefix(w.until(t), e2eQ); len(evs) != 1 || evs[0].Source != "rtr" || evs[0].Posture != "unverified" {
		t.Fatalf("watch events for %s: %+v, want one, source rtr, unverified", e2eQ, evs)
	}
	h.hooks.await(t, 2, "the withdrawn route's rules", forPrefix(e2eQ))
	h.stop()
	posts := h.hooks.matching(forPrefix(e2eQ))
	byRule := map[string]int{}
	for _, p := range posts {
		byRule[p.Rule]++
		if p.Body["source"] != "rtr" || p.Body["old_posture"] != "origin-only" || p.Body["new_posture"] != "unverified" {
			t.Errorf("payload %v, want source rtr, origin-only -> unverified", p.Body)
		}
	}
	if len(posts) != 2 || byRule["notfound"] != 1 || byRule["from-rtr"] != 1 {
		t.Errorf("webhook posts by rule %v, want one per rule", byRule)
	}
}

// An ASPA delta that leaves the route's origin AS without the neighbor as a
// provider turns the route path-suspect: one watch event, one event.
func TestE2EASPADeltaMakesRoutePathSuspect(t *testing.T) {
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, rules: []config.RuleConfig{
		webhookRule("path-suspect", postureChange("path-suspect")),
	}})
	h.ready()
	w := h.watch("")
	h.announce(bmptest.Route{Prefix: e2eR, ASPath: []uint32{64501, 65030}})
	if got := h.route(e2eR); got.SecurityPosture != types.PostureUnverified {
		t.Fatalf("before the ASPA: posture %s (ASPA %s), want unverified", got.SecurityPosture, got.ASPA.State)
	}
	h.sendMarker(1)
	w.until(t)

	h.rtrUpdate(rtrtest.Delta{AnnounceASPAs: []rtrtest.ASPASet{{Customer: 65030, Providers: []uint32{64999}}}})
	h.sendMarker(2)
	if evs := forWatchPrefix(w.until(t), e2eR); len(evs) != 1 || evs[0].Source != "rtr" ||
		evs[0].Posture != "path-suspect" || evs[0].ASPA != "Invalid" {
		t.Fatalf("watch events for %s: %+v, want one, source rtr, path-suspect", e2eR, evs)
	}
	h.hooks.await(t, 1, "the path-suspect route", forPrefix(e2eR))
	h.stop()
	posts := h.hooks.matching(forPrefix(e2eR))
	if len(posts) != 1 || posts[0].Body["source"] != "rtr" || posts[0].Body["new_posture"] != "path-suspect" ||
		posts[0].Body["aspa_state"] != "Invalid" {
		t.Errorf("webhook posts for %s: %+v, want one RTR-driven path-suspect", e2eR, posts)
	}
}

// bulkPrefix is the i-th route of the bulk tests.
func bulkPrefix(i int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 20, byte(i >> 8), byte(i)}), 32)
}

// The bulk guard, at its default threshold (100). One RTR update that turns
// 101 routes Invalid: watch gets all 101 changes, the event engine one
// rtr_bulk_change event (one webhook post, from the rule the routes would
// have fired), no per-route webhook or FlowSpec action, and the suppressed
// actions are counted. 100 routes: every per-route event fires.
func TestE2ERTRBulkGuard(t *testing.T) {
	for _, tc := range []struct {
		name   string
		routes int
		bulk   bool
	}{
		{"threshold+1 routes", events.DefaultRTRBulkThreshold + 1, true},
		{"threshold routes", events.DefaultRTRBulkThreshold, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, rules: []config.RuleConfig{invalidRule()}})
			h.ready()
			w := h.watch("")
			var routes []bmptest.Route
			var vrps []rtrtest.VRP
			for i := range tc.routes {
				p := bulkPrefix(i)
				routes = append(routes, bmptest.Route{Prefix: p, ASPath: []uint32{64501, 65040}})
				vrps = append(vrps, rtrtest.VRP{Prefix: p, MaxLen: 32, ASN: 65999})
			}
			h.announce(routes...)
			h.sendMarker(1)
			w.until(t)
			dropped := counterValue(t, "raven_watch_events_dropped_total", nil)
			suppressed := counterValue(t, "raven_events_rtr_bulk_suppressed_actions_total", nil)
			bulks := counterValue(t, "raven_events_rtr_bulk_changes_total", nil)

			serial := h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: vrps})
			h.sendMarker(2)
			changed := 0
			for _, e := range w.until(t) {
				if e.Source == "rtr" && e.Posture == "origin-invalid" {
					changed++
				}
			}
			if changed != tc.routes {
				t.Errorf("watch delivered %d RTR-driven changes, want every one of %d", changed, tc.routes)
			}
			if d := counterValue(t, "raven_watch_events_dropped_total", nil) - dropped; d != 0 {
				t.Errorf("%v watch events dropped for a watcher that reads", d)
			}

			if tc.bulk {
				h.hooks.await(t, 1, "the rtr_bulk_change", func(wp webhookPost) bool { return wp.Body["type"] == "rtr_bulk_change" })
			} else {
				h.hooks.await(t, tc.routes, "per-route events", fromRTR)
				waitUntil(t, "a FlowSpec rule per route", func() bool { return len(h.flowspecRules()) == tc.routes })
			}
			h.stop()

			rtrPosts := h.hooks.matching(fromRTR)
			fsRules := h.s.fsManagers[0].ActiveRules()
			if !tc.bulk {
				if len(rtrPosts) != tc.routes || len(fsRules) != tc.routes || len(h.emittedOfType(events.EventTypeRTRBulkChange)) != 0 {
					t.Errorf("%d per-route posts, %d FlowSpec rules, %d bulk events; want %d, %d, 0",
						len(rtrPosts), len(fsRules), len(h.emittedOfType(events.EventTypeRTRBulkChange)), tc.routes, tc.routes)
				}
				if d := counterValue(t, "raven_events_rtr_bulk_suppressed_actions_total", nil) - suppressed; d != 0 {
					t.Errorf("%v actions suppressed at the threshold, want 0", d)
				}
				return
			}
			if len(rtrPosts) != 1 {
				t.Fatalf("%d RTR-driven webhook posts, want exactly the one rtr_bulk_change: %+v", len(rtrPosts), rtrPosts)
			}
			b := rtrPosts[0].Body
			bulk, _ := b["bulk"].(map[string]any)
			matched, _ := bulk["matched"].(map[string]any)
			changes, _ := bulk["changes"].(map[string]any)
			samples, _ := matched["sample_prefixes"].([]any)
			transitions, _ := matched["transitions"].(map[string]any)
			if b["type"] != "rtr_bulk_change" || rtrPosts[0].Rule != "invalid" || b["cache_name"] != h.cache.Addr() ||
				b["serial"] != float64(serial) || bulk["suppressed"] != true || bulk["threshold"] != float64(events.DefaultRTRBulkThreshold) ||
				matched["routes"] != float64(tc.routes) || changes["routes"] != float64(tc.routes) ||
				len(samples) != events.MaxBulkSamples || len(transitions) != 1 ||
				transitions["unverified->origin-invalid"] != float64(tc.routes) || b["prefix"] != "" {
				t.Errorf("bulk payload %v, want rule invalid, cache %s, serial %d, suppressed, %d routes matched and changed, unverified->origin-invalid, %d samples",
					b, h.cache.Addr(), serial, tc.routes, events.MaxBulkSamples)
			}
			if len(fsRules) != 0 {
				t.Errorf("%d FlowSpec rules, want none for a bulk change", len(fsRules))
			}
			if d := counterValue(t, "raven_events_rtr_bulk_suppressed_actions_total", nil) - suppressed; d != float64(2*tc.routes) {
				t.Errorf("suppressed actions counter rose by %v, want %d (webhook and FlowSpec per route)", d, 2*tc.routes)
			}
			if d := counterValue(t, "raven_events_rtr_bulk_changes_total", nil) - bulks; d != 1 {
				t.Errorf("bulk change counter rose by %v, want 1", d)
			}
			perRoute := 0
			for _, ev := range h.emittedOfType(events.EventTypePostureChange) {
				if ev.Source == events.SourceRTR {
					perRoute++
				}
			}
			if perRoute != 0 {
				t.Errorf("%d per-route RTR-driven events handed to the engine, want 0", perRoute)
			}
		})
	}
}

// The same state arriving again is not a change: a BMP re-announcement of an
// unchanged route, or an RTR update that touches the route without changing
// its result (another VRP that also makes it Valid), sends nothing to watch
// or the event engine.
func TestE2ENoChangeNoEvent(t *testing.T) {
	vrp := rtrtest.VRP{Prefix: e2eP, MaxLen: 24, ASN: 65010}
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{vrp}, rules: []config.RuleConfig{
		webhookRule("everything", config.TriggerConfig{Type: "source", Sources: []string{"bmp", "rtr"}}),
	}})
	h.ready()
	w := h.watch("")
	route := bmptest.Route{Prefix: e2eP, ASPath: []uint32{64501, 65010}, Communities: []uint32{64501<<16 | 7}}
	h.announce(route)
	h.sendMarker(1)
	if evs := forWatchPrefix(w.until(t), e2eP); len(evs) != 1 || evs[0].Source != "bmp" {
		t.Fatalf("watch events for the new route: %+v, want one, source bmp", evs)
	}
	h.hooks.await(t, 1, "the new route", forPrefix(e2eP))

	h.feed.Announce(h.peer, route) // identical
	h.sendMarker(2)
	if evs := forWatchPrefix(w.until(t), e2eP); len(evs) != 0 {
		t.Errorf("watch events for an identical re-announcement: %+v, want none", evs)
	}
	h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: []rtrtest.VRP{{Prefix: e2eP, MaxLen: 25, ASN: 65010}}})
	if got := h.route(e2eP); got.SecurityPosture != types.PostureOriginOnly {
		t.Fatalf("after the second VRP: posture %s, want still origin-only", got.SecurityPosture)
	}
	h.sendMarker(3)
	if evs := forWatchPrefix(w.until(t), e2eP); len(evs) != 0 {
		t.Errorf("watch events for an RTR update that changes nothing for the route: %+v, want none", evs)
	}
	h.stop()
	if evs := h.emittedFor(e2eP); len(evs) != 1 || evs[0].Type != events.EventTypeNewRoute {
		t.Errorf("events for %s handed to the engine: %d, want only the new_route", e2eP, len(evs))
	}
	if posts := h.hooks.matching(forPrefix(e2eP)); len(posts) != 1 {
		t.Errorf("%d webhook posts for %s, want only the new route's", len(posts), e2eP)
	}
}

// BMP Peer Down: the peer's routes leave the table, and the status API's
// posture totals add up to its route count.
func TestE2EPeerDown(t *testing.T) {
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{{Prefix: e2eP, MaxLen: 24, ASN: 65010}}})
	h.ready()
	other := bmptest.Peer{Addr: netip.MustParseAddr("198.18.0.2"), ASN: 64502, BGPID: netip.MustParseAddr("198.18.0.2")}
	h.feed.PeerUp(other)
	h.announce(
		bmptest.Route{Prefix: e2eP, ASPath: []uint32{64501, 65010}},                                      // Valid
		bmptest.Route{Prefix: netip.MustParsePrefix("203.0.113.128/25"), ASPath: []uint32{64501, 65010}}, // Invalid: longer than the VRP allows
		bmptest.Route{Prefix: e2eQ, ASPath: []uint32{64501, 65020}},                                      // NotFound
		bmptest.Route{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), ASPath: []uint32{64501, 65020}},  // IPv6
	)
	keep := []bmptest.Route{
		{Prefix: e2eP, ASPath: []uint32{64502, 65010}},
		{Prefix: e2eR, ASPath: []uint32{64502, 65030}},
		{Prefix: netip.MustParsePrefix("2001:db8:2::/48"), ASPath: []uint32{64502, 65031}},
	}
	h.feed.Announce(other, keep...)
	h.waitTable(7, "both peers' routes") // 4 from the peer that goes down, 3 from the other

	h.feed.PeerDown(h.peer)
	waitUntil(t, "the peer's routes gone", func() bool {
		return h.s.removalsPending.Load() == 0 && h.s.table.Count() == 3
	})
	for _, r := range h.s.table.Snapshot() {
		if r.PeerAddr == h.peer.Addr {
			t.Errorf("route %s from the peer that went down is still in the table", r.Prefix)
		}
	}
	st := h.status()
	var sum uint64
	for _, n := range st.RouteTable.ByPosture {
		sum += n
	}
	if st.RouteTable.TotalRoutes != 3 || sum != st.RouteTable.TotalRoutes {
		t.Errorf("status: total %d, postures %v (sum %d); want 3 and a matching sum",
			st.RouteTable.TotalRoutes, st.RouteTable.ByPosture, sum)
	}
}

// Each way an RTR session ends counts once in raven_rtr_disconnects_total,
// with its reason, and marks the cache disconnected.
func TestE2ERTRDisconnectReasons(t *testing.T) {
	for _, tc := range []struct {
		reason telemetry.DisconnectReason
		cache  func(*rtrtest.ServerConfig)
		end    func(h *e2e)
	}{
		{reason: telemetry.DisconnectReasonEOF, end: func(h *e2e) { h.cache.Session().Close() }},
		{reason: telemetry.DisconnectReasonReset, end: func(h *e2e) { h.cache.Session().Reset() }},
		{reason: telemetry.DisconnectReasonErrorReport, end: func(h *e2e) {
			h.cache.Session().Send(rtrtest.ErrorReport(2, 0, "Corrupt Data"))
		}},
		// Refresh 1 s, Retry 1 s: the first poll goes unanswered.
		{reason: telemetry.DisconnectReasonTimeout,
			cache: func(c *rtrtest.ServerConfig) { c.Refresh, c.Retry = 1, 1 },
			end:   func(h *e2e) { h.cache.Then(rtrtest.Stall) }},
		{reason: telemetry.DisconnectReasonShutdown, end: func(h *e2e) { h.stop() }},
	} {
		t.Run(string(tc.reason), func(t *testing.T) {
			t.Parallel()
			h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, cache: tc.cache})
			h.ready()
			addr := h.cache.Addr()
			// The counters are process-wide, and a later run (-count) may
			// get the same port: count what this test adds.
			base := map[telemetry.DisconnectReason]float64{}
			raw := func(r telemetry.DisconnectReason) float64 {
				return counterValue(t, "raven_rtr_disconnects_total", map[string]string{"cache": addr, "reason": string(r)})
			}
			for _, r := range telemetry.DisconnectReasons {
				base[r] = raw(r)
			}
			count := func(r telemetry.DisconnectReason) float64 { return raw(r) - base[r] }
			tc.end(h)
			waitUntil(t, "the disconnect counted", func() bool { return count(tc.reason) == 1 })
			if tc.reason != telemetry.DisconnectReasonShutdown {
				h.s.rtrMu.RLock()
				state := h.s.rtrStates[addr]
				h.s.rtrMu.RUnlock()
				if state != 0 {
					t.Errorf("cache state %d after the disconnect, want 0", state)
				}
			}
			h.stop()
			for _, r := range telemetry.DisconnectReasons {
				want := 0.0
				if r == tc.reason {
					want = 1
				}
				got := count(r)
				// Stopping ends a session only if the client has one: after
				// the disconnect it waits out its backoff (5s) first.
				if r == telemetry.DisconnectReasonShutdown && tc.reason != r && got <= 1 {
					continue
				}
				if got != want {
					t.Errorf("raven_rtr_disconnects_total{reason=%q} = %v, want %v", r, got, want)
				}
			}
		})
	}
}

// BMP-driven changes fire events as before, now with source bmp: a new
// route, a posture change, a change of attributes only (old and new posture
// alike), an IPv6 route, a withdrawal. Only an identical re-announcement,
// which changes nothing, no longer fires.
func TestE2EBMPEventsUnchanged(t *testing.T) {
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{{Prefix: e2eP, MaxLen: 24, ASN: 65010}}, rules: []config.RuleConfig{
		webhookRule("bmp", config.TriggerConfig{Type: "source", Sources: []string{"bmp"}}),
	}})
	h.ready()
	w := h.watch("")
	v6 := netip.MustParsePrefix("2001:db8:100::/48")
	type want struct {
		prefix   netip.Prefix
		typ      string
		old, new string
	}
	steps := []struct {
		do   func()
		want *want
	}{
		{func() { h.announce(bmptest.Route{Prefix: e2eP, ASPath: []uint32{64501, 65010}}) },
			&want{e2eP, "new_route", "", "origin-only"}},
		{func() { h.announce(bmptest.Route{Prefix: e2eP, ASPath: []uint32{64501, 65999}}) },
			&want{e2eP, "posture_change", "origin-only", "origin-invalid"}},
		{func() {
			h.announce(bmptest.Route{Prefix: e2eP, ASPath: []uint32{64501, 65999}, Communities: []uint32{64501<<16 | 100},
				LargeCommunities: [][3]uint32{{64501, 1, 2}}})
		}, &want{e2eP, "posture_change", "origin-invalid", "origin-invalid"}},
		{func() {
			h.feed.Announce(h.peer, bmptest.Route{Prefix: e2eP, ASPath: []uint32{64501, 65999}, Communities: []uint32{64501<<16 | 100},
				LargeCommunities: [][3]uint32{{64501, 1, 2}}})
		}, nil}, // identical
		{func() { h.announce(bmptest.Route{Prefix: v6, ASPath: []uint32{64501, 65010}}) },
			&want{v6, "new_route", "", "unverified"}},
		{func() {
			h.feed.Withdraw(h.peer, e2eP)
			waitUntil(t, "the withdrawal", func() bool { return h.route(e2eP) == nil })
		}, &want{e2eP, "route_withdraw", "origin-invalid", ""}},
	}
	var wants []want
	for i, st := range steps {
		st.do()
		h.sendMarker(uint32(i + 1))
		evs := w.until(t)
		switch {
		case st.want == nil && len(evs) != 0:
			t.Errorf("step %d (identical re-announcement): watch events %+v, want none", i, evs)
		case st.want != nil && st.want.typ != "route_withdraw":
			if len(evs) != 1 || evs[0].Source != "bmp" || evs[0].Posture != st.want.new || evs[0].Prefix != st.want.prefix.String() {
				t.Errorf("step %d: watch events %+v, want one for %s, source bmp, %s", i, evs, st.want.prefix, st.want.new)
			} else if i == 2 && (len(evs[0].Communities) != 1 || evs[0].Communities[0] != "64501:100" ||
				len(evs[0].LargeCommunities) != 1 || evs[0].LargeCommunities[0] != "64501:1:2") {
				t.Errorf("step %d: communities %v, large %v; want 64501:100 and 64501:1:2", i, evs[0].Communities, evs[0].LargeCommunities)
			}
		}
		if st.want != nil {
			wants = append(wants, *st.want)
			h.hooks.await(t, len(wants), "step events", notMarker)
		}
	}
	h.stop()
	posts := h.hooks.matching(notMarker)
	if len(posts) != len(wants) {
		t.Fatalf("%d webhook posts, want %d (one per change): %+v", len(posts), len(wants), posts)
	}
	remaining := map[want]int{}
	for _, wn := range wants {
		remaining[wn]++
	}
	for _, p := range posts {
		b := p.Body
		got := want{netip.MustParsePrefix(b["prefix"].(string)), b["type"].(string), b["old_posture"].(string), b["new_posture"].(string)}
		if b["source"] != "bmp" {
			t.Errorf("post %v: source %v, want bmp", b, b["source"])
		}
		if remaining[got] == 0 {
			t.Errorf("unexpected post %+v", got)
		}
		remaining[got]--
	}
}

// notMarker keeps the posts that are not about the marker route.
func notMarker(wp webhookPost) bool { return wp.Body["prefix"] != e2eMarker.String() }

// An rtr_bulk_change event reaches notification actions only. One route
// turned Invalid on its own gets its FlowSpec rule and webhook; then an
// update turning 101 routes Invalid, which both rules' triggers match, adds
// no FlowSpec rule (per route or aggregate), and the webhook rule gets
// exactly one rtr_bulk_change.
func TestE2EBulkChangeNeverReachesFlowSpec(t *testing.T) {
	mitigate := config.RuleConfig{Name: "mitigate", Trigger: postureChange("origin-invalid"),
		Actions: []config.ActionConfig{{Type: "flowspec", DryRun: true, MaxRules: 1000}}}
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, rules: []config.RuleConfig{
		mitigate, webhookRule("notify", postureChange("origin-invalid")),
	}})
	h.ready()
	h.announce(bmptest.Route{Prefix: e2eP, ASPath: []uint32{64501, 65010}})
	h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: []rtrtest.VRP{{Prefix: e2eP, MaxLen: 24, ASN: 65999}}})
	h.hooks.await(t, 1, "the single invalid route", forPrefix(e2eP))
	waitUntil(t, "its FlowSpec rule", func() bool { return len(h.flowspecRules()) == 1 })

	n := events.DefaultRTRBulkThreshold + 1
	var routes []bmptest.Route
	var vrps []rtrtest.VRP
	for i := range n {
		routes = append(routes, bmptest.Route{Prefix: bulkPrefix(i), ASPath: []uint32{64501, 65040}})
		vrps = append(vrps, rtrtest.VRP{Prefix: bulkPrefix(i), MaxLen: 32, ASN: 65999})
	}
	h.announce(routes...)
	h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: vrps})
	isBulk := func(wp webhookPost) bool { return wp.Body["type"] == "rtr_bulk_change" }
	h.hooks.await(t, 1, "the rtr_bulk_change", isBulk)
	h.stop()

	if rules := h.s.fsManagers[0].ActiveRules(); len(rules) != 1 || rules[0].Prefix != e2eP {
		t.Errorf("FlowSpec rules after the bulk pass: %d, want only the single route's (%s)", len(rules), e2eP)
	}
	bulk := h.hooks.matching(isBulk)
	if len(bulk) != 1 || bulk[0].Rule != "notify" {
		t.Errorf("rtr_bulk_change posts %+v, want exactly one, to rule notify", bulk)
	}
	if rtr := h.hooks.matching(fromRTR); len(rtr) != 2 {
		t.Errorf("%d RTR-driven posts, want 2 (the single route's, the bulk change)", len(rtr))
	}
}

// wavePrefix is the i-th route of the harmless wave.
func wavePrefix(i int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 30, byte(i >> 8), byte(i)}), 32)
}

// Two counts against the bulk threshold. Suppression counts only changes a
// rule acts on: one update turns 500 routes NotFound -> Valid (a new ROA; no
// rule acts on that) and one route Valid -> Invalid, and with an
// origin-invalid webhook rule and the default threshold of 100 the invalid
// route gets its per-route webhook and the rule no rtr_bulk_change. The
// rtr_bulk_change trigger counts every change: a rule with it, if present,
// gets exactly one rtr_bulk_change for the 501. Watch sees all 501 changes.
func TestE2EHarmlessWaveDoesNotSuppressAlert(t *testing.T) {
	for _, withBulkRule := range []bool{false, true} {
		name := "origin-invalid rule"
		if withBulkRule {
			name += " and an rtr_bulk_change rule"
		}
		t.Run(name, func(t *testing.T) {
			valid := rtrtest.VRP{Prefix: e2eQ, MaxLen: 24, ASN: 65060}
			rules := []config.RuleConfig{webhookRule("invalid", postureChange("origin-invalid"))}
			if withBulkRule {
				rules = append(rules, webhookRule("mass", config.TriggerConfig{Type: "rtr_bulk_change"}))
			}
			h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{valid}, rules: rules})
			h.ready()
			w := h.watch("")
			const wave = 500
			var routes []bmptest.Route
			var vrps []rtrtest.VRP
			for i := range wave {
				routes = append(routes, bmptest.Route{Prefix: wavePrefix(i), ASPath: []uint32{64501, 65050}})
				vrps = append(vrps, rtrtest.VRP{Prefix: wavePrefix(i), MaxLen: 32, ASN: 65050})
			}
			h.announce(append(routes, bmptest.Route{Prefix: e2eQ, ASPath: []uint32{64501, 65060}})...)
			h.sendMarker(1)
			w.until(t)

			h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: append(vrps, rtrtest.VRP{Prefix: e2eQ, MaxLen: 24, ASN: 65999}),
				WithdrawVRPs: []rtrtest.VRP{valid}})
			h.sendMarker(2)
			byPosture := map[string]int{}
			for _, e := range w.until(t) {
				if e.Source == "rtr" {
					byPosture[e.Posture]++
				}
			}
			if byPosture["origin-only"] != wave || byPosture["origin-invalid"] != 1 {
				t.Errorf("watch RTR-driven changes by posture %v, want %d origin-only and 1 origin-invalid", byPosture, wave)
			}
			h.hooks.await(t, 1, "the invalid route's webhook", forPrefix(e2eQ))
			if withBulkRule {
				h.hooks.await(t, 1, "the rtr_bulk_change rule's post", func(wp webhookPost) bool { return wp.Rule == "mass" })
			}
			h.stop()

			byRule := func(rule string) []webhookPost {
				return h.hooks.matching(func(wp webhookPost) bool { return wp.Rule == rule && fromRTR(wp) })
			}
			posts := byRule("invalid")
			if len(posts) != 1 || posts[0].Body["prefix"] != e2eQ.String() || posts[0].Body["type"] != "posture_change" ||
				posts[0].Body["old_posture"] != "origin-only" || posts[0].Body["new_posture"] != "origin-invalid" {
				t.Errorf("origin-invalid rule's RTR-driven posts %+v, want exactly one per-route posture_change for %s and no rtr_bulk_change",
					posts, e2eQ)
			}
			mass := byRule("mass")
			if !withBulkRule {
				return
			}
			if len(mass) != 1 || mass[0].Body["type"] != "rtr_bulk_change" {
				t.Fatalf("rtr_bulk_change rule's posts %+v, want exactly one rtr_bulk_change", mass)
			}
			bulk, _ := mass[0].Body["bulk"].(map[string]any)
			changes, _ := bulk["changes"].(map[string]any)
			matched, _ := bulk["matched"].(map[string]any)
			if bulk["suppressed"] != false || changes["routes"] != float64(wave+1) || matched["routes"] != float64(1) {
				t.Errorf("bulk payload %v, want not suppressed, %d changes, 1 matched", bulk, wave+1)
			}
		})
	}
}

// The rtr_bulk_change trigger fires on the pass's total changes whether or
// not any other rule matches them: only an rtr_bulk_change rule, 500 routes
// NotFound -> Valid in one pass, the default threshold of 100: exactly one
// rtr_bulk_change.
func TestE2EBulkRuleFiresOnTotalChanges(t *testing.T) {
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, rules: []config.RuleConfig{
		webhookRule("mass", config.TriggerConfig{Type: "rtr_bulk_change"}),
	}})
	h.ready()
	const wave = 500
	var routes []bmptest.Route
	var vrps []rtrtest.VRP
	for i := range wave {
		routes = append(routes, bmptest.Route{Prefix: wavePrefix(i), ASPath: []uint32{64501, 65050}})
		vrps = append(vrps, rtrtest.VRP{Prefix: wavePrefix(i), MaxLen: 32, ASN: 65050})
	}
	h.announce(routes...)
	serial := h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: vrps})
	h.hooks.await(t, 1, "the rtr_bulk_change", func(webhookPost) bool { return true })
	h.stop()

	posts := h.hooks.matching(func(webhookPost) bool { return true })
	if len(posts) != 1 || posts[0].Body["type"] != "rtr_bulk_change" || posts[0].Body["serial"] != float64(serial) {
		t.Fatalf("posts %+v, want exactly one rtr_bulk_change at serial %d", posts, serial)
	}
	bulk, _ := posts[0].Body["bulk"].(map[string]any)
	changes, _ := bulk["changes"].(map[string]any)
	matched, _ := bulk["matched"].(map[string]any)
	transitions, _ := changes["transitions"].(map[string]any)
	samples, _ := changes["sample_prefixes"].([]any)
	if bulk["suppressed"] != false || changes["routes"] != float64(wave) || matched["routes"] != float64(0) ||
		transitions["unverified->origin-only"] != float64(wave) || len(samples) != events.MaxBulkSamples {
		t.Errorf("bulk payload %v, want %d changes unverified->origin-only with %d samples, none matched, not suppressed",
			bulk, wave, events.MaxBulkSamples)
	}
}
