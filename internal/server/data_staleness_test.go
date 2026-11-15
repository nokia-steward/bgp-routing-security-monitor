package server

import (
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/events"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

// raven serve reports stale data and a return to earlier data: the data
// age gauge and stale flag, one rtr_stale webhook per episode however many
// syncs it spans, one rtr_data_regressed webhook per return, and nothing to
// FlowSpec, even from a rule whose trigger matches both. rtr.stale-threshold
// is 300ms, in real time.
func TestE2EStaleDataAndRegression(t *testing.T) {
	both := config.TriggerConfig{Type: "compound", Operator: "or", Triggers: []config.TriggerConfig{
		{Type: "rtr_stale"}, {Type: "rtr_data_regressed"}}}
	mitigate := config.RuleConfig{Name: "mitigate", Trigger: both,
		Actions: []config.ActionConfig{{Type: "flowspec", DryRun: true, MaxRules: 1000}}}
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, staleThreshold: 300 * time.Millisecond, rules: []config.RuleConfig{
		webhookRule("stale", config.TriggerConfig{Type: "rtr_stale"}),
		webhookRule("regressed", config.TriggerConfig{Type: "rtr_data_regressed"}),
		mitigate,
	}})
	h.ready()
	cache := map[string]string{"cache": h.cache.Addr()}
	connected := map[string]string{"cache": h.cache.Addr(), "cache_state": "connected"}
	extra := rtrtest.VRP{Prefix: e2eP, MaxLen: 24, ASN: 65010}
	h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: []rtrtest.VRP{extra}})
	if v := gaugeValue(t, "raven_rtr_stale", connected); v != 0 {
		t.Fatalf("raven_rtr_stale %v before any staleness", v)
	}

	time.Sleep(400 * time.Millisecond)
	for range 3 { // new serials, the same data
		serial := h.cache.Advance(rtrtest.Delta{})
		h.cache.Notify()
		waitUntil(t, "the sync", func() bool { return h.s.vrpStore.Serial() == serial })
	}
	isType := func(typ string) func(webhookPost) bool {
		return func(wp webhookPost) bool { return wp.Body["type"] == typ }
	}
	h.hooks.await(t, 1, "rtr_stale", isType("rtr_stale"))
	if v := gaugeValue(t, "raven_rtr_stale", connected); v != 1 {
		t.Errorf("raven_rtr_stale %v while stale, want 1", v)
	}
	if age := gaugeValue(t, "raven_rtr_data_age_seconds", cache); age < 0.4 {
		t.Errorf("raven_rtr_data_age_seconds %v, want at least 0.4", age)
	}

	// Back to the first set: data_regressed; still stale.
	h.rtrUpdate(rtrtest.Delta{WithdrawVRPs: []rtrtest.VRP{extra}})
	h.hooks.await(t, 1, "rtr_data_regressed", isType("rtr_data_regressed"))
	if n := counterValue(t, "raven_rtr_data_regressions_total", cache); n != 1 {
		t.Errorf("raven_rtr_data_regressions_total %v, want 1", n)
	}
	// New data: the episode ends.
	h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: []rtrtest.VRP{{Prefix: e2eQ, MaxLen: 24, ASN: 65020}}})
	waitUntil(t, "raven_rtr_stale back to 0", func() bool { return gaugeValue(t, "raven_rtr_stale", connected) == 0 })
	h.stop()

	stale, regressed := h.hooks.matching(isType("rtr_stale")), h.hooks.matching(isType("rtr_data_regressed"))
	if len(stale) != 1 || stale[0].Rule != "stale" || len(regressed) != 1 || regressed[0].Rule != "regressed" {
		t.Fatalf("webhooks: %d rtr_stale %+v, %d rtr_data_regressed %+v; want one each, to their rule",
			len(stale), stale, len(regressed), regressed)
	}
	data, _ := stale[0].Body["data"].(map[string]any)
	if stale[0].Body["cache_name"] != h.cache.Addr() || data["threshold_source"] != "configured" || data["gap_ns"] == nil ||
		data["cache_state"] != "connected" {
		t.Errorf("rtr_stale payload %v", stale[0].Body)
	}
	if n := len(h.emittedOfType(events.EventTypeRTRStale)); n != 1 {
		t.Errorf("%d rtr_stale events emitted, want 1", n)
	}
	if rules := h.s.fsManagers[0].ActiveRules(); len(rules) != 0 {
		t.Errorf("FlowSpec rules %+v, want none", rules)
	}
}

// A connected cache that stops syncing goes stale too: serve evaluates the
// data age between syncs (every 15 s; 20 ms here), and sends one rtr_stale
// with no further sync.
func TestE2EStaleWithoutSyncs(t *testing.T) {
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, staleThreshold: 300 * time.Millisecond,
		dataTick: 20 * time.Millisecond, rules: []config.RuleConfig{
			webhookRule("stale", config.TriggerConfig{Type: "rtr_stale"}),
		}})
	h.ready()
	syncs := h.cache.Received()
	isStale := func(wp webhookPost) bool { return wp.Body["type"] == "rtr_stale" }
	h.hooks.await(t, 1, "rtr_stale", isStale)
	time.Sleep(200 * time.Millisecond) // more ticks: still one
	h.stop()
	if got := h.cache.Received(); len(got) != len(syncs) {
		t.Fatalf("the client queried the cache again (%d queries, then %d): the test wants no sync", len(syncs), len(got))
	}
	if n := len(h.hooks.matching(isStale)); n != 1 {
		t.Errorf("%d rtr_stale webhooks, want 1", n)
	}
	if v := gaugeValue(t, "raven_rtr_stale", map[string]string{"cache": h.cache.Addr(), "cache_state": "connected"}); v != 1 {
		t.Errorf("raven_rtr_stale %v, want 1", v)
	}
}

// A cache serve cannot reach goes stale while its last data ages, labelled
// disconnected: on the webhook and on raven_rtr_stale. (The client waits 5 s
// before reconnecting; the 300ms threshold passes well before.)
func TestE2EStaleWhileDisconnected(t *testing.T) {
	h := startE2E(t, e2eConfig{vrps: []rtrtest.VRP{unrelated}, staleThreshold: 300 * time.Millisecond,
		dataTick: 20 * time.Millisecond, rules: []config.RuleConfig{
			webhookRule("stale", config.TriggerConfig{Type: "rtr_stale"}),
		}})
	h.ready()
	h.cache.Session().Close()
	isStale := func(wp webhookPost) bool { return wp.Body["type"] == "rtr_stale" }
	posts := h.hooks.await(t, 1, "rtr_stale", isStale)
	data, _ := posts[0].Body["data"].(map[string]any)
	if data["cache_state"] != "disconnected" {
		t.Errorf("rtr_stale data %v, want cache_state disconnected", data)
	}
	if v := gaugeValue(t, "raven_rtr_stale", map[string]string{"cache": h.cache.Addr(), "cache_state": "disconnected"}); v != 1 {
		t.Errorf("raven_rtr_stale{cache_state=disconnected} %v, want 1", v)
	}
	if v := gaugeValue(t, "raven_rtr_stale", map[string]string{"cache": h.cache.Addr(), "cache_state": "connected"}); v != 0 {
		t.Errorf("raven_rtr_stale{cache_state=connected} %v, want 0", v)
	}
	h.stop()
	if n := len(h.hooks.matching(isStale)); n != 1 {
		t.Errorf("%d rtr_stale webhooks, want 1", n)
	}
}
