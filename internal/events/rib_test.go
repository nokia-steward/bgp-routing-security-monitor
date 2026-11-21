package events

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// ribRoute is newRoute's route in another RIB, router and instance.
func ribRoute(rib types.RIBType, router string, rd uint64) *types.Route {
	r := newRoute("10.0.0.0/8")
	r.RIBType, r.Router, r.PeerDistinguisher = rib, netip.MustParseAddr(router), rd
	return r
}

// The cooldown is kept per route: an event in one RIB, on one router or in
// one VRF does not suppress the same prefix and peer address elsewhere. It
// was kept per prefix and peer address.
func TestCooldownPerRouteAndRIB(t *testing.T) {
	action := &countAction{}
	rule := &Rule{
		Name: "per-route", Trigger: &alwaysTrigger{}, Actions: []Action{action},
		Cooldown: time.Hour, log: slog.Default(), cooldownMap: make(map[string]time.Time),
	}
	ctx := context.Background()
	fire := func(r *types.Route) {
		rule.Evaluate(ctx, Event{ID: NewID(), Type: EventTypeNewRoute, Route: r, NewPosture: types.PostureOriginInvalid})
	}
	routes := []*types.Route{
		ribRoute(types.AdjRIBInPre, "192.0.2.10", 0),
		ribRoute(types.AdjRIBInPost, "192.0.2.10", 0),
		ribRoute(types.LocRIB, "192.0.2.10", 0),
		ribRoute(types.AdjRIBInPre, "192.0.2.11", 0),                     // another router
		ribRoute(types.AdjRIBInPre, "192.0.2.10", 0x0000fde8_00000001),   // 65000:1
		ribRoute(types.AdjRIBInPre, "192.0.2.10", 0x0002_0000_fde8_0001), // 65000L:1
	}
	for _, r := range routes {
		fire(r)
	}
	if n := action.count(); n != len(routes) {
		t.Errorf("%d actions for %d distinct routes, want one each", n, len(routes))
	}
	for _, r := range routes {
		fire(r)
	}
	if n := action.count(); n != len(routes) {
		t.Errorf("%d actions after repeating them within the cooldown, want still %d", n, len(routes))
	}
}

// The rib trigger matches routes of its RIBs; pre-policy and post-policy are
// aliases, and an unknown RIB or none is a config error.
func TestRIBTrigger(t *testing.T) {
	tr, err := buildTrigger(config.TriggerConfig{Type: "rib", RIBs: []string{"loc-rib", "post-policy"}})
	if err != nil {
		t.Fatal(err)
	}
	for rib, want := range map[types.RIBType]bool{
		types.AdjRIBInPre: false, types.AdjRIBInPost: true, types.LocRIB: true, types.AdjRIBOutPre: false,
	} {
		if got := tr.Matches(Event{Route: ribRoute(rib, "192.0.2.10", 0)}); got != want {
			t.Errorf("%s: Matches = %v, want %v", rib, got, want)
		}
	}
	if tr.Matches(Event{Type: EventTypeCacheUnhealthy}) {
		t.Error("an event without a route matched")
	}
	for _, ribs := range [][]string{nil, {"adj-rib-in"}} {
		if _, err := buildTrigger(config.TriggerConfig{Type: "rib", RIBs: ribs}); err == nil {
			t.Errorf("rib trigger with %v: no error", ribs)
		}
	}

	// In a compound trigger, from config.
	eng, _, err := BuildEngine(config.EventsConfig{Rules: []config.RuleConfig{{
		Name: "loc-rib-invalid",
		Trigger: config.TriggerConfig{Type: "compound", Operator: "and", Triggers: []config.TriggerConfig{
			{Type: "posture", Postures: []string{"origin-invalid"}},
			{Type: "rib", RIBs: []string{"pre-policy"}},
		}},
		Actions: []config.ActionConfig{{Type: "log"}},
	}}}, slog.Default())
	if err != nil {
		t.Fatalf("BuildEngine: %v", err)
	}
	ev := Event{Route: ribRoute(types.AdjRIBInPre, "192.0.2.10", 0), NewPosture: types.PostureOriginInvalid}
	if !eng.rules[0].Trigger.Matches(ev) {
		t.Error("compound posture+rib trigger did not match an origin-invalid pre-policy route")
	}
	ev.Route = ribRoute(types.LocRIB, "192.0.2.10", 0)
	if eng.rules[0].Trigger.Matches(ev) {
		t.Error("compound trigger for pre-policy matched a Loc-RIB route")
	}
}

// Webhook payloads and log lines name the route's RIB and peer
// distinguisher: a rule fires once per route, RIB and instance.
func TestActionsCarryRIBAndDistinguisher(t *testing.T) {
	event := Event{
		ID: NewID(), Timestamp: time.Now(), Type: EventTypeNewRoute,
		Route:      ribRoute(types.LocRIB, "192.0.2.10", 0x0002_0000_fde8_0001),
		NewPosture: types.PostureOriginInvalid,
	}

	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	if err := newWebhookAction(srv.URL, "", "r", 1, 5*time.Second, nil, slog.Default()).Execute(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["rib"] != "loc-rib" || got["peer_distinguisher"] != "65000L:1" {
		t.Errorf("payload rib %v, peer_distinguisher %v; want loc-rib, 65000L:1", got["rib"], got["peer_distinguisher"])
	}
	// Always present, "" for a global peer.
	event.Route = ribRoute(types.AdjRIBInPre, "192.0.2.10", 0)
	if err := newWebhookAction(srv.URL, "", "r", 1, 5*time.Second, nil, slog.Default()).Execute(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	got = nil
	json.Unmarshal(body, &got) //nolint:errcheck
	if v, ok := got["peer_distinguisher"]; !ok || v != "" || got["rib"] != "adj-rib-in-pre" {
		t.Errorf("global peer payload: peer_distinguisher %v (present %v), rib %v; want \"\", present, adj-rib-in-pre", v, ok, got["rib"])
	}

	var logs bytes.Buffer
	a := &LogAction{log: slog.New(slog.NewTextHandler(&logs, nil))}
	event.Route = ribRoute(types.LocRIB, "192.0.2.10", 0x0000fde8_00000001)
	if err := a.Execute(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"rib=loc-rib", "peer_distinguisher=65000:1", "peer=192.0.2.1"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log line %q has no %s", logs.String(), want)
		}
	}
}
