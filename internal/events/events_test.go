package events

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// ─── test helpers ───

type alwaysTrigger struct{}

func (t *alwaysTrigger) Matches(_ Event) bool { return true }

type countAction struct {
	mu sync.Mutex
	n  int
	wg *sync.WaitGroup
}

func (a *countAction) Name() string { return "count" }

func (a *countAction) Execute(_ context.Context, _ Event) error {
	a.mu.Lock()
	a.n++
	a.mu.Unlock()
	if a.wg != nil {
		a.wg.Done()
	}
	return nil
}

func (a *countAction) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

func newRoute(prefix string) *types.Route {
	return &types.Route{
		Prefix:   netip.MustParsePrefix(prefix),
		PeerAddr: netip.MustParseAddr("192.0.2.1"),
	}
}

// ─── TestPostureTrigger ───

func TestPostureTrigger(t *testing.T) {
	trigger := &PostureTrigger{
		Postures: []types.SecurityPosture{
			types.PostureOriginInvalid,
			types.PosturePathSuspect,
		},
	}

	tests := []struct {
		name    string
		posture types.SecurityPosture
		want    bool
	}{
		{"origin-invalid fires", types.PostureOriginInvalid, true},
		{"path-suspect fires", types.PosturePathSuspect, true},
		{"secured does not fire", types.PostureSecured, false},
		{"unverified does not fire", types.PostureUnverified, false},
		{"origin-only does not fire", types.PostureOriginOnly, false},
		{"path-only does not fire", types.PosturePathOnly, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := Event{NewPosture: tc.posture}
			if got := trigger.Matches(event); got != tc.want {
				t.Errorf("Matches() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── TestPostureChangeTrigger ───

func TestPostureChangeTrigger(t *testing.T) {
	trigger := &PostureChangeTrigger{
		Postures: []types.SecurityPosture{types.PosturePathSuspect},
	}

	tests := []struct {
		name       string
		oldPosture types.SecurityPosture
		newPosture types.SecurityPosture
		want       bool
	}{
		{
			name:       "transition to path-suspect fires",
			oldPosture: types.PostureUnverified,
			newPosture: types.PosturePathSuspect,
			want:       true,
		},
		{
			name:       "steady-state path-suspect does not fire",
			oldPosture: types.PosturePathSuspect,
			newPosture: types.PosturePathSuspect,
			want:       false,
		},
		{
			name:       "transition away from path-suspect does not fire",
			oldPosture: types.PosturePathSuspect,
			newPosture: types.PostureSecured,
			want:       false,
		},
		{
			name:       "new route (no old posture) transitioning to matching posture fires",
			oldPosture: "",
			newPosture: types.PosturePathSuspect,
			want:       true,
		},
		{
			name:       "transition to non-matching posture does not fire",
			oldPosture: types.PostureUnverified,
			newPosture: types.PostureSecured,
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := Event{OldPosture: tc.oldPosture, NewPosture: tc.newPosture}
			if got := trigger.Matches(event); got != tc.want {
				t.Errorf("Matches() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── TestASNTrigger ───

func TestASNTrigger(t *testing.T) {
	routeWith := func(path []uint32) *types.Route {
		r := newRoute("10.0.0.0/24")
		r.ASPath = path
		return r
	}

	t.Run("origin mode", func(t *testing.T) {
		trigger := &ASNTrigger{ASNs: []uint32{64501, 64502}, Match: "origin"}
		tests := []struct {
			name  string
			event Event
			want  bool
		}{
			{"origin ASN matches", Event{Route: routeWith([]uint32{65000, 64501})}, true},
			{"origin ASN in list", Event{Route: routeWith([]uint32{65000, 64502})}, true},
			{"origin ASN not in list", Event{Route: routeWith([]uint32{65000, 64503})}, false},
			{"ASN in middle but not origin", Event{Route: routeWith([]uint32{64501, 65000})}, false},
			{"empty AS path", Event{Route: routeWith(nil)}, false},
			{"nil route", Event{Route: nil}, false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := trigger.Matches(tc.event); got != tc.want {
					t.Errorf("Matches() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("path mode", func(t *testing.T) {
		trigger := &ASNTrigger{ASNs: []uint32{64501}, Match: "path"}
		tests := []struct {
			name  string
			event Event
			want  bool
		}{
			{"ASN at origin", Event{Route: routeWith([]uint32{65000, 64501})}, true},
			{"ASN in middle", Event{Route: routeWith([]uint32{64501, 65000})}, true},
			{"ASN not in path", Event{Route: routeWith([]uint32{65000, 65001})}, false},
			{"nil route", Event{Route: nil}, false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := trigger.Matches(tc.event); got != tc.want {
					t.Errorf("Matches() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("default match is origin", func(t *testing.T) {
		trigger := &ASNTrigger{ASNs: []uint32{64501}, Match: ""}
		r := routeWith([]uint32{64501, 65000})
		if trigger.Matches(Event{Route: r}) {
			t.Error("expected no match: 64501 is not the origin ASN")
		}
		r2 := routeWith([]uint32{65000, 64501})
		if !trigger.Matches(Event{Route: r2}) {
			t.Error("expected match: 64501 is the origin ASN")
		}
	})
}

// ─── TestBuildEngineASN ───

func TestBuildEngineASN(t *testing.T) {
	t.Run("origin mode built correctly", func(t *testing.T) {
		cfg := config.EventsConfig{Rules: []config.RuleConfig{{
			Name: "my-asn-origin",
			Trigger: config.TriggerConfig{
				Type: "asn",
				ASNs: []uint32{64501},
			},
			Actions: []config.ActionConfig{{Type: "log"}},
		}}}
		eng, _, err := BuildEngine(cfg, slog.Default())
		if err != nil {
			t.Fatalf("BuildEngine: %v", err)
		}
		tr, ok := eng.rules[0].Trigger.(*ASNTrigger)
		if !ok {
			t.Fatalf("expected *ASNTrigger, got %T", eng.rules[0].Trigger)
		}
		if tr.Match != "origin" {
			t.Errorf("expected default match \"origin\", got %q", tr.Match)
		}
	})

	t.Run("path mode built correctly", func(t *testing.T) {
		cfg := config.EventsConfig{Rules: []config.RuleConfig{{
			Name: "my-asn-path",
			Trigger: config.TriggerConfig{
				Type:     "asn",
				ASNs:     []uint32{64501, 64502},
				ASNMatch: "path",
			},
			Actions: []config.ActionConfig{{Type: "log"}},
		}}}
		eng, _, err := BuildEngine(cfg, slog.Default())
		if err != nil {
			t.Fatalf("BuildEngine: %v", err)
		}
		tr, ok := eng.rules[0].Trigger.(*ASNTrigger)
		if !ok {
			t.Fatalf("expected *ASNTrigger, got %T", eng.rules[0].Trigger)
		}
		if tr.Match != "path" {
			t.Errorf("expected match \"path\", got %q", tr.Match)
		}
		if len(tr.ASNs) != 2 {
			t.Errorf("expected 2 ASNs, got %d", len(tr.ASNs))
		}
	})

	t.Run("empty asns rejected", func(t *testing.T) {
		cfg := config.EventsConfig{Rules: []config.RuleConfig{{
			Name:    "bad",
			Trigger: config.TriggerConfig{Type: "asn"},
			Actions: []config.ActionConfig{{Type: "log"}},
		}}}
		if _, _, err := BuildEngine(cfg, slog.Default()); err == nil {
			t.Error("expected error for empty asns, got nil")
		}
	})

	t.Run("invalid asn_match rejected", func(t *testing.T) {
		cfg := config.EventsConfig{Rules: []config.RuleConfig{{
			Name: "bad",
			Trigger: config.TriggerConfig{
				Type:     "asn",
				ASNs:     []uint32{64501},
				ASNMatch: "invalid",
			},
			Actions: []config.ActionConfig{{Type: "log"}},
		}}}
		if _, _, err := BuildEngine(cfg, slog.Default()); err == nil {
			t.Error("expected error for invalid asn_match, got nil")
		}
	})
}

// ─── TestProtectedASNTrigger ───

func TestProtectedASNTrigger(t *testing.T) {
	vrp := func(asn uint32) types.VRP {
		return types.VRP{
			Prefix:    netip.MustParsePrefix("10.0.0.0/24"),
			ASN:       asn,
			MaxLength: 24,
		}
	}

	routeInvalid := func(matchedVRPs []types.VRP) *types.Route {
		r := newRoute("10.0.0.0/24")
		r.ROV = types.ROVResult{State: types.ROVInvalid, MatchedVRPs: matchedVRPs}
		return r
	}

	trigger := &ProtectedASNTrigger{ASNs: []uint32{3215}}

	tests := []struct {
		name  string
		event Event
		want  bool
	}{
		{
			name: "protected ASN in MatchedVRPs fires",
			event: Event{
				Route:      routeInvalid([]types.VRP{vrp(3215)}),
				NewPosture: types.PostureOriginInvalid,
			},
			want: true,
		},
		{
			name: "protected ASN not in MatchedVRPs does not fire",
			event: Event{
				Route:      routeInvalid([]types.VRP{vrp(64999)}),
				NewPosture: types.PostureOriginInvalid,
			},
			want: false,
		},
		{
			name: "multiple VRPs, one matches",
			event: Event{
				Route:      routeInvalid([]types.VRP{vrp(64999), vrp(3215)}),
				NewPosture: types.PostureOriginInvalid,
			},
			want: true,
		},
		{
			name: "route is valid, not a hijack",
			event: Event{
				Route:      newRoute("10.0.0.0/24"),
				NewPosture: types.PostureSecured,
			},
			want: false,
		},
		{
			name: "route is unverified (no VRPs), not a hijack",
			event: Event{
				Route:      newRoute("10.0.0.0/24"),
				NewPosture: types.PostureUnverified,
			},
			want: false,
		},
		{
			name:  "nil route does not fire",
			event: Event{Route: nil},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := trigger.Matches(tc.event); got != tc.want {
				t.Errorf("Matches() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── TestBuildEngineProtectedASN ───

func TestBuildEngineProtectedASN(t *testing.T) {
	t.Run("built correctly from config", func(t *testing.T) {
		cfg := config.EventsConfig{Rules: []config.RuleConfig{{
			Name: "my-prefixes-hijacked",
			Trigger: config.TriggerConfig{
				Type: "protected_asn",
				ASNs: []uint32{3215, 64501},
			},
			Actions: []config.ActionConfig{{Type: "log"}},
		}}}
		eng, _, err := BuildEngine(cfg, slog.Default())
		if err != nil {
			t.Fatalf("BuildEngine: %v", err)
		}
		tr, ok := eng.rules[0].Trigger.(*ProtectedASNTrigger)
		if !ok {
			t.Fatalf("expected *ProtectedASNTrigger, got %T", eng.rules[0].Trigger)
		}
		if len(tr.ASNs) != 2 {
			t.Errorf("expected 2 ASNs, got %d", len(tr.ASNs))
		}
	})

	t.Run("empty asns rejected", func(t *testing.T) {
		cfg := config.EventsConfig{Rules: []config.RuleConfig{{
			Name:    "bad",
			Trigger: config.TriggerConfig{Type: "protected_asn"},
			Actions: []config.ActionConfig{{Type: "log"}},
		}}}
		if _, _, err := BuildEngine(cfg, slog.Default()); err == nil {
			t.Error("expected error for empty asns, got nil")
		}
	})
}

// ─── TestCooldown ───

func TestCooldown(t *testing.T) {
	action := &countAction{}
	rule := &Rule{
		Name:        "test-cooldown",
		Trigger:     &alwaysTrigger{},
		Actions:     []Action{action},
		Cooldown:    100 * time.Millisecond,
		log:         slog.Default(),
		cooldownMap: make(map[string]time.Time),
	}

	event := Event{
		ID:         NewID(),
		Timestamp:  time.Now(),
		Type:       EventTypePostureChange,
		Route:      newRoute("10.0.0.0/8"),
		NewPosture: types.PostureOriginInvalid,
	}
	ctx := context.Background()

	// First evaluation: should fire.
	rule.Evaluate(ctx, event)
	if n := action.count(); n != 1 {
		t.Fatalf("expected 1 after first fire, got %d", n)
	}

	// Second evaluation within cooldown: should be suppressed.
	rule.Evaluate(ctx, event)
	if n := action.count(); n != 1 {
		t.Errorf("expected count still 1 within cooldown, got %d", n)
	}

	// After cooldown expires, should fire again.
	time.Sleep(150 * time.Millisecond)
	rule.Evaluate(ctx, event)
	if n := action.count(); n != 2 {
		t.Errorf("expected 2 after cooldown expired, got %d", n)
	}
}

// ─── TestEngine_Run ───

func TestEngine_Run(t *testing.T) {
	const numEvents = 5
	var wg sync.WaitGroup
	wg.Add(numEvents)

	action := &countAction{wg: &wg}
	rule := &Rule{
		Name:        "count-all",
		Trigger:     &alwaysTrigger{},
		Actions:     []Action{action},
		log:         slog.Default(),
		cooldownMap: make(map[string]time.Time),
	}
	engine := NewEngine([]*Rule{rule}, slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go engine.Run(ctx, nil)

	for i := 0; i < numEvents; i++ {
		engine.Emit(Event{
			ID:        NewID(),
			Timestamp: time.Now(),
			Type:      EventTypeNewRoute,
			Route:     newRoute("10.0.0.0/8"),
		})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("timed out: only %d of %d events processed", action.count(), numEvents)
	}

	if n := action.count(); n != numEvents {
		t.Errorf("expected %d events processed, got %d", numEvents, n)
	}
}

// ─── TestBuildEngine ───

func TestBuildEngine(t *testing.T) {
	cfg := config.EventsConfig{
		Rules: []config.RuleConfig{
			{
				Name: "alert-origin-invalid",
				Trigger: config.TriggerConfig{
					Type:     "posture",
					Postures: []string{"origin-invalid"},
				},
				Cooldown: "60s",
				Actions:  []config.ActionConfig{{Type: "log", Level: "warn"}},
			},
			{
				Name: "alert-path-suspect-transition",
				Trigger: config.TriggerConfig{
					Type:     "posture_change",
					Postures: []string{"path-suspect"},
				},
				Cooldown: "300s",
				Actions:  []config.ActionConfig{{Type: "log", Level: "warn"}},
			},
		},
	}

	eng, _, err := BuildEngine(cfg, slog.Default())
	if err != nil {
		t.Fatalf("BuildEngine: %v", err)
	}
	if len(eng.rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(eng.rules))
	}

	if _, ok := eng.rules[0].Trigger.(*PostureTrigger); !ok {
		t.Errorf("rule 0: expected *PostureTrigger, got %T", eng.rules[0].Trigger)
	}
	if _, ok := eng.rules[1].Trigger.(*PostureChangeTrigger); !ok {
		t.Errorf("rule 1: expected *PostureChangeTrigger, got %T", eng.rules[1].Trigger)
	}

	if want := 60 * time.Second; eng.rules[0].Cooldown != want {
		t.Errorf("rule 0 cooldown: got %v, want %v", eng.rules[0].Cooldown, want)
	}
	if want := 300 * time.Second; eng.rules[1].Cooldown != want {
		t.Errorf("rule 1 cooldown: got %v, want %v", eng.rules[1].Cooldown, want)
	}

	// Verify that an invalid trigger type is rejected.
	bad := config.EventsConfig{
		Rules: []config.RuleConfig{
			{
				Name:    "bad",
				Trigger: config.TriggerConfig{Type: "unknown"},
				Actions: []config.ActionConfig{{Type: "log"}},
			},
		},
	}
	if _, _, err := BuildEngine(bad, slog.Default()); err == nil {
		t.Error("expected error for unknown trigger type, got nil")
	}
}
