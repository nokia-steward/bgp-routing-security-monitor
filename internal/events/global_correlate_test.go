package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// fakeGlobalProvider is an external.GlobalVisibilityProvider stand-in so the
// event tests never touch the network.
//
// It returns summary verbatim, so a test that wants to model a cache hit sets
// GlobalOriginSummary.CacheHit on it. Unset means a live fetch, which is what
// these tests want: none of them is about cache accounting.
type fakeGlobalProvider struct {
	summary external.GlobalOriginSummary
	err     error
	delay   time.Duration

	calls       atomic.Int64
	lastMaxAge  atomic.Int64
	maxObserved atomic.Int64
	inFlight    atomic.Int64
}

func (f *fakeGlobalProvider) Name() string { return "fake" }

func (f *fakeGlobalProvider) GlobalOrigins(
	ctx context.Context,
	_ netip.Prefix,
	maxAge time.Duration,
) (external.GlobalOriginSummary, error) {
	f.calls.Add(1)
	f.lastMaxAge.Store(int64(maxAge))

	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		peak := f.maxObserved.Load()
		if n <= peak || f.maxObserved.CompareAndSwap(peak, n) {
			break
		}
	}

	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return external.GlobalOriginSummary{}, ctx.Err()
		}
	}
	if f.err != nil {
		return external.GlobalOriginSummary{}, f.err
	}
	return f.summary, nil
}

func testRoute(t *testing.T, prefix string, asPath ...uint32) *types.Route {
	t.Helper()
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", prefix, err)
	}
	return &types.Route{
		Prefix:   p,
		PeerAddr: netip.MustParseAddr("192.0.2.1"),
		PeerASN:  64500,
		ASPath:   asPath,
	}
}

// ─── TestGlobalCorrelateActionEnrich ───

func TestGlobalCorrelateActionEnrich(t *testing.T) {
	t.Run("attaches a match result", func(t *testing.T) {
		p := &fakeGlobalProvider{summary: external.GlobalOriginSummary{
			Origins:        []external.GlobalOriginObservation{{ASN: 64511, CollectorCount: 20}},
			CollectorCount: 20,
		}}
		a := newGlobalCorrelateAction(p, 60*time.Second, slog.Default())

		event := Event{ID: "e1", Route: testRoute(t, "203.0.113.0/24", 64500, 64511)}
		a.Enrich(context.Background(), &event)

		if event.GlobalVisibility == nil {
			t.Fatal("GlobalVisibility is nil, want an annotation")
		}
		if got := event.GlobalVisibility.Consensus; got != external.ConsensusMatch {
			t.Errorf("Consensus = %q, want %q", got, external.ConsensusMatch)
		}
		if got := event.GlobalVisibility.LocalOrigin; got != 64511 {
			t.Errorf("LocalOrigin = %d, want 64511 (the route's origin ASN)", got)
		}
	})

	t.Run("attaches a divergent result", func(t *testing.T) {
		p := &fakeGlobalProvider{summary: external.GlobalOriginSummary{
			Origins:        []external.GlobalOriginObservation{{ASN: 65000, CollectorCount: 30}},
			CollectorCount: 30,
		}}
		a := newGlobalCorrelateAction(p, 0, slog.Default())

		event := Event{ID: "e2", Route: testRoute(t, "203.0.113.0/24", 64500, 64511)}
		a.Enrich(context.Background(), &event)

		if got := event.GlobalVisibility.Consensus; got != external.ConsensusDivergent {
			t.Errorf("Consensus = %q, want %q", got, external.ConsensusDivergent)
		}
	})

	// A provider failure must still yield an annotation, so downstream
	// actions always have something to report.
	t.Run("fails open on a provider error", func(t *testing.T) {
		p := &fakeGlobalProvider{err: errors.New("connection refused")}
		a := newGlobalCorrelateAction(p, 0, slog.Default())

		event := Event{ID: "e3", Route: testRoute(t, "203.0.113.0/24", 64500, 64511)}
		a.Enrich(context.Background(), &event)

		if event.GlobalVisibility == nil {
			t.Fatal("GlobalVisibility is nil, want an inconclusive annotation")
		}
		if got := event.GlobalVisibility.Consensus; got != external.ConsensusInconclusive {
			t.Errorf("Consensus = %q, want %q", got, external.ConsensusInconclusive)
		}
		if event.GlobalVisibility.Error == "" {
			t.Error("Error is empty, want the provider failure recorded")
		}
	})

	// Cache-unhealthy events carry no route, so there is no prefix to
	// correlate and nothing should be attached.
	t.Run("skips events without a route", func(t *testing.T) {
		p := &fakeGlobalProvider{}
		a := newGlobalCorrelateAction(p, 0, slog.Default())

		event := Event{ID: "e4", Type: EventTypeCacheUnhealthy, CacheName: "rpki1"}
		a.Enrich(context.Background(), &event)

		if event.GlobalVisibility != nil {
			t.Errorf("GlobalVisibility = %+v, want nil", event.GlobalVisibility)
		}
		if p.calls.Load() != 0 {
			t.Errorf("provider calls = %d, want 0", p.calls.Load())
		}
	})

	t.Run("passes the configured cache TTL as maxAge", func(t *testing.T) {
		p := &fakeGlobalProvider{}
		a := newGlobalCorrelateAction(p, 90*time.Second, slog.Default())

		event := Event{ID: "e5", Route: testRoute(t, "203.0.113.0/24", 64500, 64511)}
		a.Enrich(context.Background(), &event)

		if got := time.Duration(p.lastMaxAge.Load()); got != 90*time.Second {
			t.Errorf("provider maxAge = %v, want 90s", got)
		}
	})

	// Execute is a no-op: Enrich already did the work.
	t.Run("Execute is a no-op", func(t *testing.T) {
		a := newGlobalCorrelateAction(&fakeGlobalProvider{}, 0, slog.Default())
		if err := a.Execute(context.Background(), Event{}); err != nil {
			t.Errorf("Execute: %v", err)
		}
		if a.Name() != "global-correlate" {
			t.Errorf("Name() = %q, want global-correlate", a.Name())
		}
	})
}

// A burst of events must not exceed the action's concurrency bound.
func TestGlobalCorrelateActionBoundsConcurrency(t *testing.T) {
	p := &fakeGlobalProvider{delay: 20 * time.Millisecond}
	a := newGlobalCorrelateAction(p, 0, slog.Default())

	done := make(chan struct{})
	for i := range 20 {
		go func() {
			defer func() { done <- struct{}{} }()
			event := Event{ID: "burst", Route: testRoute(t, "203.0.113.0/24", 64500, uint32(64511+i))}
			a.Enrich(context.Background(), &event)
		}()
	}
	for range 20 {
		<-done
	}

	if peak := p.maxObserved.Load(); peak > defaultCorrelateConcurrency {
		t.Errorf("peak concurrent provider calls = %d, want <= %d", peak, defaultCorrelateConcurrency)
	}
}

// ─── TestBuildEngineGlobalCorrelate ───

func TestBuildEngineGlobalCorrelate(t *testing.T) {
	baseRule := func(actions ...config.ActionConfig) config.EventsConfig {
		return config.EventsConfig{Rules: []config.RuleConfig{{
			Name: "correlate-invalid",
			Trigger: config.TriggerConfig{
				Type:     "posture_change",
				Postures: []string{"origin-invalid", "path-suspect"},
			},
			Actions: actions,
		}}}
	}

	t.Run("builds with a provider", func(t *testing.T) {
		cfg := baseRule(
			config.ActionConfig{Type: "global-correlate", CacheTTL: "30s"},
			config.ActionConfig{Type: "log", Level: "warn"},
		)
		eng, _, err := BuildEngine(cfg, slog.Default(),
			WithGlobalVisibility(&fakeGlobalProvider{}, 60*time.Second))
		if err != nil {
			t.Fatalf("BuildEngine: %v", err)
		}
		rule := eng.rules[0]
		// The correlate action is partitioned into Enrichers so it runs
		// before the log action rather than racing it.
		if len(rule.Enrichers) != 1 {
			t.Errorf("Enrichers = %d, want 1", len(rule.Enrichers))
		}
		if len(rule.Actions) != 1 {
			t.Errorf("Actions = %d, want 1 (the log action)", len(rule.Actions))
		}
	})

	// Without a provider the config is rejected outright, rather than
	// silently emitting Inconclusive annotations forever.
	t.Run("rejected without a provider", func(t *testing.T) {
		cfg := baseRule(config.ActionConfig{Type: "global-correlate"})
		if _, _, err := BuildEngine(cfg, slog.Default()); err == nil {
			t.Fatal("BuildEngine: want an error when no provider is configured")
		}
	})

	t.Run("rejects an unparseable cache_ttl", func(t *testing.T) {
		cfg := baseRule(config.ActionConfig{Type: "global-correlate", CacheTTL: "not-a-duration"})
		_, _, err := BuildEngine(cfg, slog.Default(),
			WithGlobalVisibility(&fakeGlobalProvider{}, 60*time.Second))
		if err == nil {
			t.Fatal("BuildEngine: want an error for an invalid cache_ttl")
		}
	})

	// An empty cache_ttl inherits external.ripestat.cache-ttl.
	t.Run("inherits the default cache TTL", func(t *testing.T) {
		cfg := baseRule(config.ActionConfig{Type: "global-correlate"})
		p := &fakeGlobalProvider{}
		eng, _, err := BuildEngine(cfg, slog.Default(), WithGlobalVisibility(p, 45*time.Second))
		if err != nil {
			t.Fatalf("BuildEngine: %v", err)
		}
		action, ok := eng.rules[0].Enrichers[0].(*GlobalCorrelateAction)
		if !ok {
			t.Fatalf("Enrichers[0] is %T, want *GlobalCorrelateAction", eng.rules[0].Enrichers[0])
		}
		if action.cacheTTL != 45*time.Second {
			t.Errorf("cacheTTL = %v, want 45s", action.cacheTTL)
		}
	})

	// Existing configs must build unchanged with no options passed.
	t.Run("existing action types unaffected", func(t *testing.T) {
		cfg := baseRule(config.ActionConfig{Type: "log", Level: "warn"})
		eng, _, err := BuildEngine(cfg, slog.Default())
		if err != nil {
			t.Fatalf("BuildEngine: %v", err)
		}
		if len(eng.rules[0].Enrichers) != 0 {
			t.Errorf("Enrichers = %d, want 0", len(eng.rules[0].Enrichers))
		}
		if len(eng.rules[0].Actions) != 1 {
			t.Errorf("Actions = %d, want 1", len(eng.rules[0].Actions))
		}
	})
}

// ─── TestEnrichmentReachesWebhook ───

// The end-to-end point of the feature: a rule combining global-correlate with
// a webhook must deliver the annotation in the webhook payload. This is what
// the enricher/action ordering exists for.
func TestEnrichmentReachesWebhook(t *testing.T) {
	type payload struct {
		Prefix           string                           `json:"prefix"`
		NewPosture       string                           `json:"new_posture"`
		GlobalVisibility *external.GlobalVisibilityResult `json:"global_visibility"`
	}

	received := make(chan payload, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("decode webhook body: %v", err)
		}
		received <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &fakeGlobalProvider{summary: external.GlobalOriginSummary{
		Origins:        []external.GlobalOriginObservation{{ASN: 65000, CollectorCount: 30}},
		CollectorCount: 30,
	}}

	cfg := config.EventsConfig{Rules: []config.RuleConfig{{
		Name: "correlate-and-notify",
		Trigger: config.TriggerConfig{
			Type:     "posture_change",
			Postures: []string{"origin-invalid"},
		},
		Actions: []config.ActionConfig{
			{Type: "global-correlate", CacheTTL: "60s"},
			{Type: "webhook", URL: srv.URL, MaxAttempts: 1, Timeout: "2s"},
		},
	}}}

	eng, _, err := BuildEngine(cfg, slog.Default(), WithGlobalVisibility(provider, 60*time.Second))
	if err != nil {
		t.Fatalf("BuildEngine: %v", err)
	}

	event := Event{
		ID:         "e-webhook",
		Timestamp:  time.Now(),
		Type:       EventTypePostureChange,
		Route:      testRoute(t, "203.0.113.0/24", 64500, 64511),
		OldPosture: types.PostureSecured,
		NewPosture: types.PostureOriginInvalid,
	}
	eng.rules[0].Evaluate(context.Background(), event)

	select {
	case got := <-received:
		if got.GlobalVisibility == nil {
			t.Fatal("webhook payload has no global_visibility field")
		}
		if got.GlobalVisibility.Consensus != external.ConsensusDivergent {
			t.Errorf("consensus = %q, want %q", got.GlobalVisibility.Consensus, external.ConsensusDivergent)
		}
		if got.GlobalVisibility.Source != "fake" {
			t.Errorf("source = %q, want fake", got.GlobalVisibility.Source)
		}
		if got.Prefix != "203.0.113.0/24" {
			t.Errorf("prefix = %q, want 203.0.113.0/24", got.Prefix)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook was not delivered")
	}

	// The engine's own copy of the event is untouched: enrichment mutates
	// only the per-rule copy, so one rule cannot leak into another.
	if event.GlobalVisibility != nil {
		t.Error("enrichment leaked into the caller's event")
	}
}

// A rule without a global-correlate action must produce a payload with no
// global_visibility key at all, so existing webhook consumers see no change.
func TestWebhookPayloadOmitsGlobalVisibilityByDefault(t *testing.T) {
	a := newWebhookAction("http://example.invalid", "", "r", 1, time.Second, nil, slog.Default())
	body, err := json.Marshal(a.buildPayload(Event{
		ID:    "e-plain",
		Route: testRoute(t, "203.0.113.0/24", 64500, 64511),
	}))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, present := decoded["global_visibility"]; present {
		t.Errorf("global_visibility present in payload without a correlate action: %s", body)
	}
}
