package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/flowspec"
)

func TestFlowspecHandler_ListEmpty(t *testing.T) {
	h := NewFlowspecHandler(nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flowspec/rules", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}

	var rules []FlowspecRuleResponse
	if err := json.NewDecoder(rr.Body).Decode(&rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("got %d rules, want 0", len(rules))
	}
}

func TestFlowspecHandler_ListRules(t *testing.T) {
	mgr, err := flowspec.NewManager(flowspec.ManagerConfig{
		DryRun:         true,
		MaxRules:       100,
		DefaultTTL:     time.Hour,
		DefaultAction:  flowspec.FlowspecActionDrop,
		ReaperInterval: time.Hour,
	}, slog.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	rule := &flowspec.FlowspecRule{
		Prefix:     netip.MustParsePrefix("192.0.2.0/24"),
		Action:     flowspec.FlowspecActionDrop,
		InsertedAt: time.Now(),
		TTL:        time.Hour,
		EventID:    "test-event",
		DryRun:     true,
	}
	rule.Key = rule.CanonicalKey()

	if err := mgr.Inject(context.Background(), rule); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	h := NewFlowspecHandler([]*flowspec.Manager{mgr})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/flowspec/rules", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rr.Code)
	}

	var rules []FlowspecRuleResponse
	if err := json.NewDecoder(rr.Body).Decode(&rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Key != "192.0.2.0/24|drop" {
		t.Errorf("key: got %q, want %q", rules[0].Key, "192.0.2.0/24|drop")
	}
	if rules[0].Action != "drop" {
		t.Errorf("action: got %q, want drop", rules[0].Action)
	}
	if !rules[0].DryRun {
		t.Error("dry_run: expected true")
	}
	if rules[0].TTLSeconds != 3600 {
		t.Errorf("ttl_seconds: got %d, want 3600", rules[0].TTLSeconds)
	}
}
