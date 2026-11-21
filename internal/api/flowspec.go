package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/flowspec"
)

const (
	fsRulesPrefix  = "/api/v1/flowspec/rules/"
	fsToggleSuffix = "/toggle-dryrun"
)

// FlowspecHandler serves the flowspec rules API endpoints.
type FlowspecHandler struct {
	managers []*flowspec.Manager
}

// NewFlowspecHandler creates a FlowspecHandler backed by the given managers.
func NewFlowspecHandler(managers []*flowspec.Manager) *FlowspecHandler {
	return &FlowspecHandler{managers: managers}
}

// RegisterRoutes registers the flowspec endpoints on mux.
func (h *FlowspecHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/flowspec/rules", h.handleList)
	mux.HandleFunc("POST /api/v1/flowspec/rules/", h.handleRuleOp)
}

// FlowspecRuleResponse is the JSON representation of a single active flowspec rule.
type FlowspecRuleResponse struct {
	Key        string    `json:"key"`
	Prefix     string    `json:"prefix"`
	OriginASN  uint32    `json:"origin_asn"`
	PeerAddr   string    `json:"peer_addr"`
	Action     string    `json:"action"`
	InsertedAt time.Time `json:"inserted_at"`
	TTLSeconds int64     `json:"ttl_seconds"`
	ExpiresAt  time.Time `json:"expires_at"`
	DryRun     bool      `json:"dry_run"`
	EventID    string    `json:"event_id"`
}

func fsRuleToResponse(rule *flowspec.FlowspecRule) FlowspecRuleResponse {
	return FlowspecRuleResponse{
		Key:        rule.CanonicalKey(),
		Prefix:     rule.Prefix.String(),
		OriginASN:  rule.OriginASN,
		PeerAddr:   rule.PeerAddr.String(),
		Action:     string(rule.Action),
		InsertedAt: rule.InsertedAt,
		TTLSeconds: int64(rule.TTL.Seconds()),
		ExpiresAt:  rule.InsertedAt.Add(rule.TTL),
		DryRun:     rule.DryRun,
		EventID:    rule.EventID,
	}
}

func (h *FlowspecHandler) handleList(w http.ResponseWriter, r *http.Request) {
	resp := make([]FlowspecRuleResponse, 0)
	for _, mgr := range h.managers {
		for _, rule := range mgr.ActiveRules() {
			resp = append(resp, fsRuleToResponse(rule))
		}
	}
	writeJSON(w, resp)
}

// handleRuleOp handles POST /api/v1/flowspec/rules/<encoded-key>/toggle-dryrun.
func (h *FlowspecHandler) handleRuleOp(w http.ResponseWriter, r *http.Request) {
	rawPath := r.URL.RawPath
	if rawPath == "" {
		rawPath = r.URL.Path
	}

	if !strings.HasSuffix(rawPath, fsToggleSuffix) {
		httpError(w, fmt.Errorf("unknown operation"), http.StatusNotFound)
		return
	}

	inner := strings.TrimPrefix(rawPath, fsRulesPrefix)
	inner = strings.TrimSuffix(inner, fsToggleSuffix)

	key, err := url.PathUnescape(inner)
	if err != nil {
		httpError(w, fmt.Errorf("invalid key encoding: %w", err), http.StatusBadRequest)
		return
	}

	// Find the manager that owns this rule.
	var targetMgr *flowspec.Manager
	for _, mgr := range h.managers {
		if mgr.GetRule(key) != nil {
			targetMgr = mgr
			break
		}
	}
	if targetMgr == nil {
		httpError(w, fmt.Errorf("rule not found: %s", key), http.StatusNotFound)
		return
	}

	rule := targetMgr.GetRule(key)
	if rule == nil {
		httpError(w, fmt.Errorf("rule not found: %s", key), http.StatusNotFound)
		return
	}

	if rule.DryRun {
		// dry-run → live: update flag then inject into GoBGP.
		updated, ok := targetMgr.SetDryRun(key, false)
		if !ok {
			httpError(w, fmt.Errorf("rule disappeared: %s", key), http.StatusNotFound)
			return
		}
		if err := targetMgr.InjectLive(r.Context(), updated); err != nil {
			targetMgr.SetDryRun(key, true) // revert on failure
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, fsRuleToResponse(updated))
	} else {
		// live → dry-run: withdraw from GoBGP first (while rule.DryRun is
		// still false), then mark the registry entry as dry-run so the rule
		// remains visible and is reversible.
		if err := targetMgr.Withdraw(r.Context(), key); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		updated, ok := targetMgr.SetDryRun(key, true)
		if !ok {
			httpError(w, fmt.Errorf("rule disappeared: %s", key), http.StatusNotFound)
			return
		}
		writeJSON(w, fsRuleToResponse(updated))
	}
}
