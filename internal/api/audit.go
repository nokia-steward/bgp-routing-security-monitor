package api

import (
	"fmt"
	"net/http"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/audit"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// AuditHandler serves the router security posture audit endpoint.
type AuditHandler struct {
	table *routetable.Table
}

// NewAuditHandler creates a new AuditHandler backed by the given route table.
func NewAuditHandler(table *routetable.Table) *AuditHandler {
	return &AuditHandler{table: table}
}

// RegisterRoutes registers the audit endpoint on the given mux.
func (h *AuditHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/audit", h.handleAudit)
}

func (h *AuditHandler) handleAudit(w http.ResponseWriter, r *http.Request) {
	routerID := r.URL.Query().Get("router")
	if routerID == "" {
		httpError(w, fmt.Errorf("router query parameter required"), http.StatusBadRequest)
		return
	}
	// One RIB: Adj-RIB-In pre-policy unless the rib parameter names
	// another (types.ParseRIBType, so pre-policy and post-policy work too).
	rib := types.AdjRIBInPre
	if v := r.URL.Query().Get("rib"); v != "" {
		var err error
		if rib, err = types.ParseRIBType(v); err != nil {
			httpError(w, err, http.StatusBadRequest)
			return
		}
	}
	report := audit.Analyze(routerID, rib, h.table.AllOfRIB(rib))
	writeJSON(w, report)
}
