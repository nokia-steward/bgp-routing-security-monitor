package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/nokia/bgp-routing-security-monitor/internal/aspa/recommender"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
)

type WhatIfHandler struct {
	simulator   *whatif.Simulator
	recommender *recommender.Recommender
	aspaStore   *store.ASPAStore
}

func NewWhatIfHandler(sim *whatif.Simulator, rec *recommender.Recommender, aspaStore *store.ASPAStore) *WhatIfHandler {
	return &WhatIfHandler{simulator: sim, recommender: rec, aspaStore: aspaStore}
}

func (h *WhatIfHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/whatif/reject-invalid", h.rejectInvalid)
	mux.HandleFunc("/api/v1/whatif/aspa-enforce", h.aspaEnforce)
	mux.HandleFunc("/api/v1/aspa/recommend", h.aspaRecommend)
	mux.HandleFunc("/api/v1/aspa/record", h.aspaRecord)
}

func (h *WhatIfHandler) rejectInvalid(w http.ResponseWriter, r *http.Request) {
	opts, err := whatifOptsFromRequest(r)
	if err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}
	result, err := h.simulator.SimulateRejectInvalid(r.Context(), opts)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func (h *WhatIfHandler) aspaEnforce(w http.ResponseWriter, r *http.Request) {
	opts, err := whatifOptsFromRequest(r)
	if err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}
	result, err := h.simulator.SimulateASPAEnforce(r.Context(), opts)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func (h *WhatIfHandler) aspaRecommend(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := &recommender.RecommendOptions{FilterPeer: q.Get("peer")}
	if asnStr := q.Get("asn"); asnStr != "" {
		fmt.Sscan(asnStr, &opts.FilterCustomerASN) //nolint:errcheck
	}
	if minObs := q.Get("min_observations"); minObs != "" {
		fmt.Sscan(minObs, &opts.MinObservations) //nolint:errcheck
	}
	if topN := q.Get("top"); topN != "" {
		fmt.Sscan(topN, &opts.TopN) //nolint:errcheck
	}
	opts.IncludeAlreadyCovered = q.Get("include_existing") == "true"

	suggestions, err := h.recommender.Recommend(r.Context(), opts)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, suggestions)
}

func (h *WhatIfHandler) aspaRecord(w http.ResponseWriter, r *http.Request) {
	var asn uint32
	if _, err := fmt.Sscan(r.URL.Query().Get("asn"), &asn); err != nil || asn == 0 {
		httpError(w, fmt.Errorf("asn query parameter required"), http.StatusBadRequest)
		return
	}
	record := h.aspaStore.GetRecord(asn)
	providers := make([]uint32, 0)
	if record != nil {
		for p := range record.Providers {
			providers = append(providers, p)
		}
		sort.Slice(providers, func(i, j int) bool { return providers[i] < providers[j] })
	}
	writeJSON(w, map[string]any{"customer_asn": asn, "providers": providers})
}

// whatifOptsFromRequest reads the peer, afi, top and rib query parameters.
// rib is whatif.ParseRIBs's: absent, Adj-RIB-In pre-policy.
func whatifOptsFromRequest(r *http.Request) (*whatif.Options, error) {
	q := r.URL.Query()
	opts := &whatif.Options{FilterPeer: q.Get("peer"), FilterAFI: q.Get("afi")}
	fmt.Sscan(q.Get("top"), &opts.TopN) //nolint:errcheck
	ribs, err := whatif.ParseRIBs(strings.Join(q["rib"], ","))
	if err != nil {
		return nil, fmt.Errorf("invalid rib: %w", err)
	}
	opts.RIBs = ribs
	return opts, nil
}
