// Package recommender analyses Adj-RIB-In routes observed via BMP and infers
// customer-provider relationships from AS_PATHs, producing ASPA object suggestions.
package recommender

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

type Recommender struct {
	table     *routetable.Table
	aspaStore *store.ASPAStore
}

func NewRecommender(table *routetable.Table, aspaStore *store.ASPAStore) *Recommender {
	return &Recommender{table: table, aspaStore: aspaStore}
}

type ASPASuggestion struct {
	CustomerASN        uint32               `json:"customer_asn"`
	SuggestedProviders []ProviderSuggestion `json:"suggested_providers"`
	AlreadyHasASPA     bool                 `json:"already_has_aspa"`
	ExistingProviders  []uint32             `json:"existing_providers,omitempty"`
	ObservationCount   int                  `json:"observation_count"`
	Confidence         int                  `json:"confidence"`
}

type ProviderSuggestion struct {
	ProviderASN    uint32 `json:"provider_asn"`
	ObservedCount  int    `json:"observed_count"`
	AlreadyCovered bool   `json:"already_covered"`
}

type RecommendOptions struct {
	FilterPeer            string
	FilterCustomerASN     uint32
	MinObservations       int
	TopN                  int
	IncludeAlreadyCovered bool
}

func defaultOpts(o *RecommendOptions) *RecommendOptions {
	if o == nil {
		o = &RecommendOptions{}
	}
	if o.MinObservations == 0 {
		o.MinObservations = 1
	}
	return o
}

func (r *Recommender) Recommend(ctx context.Context, opts *RecommendOptions) ([]ASPASuggestion, error) {
	opts = defaultOpts(opts)

	// Adj-RIB-In pre-policy only, not the default view: relationships are
	// inferred from paths as neighbors sent them. A Loc-RIB path is not
	// one: FRR 10.2 puts the router's own AS first, and a path learned
	// over iBGP starts at a border router's neighbor.
	filter := routetable.Filter{RIBs: types.RIBSetOf(types.AdjRIBInPre)}
	if opts.FilterPeer != "" {
		if _, err := netip.ParseAddr(opts.FilterPeer); err != nil {
			return nil, fmt.Errorf("recommender: invalid peer address %q: %w", opts.FilterPeer, err)
		}
		filter.PeerAddr = opts.FilterPeer
	}

	routes, err := r.table.ListRoutes(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("recommender: fetch routes: %w", err)
	}

	// relationship[customerASN][providerASN] = observation count
	relationship := make(map[uint32]map[uint32]int)

	for i := range routes {
		route := &routes[i]
		path := route.ASPath
		if len(path) < 2 {
			continue
		}

		// AS_PATH on wire: path[0] = neighbor (closest), path[len-1] = origin.
		// path[i] (closer to origin) = customer, path[i-1] (closer to us) = provider.
		for j := len(path) - 1; j > 0; j-- {
			customerASN := path[j]
			providerASN := path[j-1]
			if customerASN == 0 || providerASN == 0 {
				continue
			}
			if opts.FilterCustomerASN != 0 && customerASN != opts.FilterCustomerASN {
				continue
			}
			if relationship[customerASN] == nil {
				relationship[customerASN] = make(map[uint32]int)
			}
			relationship[customerASN][providerASN]++
		}
	}

	suggestions := make([]ASPASuggestion, 0, len(relationship))

	for customerASN, providers := range relationship {
		existingRecord := r.aspaStore.GetRecord(customerASN)

		s := ASPASuggestion{
			CustomerASN:    customerASN,
			AlreadyHasASPA: existingRecord != nil,
		}

		if existingRecord != nil {
			for p := range existingRecord.Providers {
				s.ExistingProviders = append(s.ExistingProviders, p)
			}
			sort.Slice(s.ExistingProviders, func(i, j int) bool {
				return s.ExistingProviders[i] < s.ExistingProviders[j]
			})
		}

		allCovered := true
		for providerASN, count := range providers {
			if count < opts.MinObservations {
				continue
			}
			alreadyCovered := existingRecord != nil && existingRecord.HasProvider(providerASN)
			if !alreadyCovered {
				allCovered = false
			}
			s.SuggestedProviders = append(s.SuggestedProviders, ProviderSuggestion{
				ProviderASN:    providerASN,
				ObservedCount:  count,
				AlreadyCovered: alreadyCovered,
			})
			s.ObservationCount += count
		}

		if len(s.SuggestedProviders) == 0 {
			continue
		}
		if allCovered && !opts.IncludeAlreadyCovered {
			continue
		}

		sort.Slice(s.SuggestedProviders, func(i, j int) bool {
			return s.SuggestedProviders[i].ObservedCount > s.SuggestedProviders[j].ObservedCount
		})

		s.Confidence = computeConfidence(s.ObservationCount, len(s.SuggestedProviders))
		suggestions = append(suggestions, s)
	}

	sort.Slice(suggestions, func(i, j int) bool {
		if suggestions[i].Confidence != suggestions[j].Confidence {
			return suggestions[i].Confidence > suggestions[j].Confidence
		}
		return suggestions[i].CustomerASN < suggestions[j].CustomerASN
	})

	if opts.TopN > 0 && len(suggestions) > opts.TopN {
		suggestions = suggestions[:opts.TopN]
	}

	return suggestions, nil
}

// Ensure types import is used (route iteration uses types.Route indirectly)
var _ types.Route

func computeConfidence(observationCount, providerCount int) int {
	score := 50
	switch {
	case observationCount >= 1000:
		score += 30
	case observationCount >= 100:
		score += 20
	case observationCount >= 10:
		score += 10
	case observationCount >= 2:
		score += 5
	}
	switch {
	case providerCount == 1:
		score += 20
	case providerCount == 2:
		score += 10
	case providerCount >= 10:
		score -= 30
	case providerCount >= 5:
		score -= 20
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}
