package events

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Rule pairs a Trigger with one or more Actions and optional per-prefix rate-limiting.
type Rule struct {
	// Name is a human-readable identifier used in logs.
	Name string
	// Trigger decides whether this rule fires for a given event.
	Trigger Trigger
	// Actions are executed concurrently when the trigger matches.
	Actions []Action
	// Enrichers annotate the event before Actions run. They are populated
	// from the same YAML actions list; buildRule partitions them out.
	Enrichers []Enricher
	// Cooldown prevents the same rule from firing more than once per route
	// (types.RouteKey: router, peer distinguisher, peer, prefix, path ID
	// and RIB) within this duration. Zero means no cooldown.
	Cooldown    time.Duration
	log         *slog.Logger
	cooldownMu  sync.Mutex
	cooldownMap map[string]time.Time // key: "prefix|peerAddr" or event type
}

// Evaluate checks the trigger, enforces the cooldown, runs any enrichers,
// then calls every action concurrently in its own goroutine. Action errors
// are logged but do not interrupt other actions.
//
// The engine calls Evaluate from its own goroutine, so everything here —
// including an enricher's outbound HTTP call — is already off the BMP ingest
// and validation path.
func (r *Rule) Evaluate(ctx context.Context, event Event) {
	if !r.Trigger.Matches(event) {
		return
	}
	r.fire(ctx, event)
}

// fire runs the rule for an event that matched it: cooldown, enrichers,
// then the actions.
//
// An rtr_bulk_change event goes to notification actions only (webhook,
// log): it stands for routes whose per-route actions were suppressed, and
// must never produce a FlowSpec rule, per route or aggregate. Enrichers do
// not run for it either; it has no route to annotate.
func (r *Rule) fire(ctx context.Context, event Event) {
	bulk := event.Type == EventTypeRTRBulkChange
	if !r.checkCooldown(event) {
		return
	}

	// Enrichers run to completion before the actions so that every action
	// sees the same fully annotated event. They mutate a local copy; the
	// event the engine holds is untouched, so one rule's enrichment cannot
	// leak into another rule's evaluation of the same event.
	if !bulk {
		for _, enricher := range r.Enrichers {
			enricher.Enrich(ctx, &event)
		}
	}

	var wg sync.WaitGroup
	for _, action := range r.Actions {
		if bulk && !isNotification(action) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := action.Execute(ctx, event); err != nil {
				r.log.Error("action failed",
					"rule", r.Name,
					"action", action.Name(),
					"error", err,
				)
			}
		}()
	}
	wg.Wait()
}

// checkCooldown returns false when the event falls within the active cooldown
// window for its route key. On a pass it records the current time.
func (r *Rule) checkCooldown(event Event) bool {
	if r.Cooldown == 0 {
		return true
	}
	key := cooldownKey(event)
	now := time.Now()
	r.cooldownMu.Lock()
	defer r.cooldownMu.Unlock()
	if last, ok := r.cooldownMap[key]; ok && now.Sub(last) < r.Cooldown {
		return false
	}
	r.cooldownMap[key] = now
	return true
}

func cooldownKey(event Event) string {
	if event.Type == EventTypeCacheUnhealthy {
		return "cache|" + event.CacheName
	}
	if event.Route == nil {
		return string(event.Type)
	}
	// The whole route key: a key of prefix and peer address alone let an
	// event in one RIB, router or VRF suppress another's.
	k := event.Route.Key()
	return fmt.Sprintf("%s|%s|%s|%s|%d|%s", k.Peer.Router, types.FormatRD(k.Peer.Distinguisher),
		k.Peer.Addr, k.Prefix, k.PathID, k.RIBType)
}
