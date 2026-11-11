package events

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
)

const internalChannelSize = 1000

// DefaultRTRBulkThreshold is events.rtr-bulk-threshold's default: an RTR
// update that changes the posture of more routes than this is reported as
// one rtr_bulk_change event.
const DefaultRTRBulkThreshold = 100

// Engine evaluates all configured rules for every event it receives.
// It owns an internal buffered channel so that callers using Emit are
// decoupled from action execution latency.
type Engine struct {
	rules   []*Rule
	logger  *slog.Logger
	eventCh chan Event
	// bulkThreshold is the RTR bulk guard's threshold; 0 disables it.
	bulkThreshold int
}

// NewEngine creates an Engine backed by a 1000-event internal buffer, with
// the RTR bulk guard at DefaultRTRBulkThreshold.
func NewEngine(rules []*Rule, logger *slog.Logger) *Engine {
	return &Engine{
		rules:         rules,
		logger:        logger,
		eventCh:       make(chan Event, internalChannelSize),
		bulkThreshold: DefaultRTRBulkThreshold,
	}
}

// SetRTRBulkThreshold sets the RTR bulk guard's threshold (see RTRBatch).
// Zero or less disables the guard: every RTR-driven change is a per-route
// event, however many one update makes.
func (e *Engine) SetRTRBulkThreshold(n int) {
	e.bulkThreshold = max(n, 0)
}

// Run reads events from eventCh and the engine's internal channel, evaluating
// all rules concurrently for each event. It blocks until ctx is done and all
// in-flight evaluations complete.
//
// eventCh may be nil; in that case only events sent via Emit are processed.
func (e *Engine) Run(ctx context.Context, eventCh <-chan Event) {
	var wg sync.WaitGroup
	for {
		var event Event
		select {
		case ev, ok := <-eventCh:
			if !ok {
				eventCh = nil // disable closed channel; keep draining internal
				continue
			}
			event = ev
		case ev := <-e.eventCh:
			event = ev
		case <-ctx.Done():
			wg.Wait()
			return
		}
		// Stale routes have not been confirmed by a live BMP message yet —
		// skip them so snapshot artefacts never trigger active-response rules.
		if event.Route != nil && event.Route.Stale {
			continue
		}
		for i, rule := range e.rules {
			targeted := i < len(event.targets) && event.targets[i]
			// An event with targets (an rtr_bulk_change) goes to those
			// rules only, once each; no other rule's trigger is asked.
			if event.targets != nil && !targeted {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if targeted {
					rule.fire(ctx, event)
				} else {
					rule.Evaluate(ctx, event)
				}
			}()
		}
	}
}

// Emit sends an event to the engine's internal channel for processing by Run.
// It is non-blocking: if the channel is full the event is dropped with a warning.
func (e *Engine) Emit(event Event) {
	select {
	case e.eventCh <- event:
	default:
		e.logger.Warn("event channel full, dropping event",
			"type", event.Type,
			"id", event.ID,
		)
	}
}

// RTRBatch collects the per-route events of one RTR update (one
// revalidation pass) and applies the bulk guard when it is flushed.
//
// A single RTR update can flip thousands of routes at once: a repository
// outage turned ~400 legitimate routes Invalid in one update. Per-route
// webhooks and FlowSpec rules for each of them would page operators
// hundreds of times and could block traffic that is, in fact, legitimate.
//
// The batch keeps two counts against the threshold:
//
//   - Matched: changes that match a rule with an action. When more than the
//     threshold match, the update is bulk for those rules: their per-route
//     events are not emitted, and each of them gets one rtr_bulk_change
//     event instead (notification actions only, see Rule.fire). A change no
//     rule acts on does not count here, so a large harmless wave (NotFound
//     to Valid after a new ROA) cannot suppress the one alert the same
//     update carries.
//   - Changes: every posture change in the pass. When more than the
//     threshold change, rules with an rtr_bulk_change trigger get one
//     rtr_bulk_change event, whether or not any other rule matches the
//     changes: a mass change is worth knowing about by itself.
//
// One event per pass carries both counts, and each rule gets it at most
// once. At or below the threshold the matched events are emitted as they
// would be without the guard.
//
// The batch holds at most threshold+1 events: past that the update is bulk
// whatever else it changes, and only counts and samples are kept. Not safe
// for concurrent use; one goroutine (raven serve's ingest loop) owns it.
type RTRBatch struct {
	e      *Engine
	caches []string
	serial uint32

	events  []Event
	all     bulkCounter // every change
	acted   bulkCounter // changes a rule with an action matched
	matched []bool      // rules a batched event matched
	actions int         // actions those matches would have run
}

// bulkCounter accumulates a BulkCounts.
type bulkCounter struct {
	BulkCounts
	seen map[string]bool // sample prefixes
}

func (c *bulkCounter) add(ev Event) {
	if c.Transitions == nil {
		c.Transitions, c.seen = map[string]int{}, map[string]bool{}
	}
	c.Routes++
	c.Transitions[string(ev.OldPosture)+"->"+string(ev.NewPosture)]++
	if ev.Route != nil {
		if p := ev.Route.Prefix.String(); len(c.SamplePrefixes) < MaxBulkSamples && !c.seen[p] {
			c.seen[p] = true
			c.SamplePrefixes = append(c.SamplePrefixes, p)
		}
	}
}

func (c *bulkCounter) counts() BulkCounts {
	out := c.BulkCounts
	if out.Transitions == nil {
		out.Transitions = map[string]int{}
	}
	if out.SamplePrefixes == nil {
		out.SamplePrefixes = []string{}
	}
	return out
}

// NewRTRBatch starts the batch for an RTR update from caches, at serial.
func (e *Engine) NewRTRBatch(caches []string, serial uint32) *RTRBatch {
	return &RTRBatch{
		e:       e,
		caches:  caches,
		serial:  serial,
		matched: make([]bool, len(e.rules)),
	}
}

// Add adds one route's RTR-driven change. ev's Source and Serial are set
// here. Every change counts in Changes; one that matches no rule with an
// action is not kept and does not count in Matched: it would fire nothing.
func (b *RTRBatch) Add(ev Event) {
	ev.Source = SourceRTR
	ev.Serial = b.serial
	b.all.add(ev)
	acted := false
	for i, rule := range b.e.rules {
		// Stale routes never fire rules (see Run).
		if len(rule.Actions) > 0 && (ev.Route == nil || !ev.Route.Stale) && rule.Trigger.Matches(ev) {
			b.matched[i] = true
			b.actions += len(rule.Actions)
			acted = true
		}
	}
	if !acted {
		return
	}
	b.acted.add(ev)
	switch {
	case b.e.bulkThreshold == 0 || b.acted.Routes <= b.e.bulkThreshold:
		b.events = append(b.events, ev)
	default:
		b.events = nil // bulk: the per-route events will not be emitted
	}
}

// Routes is how many changes in the batch a rule acts on: the count that
// suppresses per-route events.
func (b *RTRBatch) Routes() int { return b.acted.Routes }

// Changes is how many posture changes the batch has seen: the count that
// fires rtr_bulk_change rules.
func (b *RTRBatch) Changes() int { return b.all.Routes }

// Flush emits the batch with emit (the engine's Emit if nil): its per-route
// events unless more than the threshold matched rules, and one
// rtr_bulk_change event if more than the threshold changed (to the
// rtr_bulk_change rules) or matched (to the rules whose per-route events it
// replaces). It returns the bulk event, nil if there was none.
func (b *RTRBatch) Flush(emit func(Event)) *Event {
	if emit == nil {
		emit = b.e.Emit
	}
	th := b.e.bulkThreshold
	suppress := th > 0 && b.acted.Routes > th
	mass := th > 0 && b.all.Routes > th
	if !suppress {
		for _, ev := range b.events {
			emit(ev)
		}
	}
	if !suppress && !mass {
		return nil
	}
	ev := Event{
		ID:        NewID(),
		Timestamp: time.Now(),
		Type:      EventTypeRTRBulkChange,
		CacheName: strings.Join(b.caches, ","),
		Source:    SourceRTR,
		Serial:    b.serial,
		Bulk: &BulkChange{
			Threshold:  th,
			Changes:    b.all.counts(),
			Matched:    b.acted.counts(),
			Suppressed: suppress,
		},
	}
	targets := make([]bool, len(b.e.rules))
	anyTarget := false
	for i, rule := range b.e.rules {
		targets[i] = (suppress && b.matched[i]) ||
			(mass && hasBulkTrigger(rule.Trigger) && rule.Trigger.Matches(ev))
		anyTarget = anyTarget || targets[i]
	}
	if suppress {
		metrics.EventsRTRBulkSuppressedActionsTotal.Add(float64(b.actions))
		b.e.logger.Warn("RTR update changed many routes at once: one rtr_bulk_change event, per-route actions suppressed",
			"cache", ev.CacheName, "serial", b.serial, "matched", b.acted.Routes, "changes", b.all.Routes,
			"threshold", th, "suppressed_actions", b.actions, "transitions", b.acted.Transitions)
	}
	if !anyTarget {
		return nil
	}
	ev.targets = targets
	metrics.EventsRTRBulkChangesTotal.Inc()
	if !suppress {
		b.e.logger.Info("RTR update changed many routes at once: rtr_bulk_change event to the rtr_bulk_change rules",
			"cache", ev.CacheName, "serial", b.serial, "changes", b.all.Routes, "matched", b.acted.Routes,
			"threshold", th, "transitions", b.all.Transitions)
	}
	emit(ev)
	return &ev
}
