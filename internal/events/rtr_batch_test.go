package events

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

func batchEngine(threshold int, rules ...*Rule) *Engine {
	e := NewEngine(rules, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetRTRBulkThreshold(threshold)
	return e
}

func batchRule(name string, trigger Trigger, actions int) *Rule {
	rule := &Rule{Name: name, Trigger: trigger, log: slog.New(slog.DiscardHandler)}
	for range actions {
		rule.Actions = append(rule.Actions, &countAction{})
	}
	return rule
}

func rtrChange(i int, old, new types.SecurityPosture) Event {
	r := newRoute(fmt.Sprintf("10.%d.%d.0/24", i>>8, i&0xff))
	return Event{ID: NewID(), Type: EventTypePostureChange, Route: r, OldPosture: old, NewPosture: new}
}

// collect returns an emit func for Flush and the events it was given.
func collect() (func(Event), *[]Event) {
	var got []Event
	return func(ev Event) { got = append(got, ev) }, &got
}

// At or below the threshold a batch emits every event, as RTR-driven
// posture changes (source rtr, the update's serial).
func TestRTRBatchAtThresholdEmitsEveryEvent(t *testing.T) {
	e := batchEngine(3, batchRule("invalid", &PostureChangeTrigger{Postures: []types.SecurityPosture{types.PostureOriginInvalid}}, 1))
	b := e.NewRTRBatch([]string{"rtr1:323"}, 42)
	for i := range 3 {
		b.Add(rtrChange(i, types.PostureUnverified, types.PostureOriginInvalid))
	}
	emit, got := collect()
	if bulk := b.Flush(emit); bulk != nil {
		t.Fatalf("bulk event %+v at the threshold", bulk)
	}
	if len(*got) != 3 {
		t.Fatalf("%d events emitted, want 3", len(*got))
	}
	for _, ev := range *got {
		if ev.Source != SourceRTR || ev.Serial != 42 || ev.Type != EventTypePostureChange {
			t.Errorf("event %+v, want an RTR posture_change at serial 42", ev)
		}
	}
}

// Past the threshold a batch emits one rtr_bulk_change event and no
// per-route event: counts per transition, at most MaxBulkSamples distinct
// sample prefixes, the cache and serial, and as its targets exactly the
// rules a suppressed event matched.
func TestRTRBatchPastThresholdEmitsOneBulkEvent(t *testing.T) {
	invalid := batchRule("invalid", &PostureChangeTrigger{Postures: []types.SecurityPosture{types.PostureOriginInvalid}}, 2)
	notFound := batchRule("notfound", &PostureChangeTrigger{Postures: []types.SecurityPosture{types.PostureUnverified}}, 1)
	other := batchRule("other", &PrefixTrigger{Supernet: netip.MustParsePrefix("192.0.2.0/24")}, 1)
	e := batchEngine(10, invalid, notFound, other)
	b := e.NewRTRBatch([]string{"rtr1:323", "rtr2:323"}, 7)
	for i := range 30 {
		b.Add(rtrChange(i, types.PostureUnverified, types.PostureOriginInvalid))
	}
	b.Add(rtrChange(0, types.PostureOriginInvalid, types.PostureOriginOnly)) // matches no rule: not counted
	emit, got := collect()
	bulk := b.Flush(emit)
	if bulk == nil || len(*got) != 1 || (*got)[0].Type != EventTypeRTRBulkChange {
		t.Fatalf("emitted %+v, want exactly one rtr_bulk_change", *got)
	}
	ev := (*got)[0]
	m, all := ev.Bulk.Matched, ev.Bulk.Changes
	if ev.CacheName != "rtr1:323,rtr2:323" || ev.Serial != 7 || ev.Source != SourceRTR || ev.Route != nil ||
		!ev.Bulk.Suppressed || ev.Bulk.Threshold != 10 ||
		m.Routes != 30 || len(m.SamplePrefixes) != MaxBulkSamples || len(m.Transitions) != 1 ||
		m.Transitions["unverified->origin-invalid"] != 30 ||
		all.Routes != 31 || len(all.Transitions) != 2 || all.Transitions["origin-invalid->origin-only"] != 1 {
		t.Errorf("bulk event %+v (%+v), want caches, serial 7, suppressed, 30 matched in one transition, 31 changes in two",
			ev, *ev.Bulk)
	}
	seen := map[string]bool{}
	for _, p := range m.SamplePrefixes {
		if seen[p] {
			t.Errorf("sample prefix %s listed twice", p)
		}
		seen[p] = true
	}
	if want := []bool{true, false, false}; fmt.Sprint(ev.targets) != fmt.Sprint(want) {
		t.Errorf("bulk event targets %v, want only the rule the suppressed events matched (%v)", ev.targets, want)
	}
	if b.actions != 60 {
		t.Errorf("suppressed actions %d, want 60 (30 events x 2 actions)", b.actions)
	}
}

// A negative events.rtr-bulk-threshold disables the guard; unset (0) is the
// default. The source and rtr_bulk_change triggers build from config.
func TestRTRBulkConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rule := config.RuleConfig{Name: "r", Trigger: config.TriggerConfig{Type: "source", Sources: []string{"rtr"}},
		Actions: []config.ActionConfig{{Type: "log"}}}
	for _, tc := range []struct {
		set, want int
	}{{0, DefaultRTRBulkThreshold}, {5, 5}, {-1, 0}} {
		e, _, err := BuildEngine(config.EventsConfig{Rules: []config.RuleConfig{rule}, RTRBulkThreshold: tc.set}, log)
		if err != nil {
			t.Fatal(err)
		}
		if e.bulkThreshold != tc.want {
			t.Errorf("rtr-bulk-threshold %d: threshold %d, want %d", tc.set, e.bulkThreshold, tc.want)
		}
	}
	e := batchEngine(0, batchRule("invalid", &PostureChangeTrigger{Postures: []types.SecurityPosture{types.PostureOriginInvalid}}, 1))
	b := e.NewRTRBatch(nil, 1)
	for i := range 500 {
		b.Add(rtrChange(i, types.PostureUnverified, types.PostureOriginInvalid))
	}
	emit, got := collect()
	if b.Flush(emit) != nil || len(*got) != 500 {
		t.Errorf("guard disabled: %d events emitted, want all 500 and no bulk event", len(*got))
	}

	if _, _, err := BuildEngine(config.EventsConfig{Rules: []config.RuleConfig{{Name: "bad",
		Trigger: config.TriggerConfig{Type: "source", Sources: []string{"kafka"}}}}}, log); err == nil {
		t.Error("source trigger with an unknown source built")
	}
	bulkRule := config.RuleConfig{Name: "bulk", Trigger: config.TriggerConfig{Type: "rtr_bulk_change"}}
	if _, _, err := BuildEngine(config.EventsConfig{Rules: []config.RuleConfig{bulkRule}}, log); err != nil {
		t.Errorf("rtr_bulk_change trigger: %v", err)
	}
}

// The source trigger matches on the event's source; rtr_bulk_change matches
// bulk events only.
func TestSourceAndBulkTriggers(t *testing.T) {
	rtrOnly := &SourceTrigger{Sources: []string{SourceRTR}}
	if !rtrOnly.Matches(Event{Source: SourceRTR}) || rtrOnly.Matches(Event{Source: SourceBMP}) || rtrOnly.Matches(Event{}) {
		t.Error("source trigger [rtr] matched wrongly")
	}
	bulk := &RTRBulkChangeTrigger{}
	if !bulk.Matches(Event{Type: EventTypeRTRBulkChange}) || bulk.Matches(Event{Type: EventTypePostureChange}) {
		t.Error("rtr_bulk_change trigger matched wrongly")
	}
}

// Only changes a rule acts on count toward the threshold. A pass with 500
// routes NotFound -> Valid (a new ROA: no rule acts on it) and one route
// Valid -> Invalid, an origin-invalid rule and threshold 100: the invalid
// route's per-route event is emitted, and there is no rtr_bulk_change.
func TestRTRBatchCountsOnlyChangesARuleActsOn(t *testing.T) {
	e := batchEngine(100, batchRule("invalid", &PostureChangeTrigger{Postures: []types.SecurityPosture{types.PostureOriginInvalid}}, 1))
	b := e.NewRTRBatch([]string{"rtr1:323"}, 3)
	for i := range 500 {
		b.Add(rtrChange(i, types.PostureUnverified, types.PostureOriginOnly))
	}
	invalid := rtrChange(1000, types.PostureOriginOnly, types.PostureOriginInvalid)
	b.Add(invalid)
	emit, got := collect()
	if bulk := b.Flush(emit); bulk != nil {
		t.Fatalf("rtr_bulk_change %+v for one matching change", *bulk.Bulk)
	}
	if len(*got) != 1 || (*got)[0].Route != invalid.Route || (*got)[0].NewPosture != types.PostureOriginInvalid {
		t.Fatalf("emitted %d events, want exactly the invalid route's", len(*got))
	}
	if b.Routes() != 1 || b.Changes() != 501 {
		t.Errorf("counted %d of %d changes, want 1 of 501", b.Routes(), b.Changes())
	}
}

// notifyAction is a test notification action (as webhook and log are).
type notifyAction struct{ countAction }

func (a *notifyAction) notification() {}

// An rtr_bulk_change event reaches a rule's notification actions only:
// never a FlowSpec (or any other) action, even on a rule the suppressed
// routes matched.
func TestBulkEventReachesNotificationActionsOnly(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	notify := &notifyAction{countAction{wg: &wg}}
	mitigate := &countAction{}
	rule := &Rule{Name: "invalid", Trigger: &PostureChangeTrigger{Postures: []types.SecurityPosture{types.PostureOriginInvalid}},
		Actions: []Action{notify, mitigate}, log: slog.New(slog.DiscardHandler)}
	e := batchEngine(2, rule)
	b := e.NewRTRBatch([]string{"rtr1:323"}, 1)
	for i := range 3 {
		b.Add(rtrChange(i, types.PostureUnverified, types.PostureOriginInvalid))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx, nil)
	}()
	if b.Flush(nil) == nil {
		t.Fatal("no bulk event")
	}
	wg.Wait() // the notification ran
	cancel()
	<-done // Run waits for every evaluation it started
	if notify.count() != 1 || mitigate.count() != 0 {
		t.Errorf("notification action ran %d times, other action %d; want 1 and 0", notify.count(), mitigate.count())
	}
	if !isNotification(&WebhookAction{}) || !isNotification(&LogAction{}) || isNotification(&FlowspecAction{}) {
		t.Error("webhook and log must be notification actions, flowspec must not")
	}
	// FlowSpec refuses a bulk event on its own too.
	if err := (&FlowspecAction{}).Execute(ctx, Event{Type: EventTypeRTRBulkChange, Route: newRoute("10.0.0.0/24")}); err != nil {
		t.Errorf("FlowSpec action on a bulk event: %v", err)
	}
}

// A negative events.rtr-bulk-threshold disables the guard, with a WARN at
// startup.
func TestRTRBulkGuardDisabledWarns(t *testing.T) {
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))
	rule := config.RuleConfig{Name: "r", Trigger: config.TriggerConfig{Type: "posture", Postures: []string{"origin-invalid"}},
		Actions: []config.ActionConfig{{Type: "log"}}}
	for _, th := range []int{0, 100, -1} {
		logs.Reset()
		if _, _, err := BuildEngine(config.EventsConfig{Rules: []config.RuleConfig{rule}, RTRBulkThreshold: th}, log); err != nil {
			t.Fatal(err)
		}
		warned := strings.Contains(logs.String(), "level=WARN") && strings.Contains(logs.String(), "RTR bulk guard disabled")
		if warned != (th < 0) {
			t.Errorf("rtr-bulk-threshold %d: warned %t, want %t; logs %q", th, warned, th < 0, logs.String())
		}
	}
}

var (
	invalidTrigger = &PostureChangeTrigger{Postures: []types.SecurityPosture{types.PostureOriginInvalid}}
	bulkTrigger    = &RTRBulkChangeTrigger{}
)

// The rtr_bulk_change trigger counts every posture change in the pass,
// whatever other rules match. With only an rtr_bulk_change rule, 500
// routes NotFound -> Valid in one pass and threshold 100: exactly one
// rtr_bulk_change, to that rule, not suppressing anything. 100 changes:
// none.
func TestBulkTriggerCountsEveryChange(t *testing.T) {
	for _, tc := range []struct {
		changes int
		bulk    bool
	}{{500, true}, {100, false}} {
		e := batchEngine(100, batchRule("mass", bulkTrigger, 1))
		b := e.NewRTRBatch([]string{"rtr1:323"}, 5)
		for i := range tc.changes {
			b.Add(rtrChange(i, types.PostureUnverified, types.PostureOriginOnly))
		}
		emit, got := collect()
		bulk := b.Flush(emit)
		if !tc.bulk {
			if bulk != nil || len(*got) != 0 {
				t.Errorf("%d changes: emitted %d events, want none", tc.changes, len(*got))
			}
			continue
		}
		if bulk == nil || len(*got) != 1 {
			t.Fatalf("%d changes: emitted %d events, want exactly one rtr_bulk_change", tc.changes, len(*got))
		}
		bc := bulk.Bulk
		if bc.Suppressed || bc.Changes.Routes != 500 || bc.Changes.Transitions["unverified->origin-only"] != 500 ||
			len(bc.Changes.SamplePrefixes) != MaxBulkSamples || bc.Matched.Routes != 0 || len(bc.Matched.SamplePrefixes) != 0 {
			t.Errorf("bulk %+v, want 500 changes, none matched, not suppressing", *bc)
		}
		if fmt.Sprint(bulk.targets) != "[true]" {
			t.Errorf("targets %v, want the rtr_bulk_change rule", bulk.targets)
		}
	}
}

// The harmless wave with both kinds of rule: 500 NotFound -> Valid and one
// Valid -> Invalid, an origin-invalid rule and an rtr_bulk_change rule,
// threshold 100. The invalid route's per-route event is emitted, and the
// one rtr_bulk_change goes to the rtr_bulk_change rule only.
func TestHarmlessWaveBulkGoesToBulkRuleOnly(t *testing.T) {
	e := batchEngine(100, batchRule("invalid", invalidTrigger, 1), batchRule("mass", bulkTrigger, 1))
	b := e.NewRTRBatch([]string{"rtr1:323"}, 6)
	for i := range 500 {
		b.Add(rtrChange(i, types.PostureUnverified, types.PostureOriginOnly))
	}
	b.Add(rtrChange(1000, types.PostureOriginOnly, types.PostureOriginInvalid))
	emit, got := collect()
	bulk := b.Flush(emit)
	if len(*got) != 2 || (*got)[0].Type != EventTypePostureChange || (*got)[0].NewPosture != types.PostureOriginInvalid || bulk == nil {
		t.Fatalf("emitted %+v, want the invalid route's posture_change, then one rtr_bulk_change", *got)
	}
	if fmt.Sprint(bulk.targets) != "[false true]" {
		t.Errorf("bulk targets %v, want only the rtr_bulk_change rule", bulk.targets)
	}
	if bc := bulk.Bulk; bc.Suppressed || bc.Changes.Routes != 501 || bc.Matched.Routes != 1 ||
		bc.Matched.Transitions["origin-only->origin-invalid"] != 1 || len(bc.Matched.SamplePrefixes) != 1 {
		t.Errorf("bulk %+v, want 501 changes, 1 matched, not suppressing", *bc)
	}
}

// A rule both suppressed and asking for bulk changes (an or of its posture
// trigger and rtr_bulk_change) gets the pass's rtr_bulk_change once.
func TestBulkEventOncePerRulePerPass(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	notify := &notifyAction{countAction{wg: &wg}}
	rule := &Rule{Name: "both", Trigger: &CompoundTrigger{Op: "or", Triggers: []Trigger{invalidTrigger, bulkTrigger}},
		Actions: []Action{notify}, log: slog.New(slog.DiscardHandler)}
	other := &countAction{}
	bystander := &Rule{Name: "rtr", Trigger: &SourceTrigger{Sources: []string{SourceRTR}}, Actions: []Action{other},
		log: slog.New(slog.DiscardHandler)}
	e := batchEngine(100, rule)
	e.rules = append(e.rules, bystander)
	b := e.NewRTRBatch(nil, 1)
	for i := range 101 {
		b.Add(rtrChange(i, types.PostureUnverified, types.PostureOriginInvalid))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx, nil)
	}()
	bulk := b.Flush(nil)
	if bulk == nil || !bulk.Bulk.Suppressed {
		t.Fatal("no suppressing bulk event")
	}
	wg.Wait()
	cancel()
	<-done
	if notify.count() != 1 {
		t.Errorf("rule got the bulk event %d times, want once", notify.count())
	}
	// The source rule matched every change, so it was suppressed and is
	// a target too; its plain action is not a notification and does not run.
	if fmt.Sprint(bulk.targets) != "[true true]" || other.count() != 0 {
		t.Errorf("targets %v, plain action ran %d times; want both rules targeted, no plain action", bulk.targets, other.count())
	}
}
