package events

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
)

// rtr_stale and rtr_data_regressed reach a rule's notification actions only,
// never FlowSpec (or any other action), whatever trigger the rule has; each
// reaches only the rules with its trigger.
func TestDataEventsReachNotificationActionsOnly(t *testing.T) {
	for _, typ := range []EventType{EventTypeRTRStale, EventTypeRTRDataRegressed} {
		t.Run(string(typ), func(t *testing.T) {
			var wg sync.WaitGroup
			wg.Add(1)
			notify := &notifyAction{countAction{wg: &wg}}
			mitigate := &countAction{}
			rule := &Rule{Name: "any", Trigger: &alwaysTrigger{}, Actions: []Action{notify, mitigate},
				log: slog.New(slog.DiscardHandler)}
			rule.Evaluate(context.Background(), Event{Type: typ, CacheName: "rtr1:323", Data: &DataChange{Gap: time.Hour}})
			wg.Wait()
			// Actions run concurrently; Evaluate returns once they have.
			if notify.count() != 1 || mitigate.count() != 0 {
				t.Errorf("notification action ran %d times, other action %d; want 1 and 0", notify.count(), mitigate.count())
			}
		})
	}
	stale, regressed := &RTRStaleTrigger{}, &RTRDataRegressedTrigger{}
	if !stale.Matches(Event{Type: EventTypeRTRStale}) || stale.Matches(Event{Type: EventTypeRTRDataRegressed}) ||
		!regressed.Matches(Event{Type: EventTypeRTRDataRegressed}) || regressed.Matches(Event{Type: EventTypeRTRStale}) {
		t.Error("rtr_stale and rtr_data_regressed triggers match the wrong events")
	}
	for _, name := range []string{"rtr_stale", "rtr_data_regressed"} {
		if _, err := buildTrigger(config.TriggerConfig{Type: name}); err != nil {
			t.Errorf("trigger %s: %v", name, err)
		}
	}
}

// A webhook payload carries the data state.
func TestWebhookPayloadCarriesDataChange(t *testing.T) {
	at := time.Date(2026, 11, 12, 4, 49, 43, 0, time.UTC)
	p := (&WebhookAction{ruleName: "r"}).buildPayload(Event{Type: EventTypeRTRStale, CacheName: "rtr1:323", Serial: 3,
		Data: &DataChange{LastChange: at, Gap: 2 * time.Hour, Threshold: time.Hour, ThresholdSource: "learned", SyncsWithoutChange: 2}})
	if p.Type != "rtr_stale" || p.CacheName != "rtr1:323" || p.Serial != 3 || p.Data == nil ||
		p.Data.LastChange != "2026-11-12T04:49:43Z" || p.Data.GapNS != int64(2*time.Hour) || p.Data.ThresholdSource != "learned" {
		t.Errorf("payload %+v data %+v", p, p.Data)
	}
}
