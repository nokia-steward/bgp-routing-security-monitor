package telemetry

import "testing"

func TestAnomalyTrigger(t *testing.T) {
	tests := []struct {
		name string
		ev   *AnomalyEvent
		want string
	}{
		{
			name: "correlated joins in canonical order, not input order",
			// ZScores is a map, so input order is irrelevant; the join must
			// follow canonical metric order regardless.
			ev: &AnomalyEvent{
				Trigger: "correlated",
				ZScores: map[string]float64{
					MetricVRPWithdrawn: 4.1,
					MetricSyncDuration: 3.8,
				},
			},
			want: "sync_duration_ns+vrp_withdrawn",
		},
		{
			name: "correlated with many crossers stays canonical",
			ev: &AnomalyEvent{
				Trigger: "correlated",
				ZScores: map[string]float64{
					MetricASPAWithdrawn:        3.2,
					MetricVRPAnnounced:         3.9,
					MetricSerialChangeInterval: 4.4,
				},
			},
			want: "serial_change_interval_ns+vrp_announced+aspa_withdrawn",
		},
		{
			name: "hard-trip single metric passes through unchanged",
			// Even though ZScores carries multiple soft crossers, a non-correlated
			// trigger must NOT be joined or reordered.
			ev: &AnomalyEvent{
				Trigger: MetricVRPWithdrawn,
				ZScores: map[string]float64{
					MetricVRPWithdrawn: 9.5,
					MetricSyncDuration: 3.7,
				},
			},
			want: "vrp_withdrawn",
		},
		{
			name: "structural cache_reset passes through unchanged",
			ev:   &AnomalyEvent{Trigger: "cache_reset"},
			want: "cache_reset",
		},
		{
			name: "structural error_report passes through unchanged",
			ev:   &AnomalyEvent{Trigger: "error_report"},
			want: "error_report",
		},
		{
			name: "correlated with no z-scores falls back to the raw trigger",
			ev:   &AnomalyEvent{Trigger: "correlated"},
			want: "correlated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := anomalyTrigger(tt.ev); got != tt.want {
				t.Fatalf("anomalyTrigger() = %q, want %q", got, tt.want)
			}
		})
	}
}
