package cli

import (
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external"
)

// ─── TestGlobalVerdict ───

func TestGlobalVerdict(t *testing.T) {
	tests := []struct {
		name        string
		result      external.GlobalVisibilityResult
		wantVerdict string
		wantIn      string
	}{
		{
			name: "match",
			result: external.GlobalVisibilityResult{
				Consensus:      external.ConsensusMatch,
				LocalOrigin:    64511,
				GlobalOrigins:  []external.GlobalOriginObservation{{ASN: 64511, CollectorCount: 20}},
				CollectorCount: 20,
			},
			wantVerdict: verdictGlobalMatch,
			wantIn:      "20 collector peers",
		},
		{
			name: "divergent with a single global origin names both ASNs",
			result: external.GlobalVisibilityResult{
				Consensus:      external.ConsensusDivergent,
				LocalOrigin:    64511,
				GlobalOrigins:  []external.GlobalOriginObservation{{ASN: 65000, CollectorCount: 18}},
				CollectorCount: 18,
			},
			wantVerdict: verdictGlobalDivergent,
			wantIn:      "AS65000",
		},
		{
			name: "divergent with multiple global origins reports a MOAS",
			result: external.GlobalVisibilityResult{
				Consensus:   external.ConsensusDivergent,
				LocalOrigin: 64511,
				GlobalOrigins: []external.GlobalOriginObservation{
					{ASN: 65000, CollectorCount: 18},
					{ASN: 64511, CollectorCount: 4},
				},
				CollectorCount: 22,
			},
			wantVerdict: verdictGlobalDivergent,
			wantIn:      "MOAS",
		},
		{
			name: "local only",
			result: external.GlobalVisibilityResult{
				Consensus:   external.ConsensusLocalOnly,
				LocalOrigin: 64511,
			},
			wantVerdict: verdictGlobalLocalOnly,
			wantIn:      "No collector sees this prefix",
		},
		{
			name: "inconclusive surfaces the underlying cause",
			result: external.GlobalVisibilityResult{
				Consensus:   external.ConsensusInconclusive,
				LocalOrigin: 64511,
				Error:       "query RIPEstat: connection refused",
			},
			wantVerdict: verdictGlobalInconclusive,
			wantIn:      "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, explanation := globalVerdict(tt.result)
			if verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", verdict, tt.wantVerdict)
			}
			if !strings.Contains(explanation, tt.wantIn) {
				t.Errorf("explanation = %q, want it to contain %q", explanation, tt.wantIn)
			}
		})
	}
}

// The verdict box must render every consensus without panicking, including
// the empty-observations cases that have no majority origin.
func TestPrintGlobalVerdictBoxHandlesEveryVerdict(t *testing.T) {
	for _, consensus := range []external.GlobalConsensus{
		external.ConsensusMatch,
		external.ConsensusDivergent,
		external.ConsensusLocalOnly,
		external.ConsensusInconclusive,
	} {
		r := globalReport{Prefix: "203.0.113.0/24", LocalOriginASN: 64511}
		r.GlobalVisibility = external.GlobalVisibilityResult{Consensus: consensus, LocalOrigin: 64511}
		r.Verdict, r.Explanation = globalVerdict(r.GlobalVisibility)
		printGlobalVerdictBox(r)
		printGlobalView(r.GlobalVisibility)
	}
}
