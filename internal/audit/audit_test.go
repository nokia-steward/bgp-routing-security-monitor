package audit

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

func makeRoute(routerID, peerAddr string, peerASN uint32, prefix string, asPath []uint32, rov types.ROVState, aspa types.ASPAState) *types.Route {
	return &types.Route{
		RouterID:        netip.MustParseAddr(routerID),
		PeerAddr:        netip.MustParseAddr(peerAddr),
		PeerASN:         peerASN,
		Prefix:          netip.MustParsePrefix(prefix),
		ASPath:          asPath,
		ROV:             types.ROVResult{State: rov},
		ASPA:            types.ASPAResult{State: aspa},
		SecurityPosture: types.ComputePosture(rov, aspa),
	}
}

// ─── TestAnalyze_Empty ───

func TestAnalyze_Empty(t *testing.T) {
	report := Analyze("192.0.2.1", types.AdjRIBInPre, nil)
	if report.TotalRoutes != 0 {
		t.Errorf("TotalRoutes: got %d, want 0", report.TotalRoutes)
	}
	if report.ROVCoverage != 0 {
		t.Errorf("ROVCoverage: got %f, want 0", report.ROVCoverage)
	}
	if report.ASPACoverage != 0 {
		t.Errorf("ASPACoverage: got %f, want 0", report.ASPACoverage)
	}
	if len(report.Peers) != 0 {
		t.Errorf("Peers: got %d, want 0", len(report.Peers))
	}
	if len(report.TopOffenders) != 0 {
		t.Errorf("TopOffenders: got %d, want 0", len(report.TopOffenders))
	}
}

// ─── TestAnalyze_RouterFilter ───

func TestAnalyze_RouterFilter(t *testing.T) {
	routes := []*types.Route{
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "1.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAValid),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "2.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAValid),
		// Different router — must not be counted.
		makeRoute("10.0.0.2", "192.0.2.2", 65002, "3.0.0.0/24", []uint32{65002}, types.ROVValid, types.ASPAValid),
	}

	report := Analyze("192.0.2.1", types.AdjRIBInPre, routes)
	if report.TotalRoutes != 2 {
		t.Errorf("TotalRoutes: got %d, want 2", report.TotalRoutes)
	}
}

// ─── TestAnalyze_ROVCoverage ───

func TestAnalyze_ROVCoverage(t *testing.T) {
	routes := []*types.Route{
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "1.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAUnknown),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "2.0.0.0/24", []uint32{65001}, types.ROVInvalid, types.ASPAUnknown),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "3.0.0.0/24", []uint32{65001}, types.ROVNotFound, types.ASPAUnknown),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "4.0.0.0/24", []uint32{65001}, types.ROVNotFound, types.ASPAUnknown),
	}

	report := Analyze("192.0.2.1", types.AdjRIBInPre, routes)
	// 2 out of 4 have ROV state != NotFound
	want := 0.5
	if report.ROVCoverage != want {
		t.Errorf("ROVCoverage: got %f, want %f", report.ROVCoverage, want)
	}
}

// ─── TestAnalyze_ASPACoverage ───

func TestAnalyze_ASPACoverage(t *testing.T) {
	routes := []*types.Route{
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "1.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAValid),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "2.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAInvalid),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "3.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAUnknown),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "4.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAUnknown),
	}

	report := Analyze("192.0.2.1", types.AdjRIBInPre, routes)
	// 2 out of 4 have ASPA state != Unknown
	want := 0.5
	if report.ASPACoverage != want {
		t.Errorf("ASPACoverage: got %f, want %f", report.ASPACoverage, want)
	}
}

// ─── TestAnalyze_PostureSummary ───

func TestAnalyze_PostureSummary(t *testing.T) {
	routes := []*types.Route{
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "1.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAValid),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "2.0.0.0/24", []uint32{65001}, types.ROVValid, types.ASPAValid),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "3.0.0.0/24", []uint32{65001}, types.ROVInvalid, types.ASPAUnknown),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "4.0.0.0/24", []uint32{65001}, types.ROVNotFound, types.ASPAUnknown),
	}

	report := Analyze("192.0.2.1", types.AdjRIBInPre, routes)

	if got := report.PostureSummary["secured"]; got != 2 {
		t.Errorf("secured: got %d, want 2", got)
	}
	if got := report.PostureSummary["origin-invalid"]; got != 1 {
		t.Errorf("origin-invalid: got %d, want 1", got)
	}
	if got := report.PostureSummary["unverified"]; got != 1 {
		t.Errorf("unverified: got %d, want 1", got)
	}
}

// ─── TestAnalyze_TopOffenders ───

func TestAnalyze_TopOffenders(t *testing.T) {
	routes := []*types.Route{
		// AS65100 contributes 3 origin-invalid routes (worst posture).
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "10.0.0.0/24", []uint32{65100}, types.ROVInvalid, types.ASPAUnknown),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "10.1.0.0/24", []uint32{65100}, types.ROVInvalid, types.ASPAUnknown),
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "10.2.0.0/24", []uint32{65100}, types.ROVInvalid, types.ASPAUnknown),
		// AS65200 contributes 1 path-suspect route.
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "20.0.0.0/24", []uint32{65001, 65200}, types.ROVNotFound, types.ASPAInvalid),
		// A secured route — should not appear in offenders.
		makeRoute("10.0.0.1", "192.0.2.1", 65001, "30.0.0.0/24", []uint32{65300}, types.ROVValid, types.ASPAValid),
	}

	report := Analyze("192.0.2.1", types.AdjRIBInPre, routes)

	if len(report.TopOffenders) != 2 {
		t.Fatalf("TopOffenders: got %d entries, want 2", len(report.TopOffenders))
	}

	top := report.TopOffenders[0]
	if top.OriginASN != 65100 {
		t.Errorf("top offender ASN: got %d, want 65100", top.OriginASN)
	}
	if top.Count != 3 {
		t.Errorf("top offender count: got %d, want 3", top.Count)
	}
	if top.Posture != "origin-invalid" {
		t.Errorf("top offender posture: got %q, want \"origin-invalid\"", top.Posture)
	}
	if len(top.Prefixes) != 3 {
		t.Errorf("top offender prefixes: got %d, want 3", len(top.Prefixes))
	}
}

// ─── TestRecommendations ───

func TestRecommendations(t *testing.T) {
	t.Run("healthy posture emits no-issues message", func(t *testing.T) {
		report := &RouterAuditReport{
			TotalRoutes:    10,
			ROVCoverage:    1.0,
			ASPACoverage:   1.0,
			PostureSummary: map[string]int{"secured": 10},
		}
		recs := generateRecommendations(report)
		if len(recs) != 1 || !strings.Contains(recs[0], "healthy") {
			t.Errorf("expected single healthy message, got %v", recs)
		}
	})

	t.Run("zero ROV coverage triggers rule 1", func(t *testing.T) {
		report := &RouterAuditReport{
			TotalRoutes:    5,
			ROVCoverage:    0,
			PostureSummary: map[string]int{"unverified": 5},
		}
		recs := generateRecommendations(report)
		found := false
		for _, r := range recs {
			if strings.Contains(r, "No ROV coverage") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected 'No ROV coverage' recommendation, got %v", recs)
		}
	})

	t.Run("origin-invalid routes trigger rule 3", func(t *testing.T) {
		report := &RouterAuditReport{
			TotalRoutes:    10,
			ROVCoverage:    1.0,
			PostureSummary: map[string]int{"secured": 8, "origin-invalid": 2},
		}
		recs := generateRecommendations(report)
		found := false
		for _, r := range recs {
			if strings.Contains(r, "origin-invalid") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected origin-invalid recommendation, got %v", recs)
		}
	})

	t.Run("three or more offenders trigger rule 7", func(t *testing.T) {
		report := &RouterAuditReport{
			TotalRoutes: 10,
			ROVCoverage: 1.0,
			PostureSummary: map[string]int{
				"secured":        7,
				"origin-invalid": 3,
			},
			TopOffenders: []OffenderEntry{
				{OriginASN: 100, Count: 2, Posture: "origin-invalid"},
				{OriginASN: 200, Count: 1, Posture: "origin-invalid"},
				{OriginASN: 300, Count: 1, Posture: "origin-invalid"},
			},
		}
		recs := generateRecommendations(report)
		found := false
		for _, r := range recs {
			if strings.Contains(r, "persistent offender") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected persistent offender recommendation, got %v", recs)
		}
	})
}
