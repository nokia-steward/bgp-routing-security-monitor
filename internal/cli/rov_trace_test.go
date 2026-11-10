package cli

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation"
	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
)

// productionAPI is a real API server over the production report's route,
// 94.177.129.126/32 from AS202744 under VRP 94.177.129.0/24-24 AS202744,
// plus a NotFound route, validated by the engine.
func productionAPI(t *testing.T) *httptest.Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	vs := store.NewVRPStore()
	vs.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("94.177.129.0/24"), ASN: 202744, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("94.176.0.0/14"), ASN: 64511, MaxLength: 24},
	}, 1, 1)
	table := routetable.New()
	e := validation.NewEngine(vs, store.NewASPAStore(), nil, table, log)
	for _, r := range []*types.Route{
		{
			Router: netip.MustParseAddr("192.0.2.3"), PeerAddr: netip.MustParseAddr("80.81.194.180"), PeerASN: 6695,
			Prefix: netip.MustParsePrefix("94.177.129.126/32"), ASPath: []uint32{6695, 202744},
			NextHop:          netip.MustParseAddr("80.81.194.180"),
			Communities:      []types.Community{{High: 6695, Low: 1911}, types.CommunityBlackhole},
			LargeCommunities: []types.LargeCommunity{{GlobalAdmin: 6695, LocalData1: 1911, LocalData2: 172}},
		},
		{
			Router: netip.MustParseAddr("192.0.2.3"), PeerAddr: netip.MustParseAddr("80.81.194.180"), PeerASN: 6695,
			Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{6695, 64500},
			NextHop: netip.MustParseAddr("80.81.194.180"),
		},
	} {
		e.ValidateRoute(r)
		table.Insert(r)
	}
	srv := httptest.NewServer(api.NewServer(table, nil, vs, log, "test").Mux())
	t.Cleanup(srv.Close)
	return srv
}

// --format wide shows the VRP that decided each route's ROV, "-" when none
// did; --format table does not.
func TestRoutesWideVRPColumn(t *testing.T) {
	srv := productionAPI(t)
	wide := runCLI(t, srv, "routes", "--prefix", "94.177.129.126/32", "--format", "wide")
	t.Logf("raven routes --prefix 94.177.129.126/32 --format wide:\n%s", wide)
	lines := strings.Split(strings.TrimSpace(wide), "\n")
	if len(lines) != 2 {
		t.Fatalf("wide output:\n%s", wide)
	}
	header, row := strings.Fields(lines[0]), lines[1]
	if header[8] != "VRP" {
		t.Errorf("header %q: want VRP after POSTURE", lines[0])
	}
	if !strings.Contains(row, "Invalid") || !strings.Contains(row, "  94.177.129.0/24-24 AS202744  ") {
		t.Errorf("row %q: want Invalid and VRP 94.177.129.0/24-24 AS202744", row)
	}

	nf := runCLI(t, srv, "routes", "--prefix", "203.0.113.0/24", "--format", "wide")
	lines = strings.Split(strings.TrimSpace(nf), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "NotFound") {
		t.Fatalf("not-found output:\n%s", nf)
	}
	// The VRP column is the one after POSTURE.
	if f := strings.Fields(lines[1]); f[8] != "-" {
		t.Errorf("not-found VRP column %q, want -: %q", f[8], lines[1])
	}

	table := runCLI(t, srv, "routes", "--prefix", "94.177.129.126/32", "--format", "table")
	if strings.Contains(table, "VRP") || strings.Contains(table, "94.177.129.0/24-24") {
		t.Errorf("table output has the VRP column:\n%s", table)
	}
	json := runCLI(t, srv, "routes", "--prefix", "94.177.129.126/32", "--format", "json")
	t.Logf("raven routes --prefix 94.177.129.126/32 --format json:\n%s", json)
	for _, want := range []string{`"rov_reason_code": "invalid_length"`, `"communities": [`, `"65535:666"`, `"6695:1911:172"`,
		`"rov_reason": "prefix length /32 exceeds maxLength /24 of VRP 94.177.129.0/24 AS202744"`} {
		if !strings.Contains(json, want) {
			t.Errorf("json output lacks %s", want)
		}
	}
	runCLI(t, srv, "routes", "--prefix", "", "--format", "table")
}

// --match is sent only with a value other than exact, and needs --prefix.
func TestRoutesMatchFlag(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		io.WriteString(w, "[]")
	}))
	defer srv.Close()
	defer runCLI(t, srv, "routes", "--prefix", "", "--match", "exact")
	for _, m := range []string{"covering", "longer"} {
		runCLI(t, srv, "routes", "--prefix", "10.0.0.0/8", "--match", m)
		if got.Get("match") != m || got.Get("prefix") != "10.0.0.0/8" {
			t.Errorf("--match %s: query %q", m, got.Encode())
		}
	}
	runCLI(t, srv, "routes", "--prefix", "10.0.0.0/8", "--match", "exact")
	if _, ok := got["match"]; ok {
		t.Errorf("--match exact sent match: %q", got.Encode())
	}
	for _, args := range [][]string{
		{"routes", "--prefix", "", "--match", "covering"},
		{"routes", "--prefix", "10.0.0.0/8", "--match", "supernets"},
	} {
		rootCmd.SetArgs(append(args, "--address", strings.TrimPrefix(srv.URL, "http://")))
		err := rootCmd.Execute()
		rootCmd.SetArgs(nil)
		if err == nil {
			t.Errorf("raven %v: no error", args)
		}
	}
}

// The reject-invalid summary breaks rejections down by reason code, counts
// BLACKHOLE routes, and its top-origins REASON column gives the codes.
func TestPrintRejectInvalidReasons(t *testing.T) {
	r := &whatif.RejectInvalidResult{
		TotalRoutes: 10, RejectedRoutes: 4, AffectedPrefixes: 3, AffectedOrigins: 2,
		ByReason: []whatif.ReasonImpact{
			{ReasonCode: "invalid_length", RouteCount: 3, PrefixCount: 2},
			{ReasonCode: "invalid_origin", RouteCount: 1, PrefixCount: 1},
		},
		BlackholeRoutes: 2, BlackholePrefixes: 1,
		TopOrigins: []whatif.OriginImpact{
			{OriginASN: 202744, RouteCount: 3, PrefixCount: 2, ReasonCode: "invalid_length",
				Reason:      "prefix length /32 exceeds maxLength /24 of VRP 94.177.129.0/24 AS202744",
				ReasonCodes: map[string]int{"invalid_length": 2, "invalid_origin": 1}},
			{OriginASN: 64666, RouteCount: 1, PrefixCount: 1, ReasonCode: "invalid_origin",
				ReasonCodes: map[string]int{"invalid_origin": 1}},
		},
	}
	var b bytes.Buffer
	printRejectInvalidResult(&b, r, "table")
	out := b.String()
	t.Logf("what-if --reject-invalid:\n%s", out)
	for _, want := range []string{
		"Carrying BLACKHOLE (RFC 7999): 2 routes, 1 prefixes",
		"REJECTED BY ROV REASON",
		"invalid_length   3        2",
		"invalid_origin   1        1",
		"AS202744     3        2          invalid_length (2), invalid_origin (1)",
		"AS64666      1        1          invalid_origin",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, "not authorized by any covering VRP") {
		t.Errorf("REASON column shows the old origin-mismatch text:\n%s", out)
	}
}
