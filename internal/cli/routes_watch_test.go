package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// runCLI runs the raven CLI with args against srv and returns its stdout.
func runCLI(t *testing.T, srv *httptest.Server, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	rootCmd.SetArgs(append(args, "--address", strings.TrimPrefix(srv.URL, "http://")))
	runErr := rootCmd.Execute()
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	rootCmd.SetArgs(nil)
	if runErr != nil {
		t.Fatalf("raven %v: %v", args, runErr)
	}
	return string(out)
}

// runWatchOnce runs raven watch --once with args against srv, whose stream
// ends, and returns its stdout. Since #81 that end is an error.
func runWatchOnce(t *testing.T, srv *httptest.Server, args ...string) string {
	t.Helper()
	addr := strings.TrimPrefix(srv.URL, "http://")
	cmd := newWatchCmd(&addr)
	var stdout, stderr strings.Builder
	cmd.SetArgs(append(args, "--once"))
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	// Bounded, so a --once that reconnects fails here instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err == nil || !strings.Contains(err.Error(), "ended") {
		t.Fatalf("raven watch --once %v: %v, want the stream-ended error", args, err)
	}
	return stdout.String()
}

// raven watch sends every filter it is given; it used to send only --posture.
func TestWatchSendsAllFilters(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
	}))
	defer srv.Close()
	runWatchOnce(t, srv, "--prefix", "1.1.1.0/24", "--origin-asn", "13335",
		"--peer", "80.81.194.180", "--posture", "secured", "--router", "br1.nyc", "--rib", "loc-rib")
	want := url.Values{"prefix": {"1.1.1.0/24"}, "origin-asn": {"13335"}, "peer": {"80.81.194.180"},
		"posture": {"secured"}, "router": {"br1.nyc"}, "rib": {"loc-rib"}}
	if got.Encode() != want.Encode() {
		t.Errorf("watch query = %q, want %q", got.Encode(), want.Encode())
	}
}

// raven watch shows each route's ASPA state and, for an ASPA Invalid, the
// failing hop as hop(customer→provider); a route with no failing hop has none.
func TestWatchShowsFailingHop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `data: {"prefix":"104.16.0.0/13","peer":"192.0.2.1","origin_asn":13335,`+
			`"as_path":[1031,262504,53072,7738,13335],"rov":"NotFound","aspa":"Invalid",`+
			`"aspa_failing_hop":{"customer_asn":53072,"provider_asn":262504},"posture":"path-suspect"}`+"\n\n")
		io.WriteString(w, `data: {"prefix":"1.1.1.0/24","peer":"192.0.2.1","origin_asn":13335,`+
			`"as_path":[174,13335],"rov":"Valid","aspa":"Unknown","posture":"origin-only"}`+"\n\n")
	}))
	defer srv.Close()
	out := runWatchOnce(t, srv)
	want := []string{
		"[path-suspect] 104.16.0.0/13 via 192.0.2.1 origin:AS13335 AS_PATH:[1031 262504 53072 7738 13335] " +
			"rov:NotFound ASPA:Invalid hop(53072→262504) posture:path-suspect",
		"[origin-only] 1.1.1.0/24 via 192.0.2.1 origin:AS13335 AS_PATH:[174 13335] " +
			"rov:Valid ASPA:Unknown posture:origin-only",
	}
	// stdout is the events alone: the banner went to stderr (#81).
	got := strings.Split(strings.TrimSpace(out), "\n")
	if len(got) != len(want) {
		t.Fatalf("watch output:\n%s", out)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("watch line %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

// raven routes sends --peer with --prefix, and --format wide shows the
// failing ASPA hop as C->P, or "-" when there is none.
func TestRoutesPeerAndFailingHop(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		io.WriteString(w, `[
 {"prefix":"145.102.136.0/22","peer":"80.81.194.180","origin_asn":1199,"rov":"Valid","aspa":"Invalid",
  "posture":"path-suspect","aspa_procedure":"upstream","aspa_procedure_source":"default",
  "aspa_failing_hop":{"customer_asn":1199,"provider_asn":65000}},
 {"prefix":"1.1.1.0/24","peer":"80.81.194.180","origin_asn":13335,"rov":"Valid","aspa":"Valid",
  "posture":"secured","aspa_procedure":"upstream","aspa_procedure_source":"default"}]`)
	}))
	defer srv.Close()
	out := runCLI(t, srv, "routes", "--prefix", "1.1.1.0/24", "--peer", "80.81.194.180", "--router", "192.0.2.1", "--format", "wide")
	if got.Get("prefix") != "1.1.1.0/24" || got.Get("peer") != "80.81.194.180" || got.Get("router") != "192.0.2.1" {
		t.Errorf("routes query = %q, want prefix, peer and router", got.Encode())
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasSuffix(strings.TrimSpace(lines[0]), "FAILING HOP") ||
		!strings.HasSuffix(strings.TrimSpace(lines[1]), "1199->65000") || !strings.HasSuffix(strings.TrimSpace(lines[2]), "-") {
		t.Errorf("wide output:\n%s", out)
	}
	runCLI(t, srv, "routes", "--prefix", "", "--peer", "", "--router", "", "--format", "table")
}

// raven status and raven peers show each peer per router, with its count
// there; two routers with the same route-server peer are two rows.
func TestStatusAndPeersShowRouter(t *testing.T) {
	peers := `[{"router":"192.0.2.1","router_name":"br1.nyc","addr":"80.81.194.180","asn":6695,"state":"up","route_count":12},
 {"router":"192.0.2.2","addr":"80.81.194.180","asn":6695,"state":"up","route_count":34},
 {"router":"192.0.2.1","router_name":"br1.nyc","peer_distinguisher":"65000:100","addr":"80.81.194.180","asn":6695,"state":"up","route_count":5}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status" {
			io.WriteString(w, `{"version":"t","uptime":"1s","bmp_peers":`+peers+`}`)
			return
		}
		io.WriteString(w, peers)
	}))
	defer srv.Close()
	for _, cmd := range []string{"status", "peers"} {
		out := runCLI(t, srv, cmd)
		if !strings.Contains(out, "ROUTER") {
			t.Errorf("%s has no ROUTER column:\n%s", cmd, out)
		}
		for _, row := range [][]string{{"br1.nyc", "80.81.194.180", "12"}, {"192.0.2.2", "80.81.194.180", "34"}, {"br1.nyc", "80.81.194.180 rd 65000:100", "5"}} {
			found := false
			for _, line := range strings.Split(out, "\n") {
				f := strings.Join(strings.Fields(line), " ")
				if strings.HasPrefix(f, row[0]+" "+row[1]+" ") && strings.Contains(f, " "+row[2]) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: no row for %v:\n%s", cmd, row, out)
			}
		}
	}
}

// raven routes and raven watch send --rib when given. Without it they send
// none, and the daemon lists its default view (adj-rib-in-pre and loc-rib):
// a router that sends only its Loc-RIB must not show an empty table.
func TestRoutesRIBFlag(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	runCLI(t, srv, "routes")
	if _, ok := got["rib"]; ok {
		t.Errorf("default rib = %q, want none sent", got.Get("rib"))
	}
	runCLI(t, srv, "routes", "--rib", "adj-rib-out-post")
	if got.Get("rib") != "adj-rib-out-post" {
		t.Errorf("rib = %q, want adj-rib-out-post", got.Get("rib"))
	}
	runCLI(t, srv, "routes", "--rib", "pre-policy,loc-rib")
	if got.Get("rib") != "pre-policy,loc-rib" {
		t.Errorf("rib = %q, want pre-policy,loc-rib", got.Get("rib"))
	}
	runCLI(t, srv, "routes", "--rib", "") // flags outlive a run
}

// raven peers shows a MALFORMED column, with the reason, only when a peer
// is marked for malformed input.
func TestPeersMalformedColumn(t *testing.T) {
	peers := `[{"router":"192.0.2.1","addr":"80.81.194.180","asn":6695,"state":"up","route_count":12,
  "malformed_input":true,"malformed_reason":"nlri"},
 {"router":"192.0.2.1","addr":"80.81.194.181","asn":6695,"state":"up","route_count":3}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, peers)
	}))
	defer srv.Close()
	lines := strings.Split(strings.TrimSpace(runCLI(t, srv, "peers")), "\n")
	if len(lines) != 3 || !strings.HasSuffix(strings.TrimSpace(lines[0]), "MALFORMED") ||
		!strings.HasSuffix(strings.TrimSpace(lines[1]), "nlri") || !strings.HasSuffix(strings.TrimSpace(lines[2]), "-") {
		t.Errorf("peers output:\n%s", strings.Join(lines, "\n"))
	}
	peers = `[{"router":"192.0.2.1","addr":"80.81.194.181","asn":6695,"state":"up","route_count":3}]`
	if out := runCLI(t, srv, "peers"); strings.Contains(out, "MALFORMED") {
		t.Errorf("MALFORMED column with no marked peer:\n%s", out)
	}
}

// raven validate rejects --origin-asn and --rtr, which it used to accept and
// ignore, until one-shot RTR validation exists; --prefix alone still works.
func TestValidateRejectsUnsupportedFlags(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	if out := runCLI(t, srv, "validate", "--prefix", "1.1.1.0/24"); !strings.Contains(out, "no routes found") || calls != 1 {
		t.Fatalf("--prefix alone: %d API calls, output %q", calls, out)
	}
	for _, args := range [][]string{
		{"--prefix", "1.1.1.0/24", "--origin-asn", "13335"},
		{"--prefix", "1.1.1.0/24", "--rtr", "rpki.example.net:3323"},
		{"--prefix", "1.1.1.0/24", "--origin-asn", "0"},
	} {
		rootCmd.SetArgs(append(append([]string{"validate"}, args...), "--address", strings.TrimPrefix(srv.URL, "http://")))
		err := rootCmd.Execute()
		rootCmd.SetArgs(nil)
		for _, name := range []string{"origin-asn", "rtr"} {
			f := validateCmd.Flags().Lookup(name)
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		}
		if err == nil || !strings.Contains(err.Error(), "not supported yet; validate reads the running daemon's routes for --prefix") {
			t.Errorf("validate %v: err %v, want the not-supported error", args, err)
		}
	}
	if calls != 1 {
		t.Errorf("%d API calls, want none for the rejected runs", calls-1)
	}
}

// raven status and raven peers send --router (an address or sysName),
// which the API matches as routes and watch do.
func TestStatusAndPeersSendRouter(t *testing.T) {
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got[r.URL.Path] = r.URL.Query().Get("router")
		if r.URL.Path == "/api/v1/status" {
			io.WriteString(w, `{"version":"t","uptime":"1s","bmp_peers":[]}`)
			return
		}
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	runCLI(t, srv, "status", "--router", "br1.nyc")
	runCLI(t, srv, "peers", "--router", "192.0.2.1")
	if got["/api/v1/status"] != "br1.nyc" || got["/api/v1/peers"] != "192.0.2.1" {
		t.Errorf("router sent: %v", got)
	}
	runCLI(t, srv, "status", "--router", "")
	runCLI(t, srv, "peers", "--router", "")
	if got["/api/v1/status"] != "" || got["/api/v1/peers"] != "" {
		t.Errorf("router sent without --router: %v", got)
	}
}
