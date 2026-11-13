package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
)

// what-if sends --rib to the daemon, refuses a RIB it cannot simulate on
// before any request, and both summaries say which RIBs they cover. A
// daemon older than --rib reports none, and the summary says so.
func TestWhatIfRIB(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		ribs, _ := whatif.ParseRIBs(r.URL.Query().Get("rib"))
		json.NewEncoder(w).Encode(map[string]any{"ribs": ribs.Names(), "total_routes": 1})
	}))
	t.Cleanup(srv.Close) // after the flag reset below: cleanups run last first
	t.Cleanup(func() { runCLI(t, srv, "what-if", "--reject-invalid", "--rib", "", "--aspa-enforce=false") })

	out := runCLI(t, srv, "what-if", "--reject-invalid", "--aspa-enforce", "--rib", "adj-rib-in-post")
	if len(got) != 2 || got[0].Get("rib") != "adj-rib-in-post" || got[1].Get("rib") != "adj-rib-in-post" {
		t.Fatalf("queries %v, want rib=adj-rib-in-post on both", got)
	}
	if n := strings.Count(out, "RIBs covered:                  adj-rib-in-post\n"); n != 2 {
		t.Errorf("%d RIBs covered lines naming adj-rib-in-post, want 2:\n%s", n, out)
	}

	got = nil
	out = runCLI(t, srv, "what-if", "--reject-invalid", "--aspa-enforce=false", "--rib", "")
	if got[0].Has("rib") || !strings.Contains(out, "RIBs covered:                  adj-rib-in-pre\n") {
		t.Errorf("default: query %v, output:\n%s\nwant no rib sent and adj-rib-in-pre covered", got[0], out)
	}

	got = nil
	rootCmd.SetArgs([]string{"what-if", "--reject-invalid", "--rib", "adj-rib-out-pre", "--address", strings.TrimPrefix(srv.URL, "http://")})
	err := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	if err == nil || !strings.Contains(err.Error(), "--rib") || len(got) != 0 {
		t.Errorf("--rib adj-rib-out-pre: err %v, %d requests; want a --rib error and none", err, len(got))
	}

	var b bytes.Buffer
	printRejectInvalidResult(&b, &whatif.RejectInvalidResult{TotalRoutes: 1}, "table")
	if !strings.Contains(b.String(), "RIBs covered:                  not reported") {
		t.Errorf("old daemon's result:\n%s", b.String())
	}
	b.Reset()
	printRejectInvalidResult(&b, &whatif.RejectInvalidResult{TotalRoutes: 1, RIBs: []string{"adj-rib-in-post"},
		ByPeer: []whatif.PeerImpact{{PeerAddr: "135.92.55.33", Total: 1}}}, "table")
	if !strings.Contains(b.String(), "raven routes --peer PEER --rib adj-rib-in-post") {
		t.Errorf("by-peer table does not say how to list a peer's routes:\n%s", b.String())
	}
}

// An empty raven routes --peer for a peer whose routes are all in other
// RIBs (AS38016's local-instance peer, post-policy only) says where they are
// and which --rib lists them.
func TestRoutesPeerHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"addr":"198.18.0.1","routes_by_rib":{"adj-rib-in-pre":5}},` +
			`{"addr":"135.92.55.33","peer_type":"local","route_count":0,"routes_by_rib":{"adj-rib-in-post":31}}]`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	want := "no routes from peer 135.92.55.33 in adj-rib-in-pre, loc-rib; it has 31 in adj-rib-in-post (list them with --rib adj-rib-in-post)"
	if got := peerRIBHint(addr, "135.92.55.33", ""); got != want {
		t.Errorf("hint\n got %q\nwant %q", got, want)
	}
	if got := peerRIBHint(addr, "135.92.55.33", "adj-rib-in-post"); got != "" {
		t.Errorf("hint with the right --rib: %q, want none", got)
	}
	if got := peerRIBHint(addr, "198.18.0.1", ""); got != "" {
		t.Errorf("hint for a peer with default-view routes: %q, want none", got)
	}
}
