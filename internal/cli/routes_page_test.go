package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// raven routes sends --limit and --after as the API's limit and after.
func TestRoutesSendsPage(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		io.WriteString(w, "[]")
	}))
	t.Cleanup(srv.Close) // after the flag reset below: cleanups run last first
	t.Cleanup(func() { runCLI(t, srv, "routes", "--limit", "0", "--after", "") })

	runCLI(t, srv, "routes", "--posture", "origin-only", "--limit", "1000", "--after", "Y3Vyc29y")
	if got.Get("limit") != "1000" || got.Get("after") != "Y3Vyc29y" || got.Get("posture") != "origin-only" {
		t.Errorf("routes query = %q, want limit, after and posture", got.Encode())
	}
	runCLI(t, srv, "routes", "--posture", "", "--limit", "0", "--after", "")
	if got.Has("limit") || got.Has("after") {
		t.Errorf("routes query = %q, want no limit or after", got.Encode())
	}
}

// The hint names the --after of the next page, from the Link header, and
// is empty on the last page.
func TestNextPageHint(t *testing.T) {
	h := http.Header{}
	if got := nextPageHint(h); got != "" {
		t.Errorf("no Link: %q, want none", got)
	}
	h.Set("Link", `</api/v1/routes?after=Y3Vyc29y&limit=2&posture=origin-only>; rel="next"`)
	if got, want := nextPageHint(h), "more routes: list the next page with --after Y3Vyc29y"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A negative --limit is refused before any request.
func TestRoutesRefusesNegativeLimit(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		io.WriteString(w, "[]")
	}))
	t.Cleanup(srv.Close) // after the flag reset below: cleanups run last first
	t.Cleanup(func() { runCLI(t, srv, "routes", "--limit", "0") })

	rootCmd.SetArgs([]string{"routes", "--limit", "-1", "--address", strings.TrimPrefix(srv.URL, "http://")})
	err := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	if err == nil || !strings.Contains(err.Error(), "--limit") || requests != 0 {
		t.Errorf("--limit -1: err %v, %d requests; want a --limit error and none", err, requests)
	}
}
