package cli

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// raven routes and raven watch send --afi to the daemon, which filters
// (it is not a client-side filter), as ipv4 or ipv6 whichever form was
// typed; a bad value fails before any request.
func TestRoutesAndWatchSendAFI(t *testing.T) {
	var got []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Query())
		if r.URL.Path == "/api/v1/routes" {
			w.Write([]byte("[]"))
		}
	}))
	t.Cleanup(srv.Close) // after the flag reset below: cleanups run last first
	t.Cleanup(func() {
		runCLI(t, srv, "routes", "--afi", "")
		runCLI(t, srv, "watch", "--afi", "", "--posture", "")
	})

	runCLI(t, srv, "routes", "--afi", "v6")
	runCLI(t, srv, "watch", "--afi", "ipv4", "--posture", "secured")
	if len(got) != 2 || got[0].Get("afi") != "ipv6" || got[1].Get("afi") != "ipv4" || got[1].Get("posture") != "secured" {
		t.Fatalf("queries %v, want afi=ipv6 then afi=ipv4 with posture", got)
	}

	got = nil
	rootCmd.SetArgs([]string{"routes", "--afi", "ipx", "--address", strings.TrimPrefix(srv.URL, "http://")})
	err := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	if err == nil || !strings.Contains(err.Error(), "--afi") || len(got) != 0 {
		t.Errorf("--afi ipx: err %v, %d requests; want an --afi error and none", err, len(got))
	}
}
