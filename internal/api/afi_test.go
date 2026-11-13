package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// afiFixture holds IPv4 and IPv6 routes from one peer, and an IPv4-mapped
// IPv6 prefix, which is IPv6.
func afiFixture(t *testing.T) *Server {
	t.Helper()
	table := routetable.New()
	for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32", "::ffff:203.0.113.0/120"} {
		table.Insert(&types.Route{
			PeerAddr: netip.MustParseAddr("192.0.2.1"),
			Prefix:   netip.MustParsePrefix(p),
			ASPath:   []uint32{64500, 64501},
			RIBType:  types.AdjRIBInPre,
		})
	}
	return NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
}

// The afi parameter filters routes by address family on the daemon, alone
// and with the other filters; ipv4/ipv6 and the v4/v6 forms are accepted, a
// typo is a 400.
func TestRoutesAFI(t *testing.T) {
	s := afiFixture(t)
	for _, tc := range []struct {
		q    url.Values
		want []string
	}{
		{url.Values{"afi": {"ipv4"}}, []string{"192.0.2.0/24", "198.51.100.0/24"}},
		{url.Values{"afi": {"ipv6"}}, []string{"2001:db8::/32", "::ffff:203.0.113.0/120"}},
		{url.Values{"afi": {"v6"}}, []string{"2001:db8::/32", "::ffff:203.0.113.0/120"}},
		{url.Values{"afi": {"IPv4"}, "peer": {"192.0.2.1"}}, []string{"192.0.2.0/24", "198.51.100.0/24"}},
		{url.Values{"afi": {"ipv6"}, "prefix": {"192.0.2.0/24"}}, nil},
		{url.Values{"afi": {"ipv4"}, "prefix": {"192.0.0.0/16"}, "match": {"longer"}}, []string{"192.0.2.0/24"}},
		{url.Values{}, []string{"192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32", "::ffff:203.0.113.0/120"}},
	} {
		code, routes := getRoutes(t, s, tc.q)
		if code != http.StatusOK {
			t.Fatalf("%v: status %d", tc.q, code)
		}
		var got []string
		for _, r := range routes {
			got = append(got, r.Prefix)
		}
		slices.Sort(got)
		want := slices.Clone(tc.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%v: got %v, want %v", tc.q, got, want)
		}
	}
	if code, _ := getRoutes(t, s, url.Values{"afi": {"ipv5"}}); code != http.StatusBadRequest {
		t.Errorf("afi=ipv5: status %d, want 400", code)
	}
}

// raven watch applies afi to the stream, on the daemon.
func TestWatchAFI(t *testing.T) {
	s := afiFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(s.handleWatch))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"?afi=ipv6", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for {
		s.watchMu.RLock()
		n := len(s.watchSubs)
		s.watchMu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	route := func(prefix string) *types.Route {
		return &types.Route{PeerAddr: netip.MustParseAddr("192.0.2.1"), Prefix: netip.MustParsePrefix(prefix), ASPath: []uint32{64500, 64501}}
	}
	s.NotifyRoute(route("192.0.2.0/24"))  // IPv4: filtered out
	s.NotifyRoute(route("2001:db8::/32")) // the match
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var rr RouteResponse
		if err := json.Unmarshal([]byte(line), &rr); err != nil {
			t.Fatal(err)
		}
		if rr.Prefix != "2001:db8::/32" {
			t.Fatalf("watch delivered %s, which afi=ipv6 excludes", rr.Prefix)
		}
		return
	}
	t.Fatalf("no event: %v", sc.Err())
}
