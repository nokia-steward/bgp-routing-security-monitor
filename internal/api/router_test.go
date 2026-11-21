package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/bmp"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// fakeRouters names routers as BMP Initiation would.
type fakeRouters map[netip.Addr]string

func (f fakeRouters) RouterName(a netip.Addr) string { return f[a] }
func (f fakeRouters) RoutersNamed(n string) []netip.Addr {
	var out []netip.Addr
	for a, name := range f {
		if name == n {
			out = append(out, a)
		}
	}
	return out
}

func TestRouterFilterAndFields(t *testing.T) {
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	peer := netip.MustParseAddr("80.81.194.180")
	table := routetable.New()
	for _, r := range []netip.Addr{a, b, c} {
		table.Insert(&types.Route{Router: r, PeerAddr: peer, Prefix: netip.MustParsePrefix("1.1.1.0/24"),
			ASPath: []uint32{6695, 13335}, RIBType: types.AdjRIBInPre})
	}
	table.Insert(&types.Route{Router: a, PeerDistinguisher: 0x0000fde8_00000064, PeerAddr: peer, PathID: 2,
		Prefix: netip.MustParsePrefix("8.8.8.0/24"), ASPath: []uint32{6695, 15169}, RIBType: types.AdjRIBInPre})
	s := NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	s.routers = fakeRouters{a: "br1.nyc", b: "br2.nyc"} // c sent no sysName

	count := func(q url.Values) int {
		_, rs := getRoutes(t, s, q)
		return len(rs)
	}
	for _, tc := range []struct {
		q    url.Values
		want int
	}{
		{url.Values{"router": {"192.0.2.1"}}, 2},
		{url.Values{"router": {"::ffff:192.0.2.1"}}, 2},
		{url.Values{"router": {"br1.nyc"}}, 2},
		{url.Values{"router": {"br2.nyc"}}, 1},
		{url.Values{"router": {"br9.nowhere"}}, 0},
		{url.Values{"router": {"br1.nyc"}, "prefix": {"1.1.1.0/24"}}, 1},
		{url.Values{"router": {"192.0.2.3"}, "peer": {"80.81.194.180"}}, 1},
		{url.Values{"prefix": {"1.1.1.0/24"}}, 3},
	} {
		if got := count(tc.q); got != tc.want {
			t.Errorf("%v: %d routes, want %d", tc.q, got, tc.want)
		}
	}

	_, rs := getRoutes(t, s, url.Values{"router": {"br1.nyc"}, "prefix": {"8.8.8.0/24"}})
	b2, _ := json.Marshal(rs[0])
	for _, want := range []string{`"router":"192.0.2.1"`, `"router_name":"br1.nyc"`, `"peer_distinguisher":"65000:100"`, `"path_id":2`} {
		if !strings.Contains(string(b2), want) {
			t.Errorf("route JSON %s lacks %s", b2, want)
		}
	}
	_, rs = getRoutes(t, s, url.Values{"router": {"192.0.2.3"}})
	b3, _ := json.Marshal(rs[0])
	for _, absent := range []string{"router_name", "peer_distinguisher", "path_id"} {
		if strings.Contains(string(b3), absent) {
			t.Errorf("route JSON %s has %s, which should be omitted", b3, absent)
		}
	}
}

func TestFormatRD(t *testing.T) {
	for rd, want := range map[uint64]string{
		0:                     "",
		0x0000_fde8_00000064:  "65000:100",
		0x0001_c0000201_0064:  "192.0.2.1:100",
		0x0002_0001_0001_0064: "65537L:100",
		// Type 0 and type 2 RDs with the same numbers stay apart.
		0x0002_0000_fde8_0064: "65000L:100",
		0x0009_0000_0000_0001: "0x0009000000000001",
	} {
		if got := FormatRD(rd); got != want {
			t.Errorf("FormatRD(%#x) = %q, want %q", rd, got, want)
		}
	}
}

type fakePeers []bmp.Peer

func (f fakePeers) GetPeers() []bmp.Peer { return f }

// /api/v1/peers and /api/v1/status take router like routes and watch: an
// address (either IPv4 form) or a BMP sysName, listing only that router's
// peers. Status totals stay daemon-wide.
func TestPeersAndStatusRouterFilter(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	s := NewServer(routetable.New(), nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	s.routers = fakeRouters{a: "br1.nyc", b: "br2.nyc"}
	s.bmpPeers = fakePeers{
		{Router: a, Addr: netip.MustParseAddr("80.81.194.180"), State: "up"},
		{Router: a, Addr: netip.MustParseAddr("80.81.194.181"), State: "up"},
		{Router: b, Addr: netip.MustParseAddr("80.81.194.180"), State: "up"},
	}
	for _, tc := range []struct {
		router string
		want   int
	}{{"", 3}, {"192.0.2.1", 2}, {"::ffff:192.0.2.1", 2}, {"br1.nyc", 2}, {"br2.nyc", 1}, {"br9.nowhere", 0}} {
		q := url.Values{}
		if tc.router != "" {
			q.Set("router", tc.router)
		}
		rec := httptest.NewRecorder()
		s.handlePeers(rec, httptest.NewRequest(http.MethodGet, "/api/v1/peers?"+q.Encode(), nil))
		var peers []PeerResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &peers); err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		s.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status?"+q.Encode(), nil))
		var status StatusResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if len(peers) != tc.want || len(status.BMP) != tc.want {
			t.Errorf("router %q: peers %d, status peers %d, want %d", tc.router, len(peers), len(status.BMP), tc.want)
		}
	}
}
