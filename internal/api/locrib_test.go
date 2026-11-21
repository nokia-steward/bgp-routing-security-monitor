package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/audit"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/bmp"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// A Loc-RIB instance is listed with its peer type and table name, and its
// route_count is its Loc-RIB routes (its default-view routes), not 0.
func TestPeersLocRIB(t *testing.T) {
	router := netip.MustParseAddr("192.0.2.1")
	zero := netip.IPv4Unspecified()
	bgp := netip.MustParseAddr("10.0.12.1")
	table := routetable.New()
	for _, p := range []string{"1.1.1.0/24", "8.8.8.0/24"} {
		table.Insert(&types.Route{Router: router, PeerType: types.PeerTypeLocRIB, PeerAddr: zero,
			Prefix: netip.MustParsePrefix(p), RIBType: types.LocRIB})
	}
	for _, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost} {
		table.Insert(&types.Route{Router: router, PeerAddr: bgp, Prefix: netip.MustParsePrefix("1.1.1.0/24"), RIBType: rib})
	}
	s := NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	s.bmpPeers = fakePeers{
		{Router: router, PeerType: bmp.PeerTypeLocRIB, Addr: zero, ASN: 65000, TableName: "global", State: "up"},
		{Router: router, PeerType: bmp.PeerTypeGlobal, Addr: bgp, ASN: 65000, State: "up"},
	}
	rec := httptest.NewRecorder()
	s.handlePeers(rec, httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil))
	var peers []PeerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &peers); err != nil {
		t.Fatal(err)
	}
	got := map[string]PeerResponse{}
	for _, p := range peers {
		got[p.PeerType] = p
	}
	if p := got["loc-rib"]; p.Addr != "0.0.0.0" || p.TableName != "global" || p.RouteCount != 2 || p.RoutesByRIB["loc-rib"] != 2 {
		t.Errorf("Loc-RIB peer %+v, want 0.0.0.0, table global, route_count 2", p)
	}
	if p := got["global"]; p.RouteCount != 1 || p.RoutesByRIB["adj-rib-in-post"] != 1 {
		t.Errorf("BGP peer %+v, want route_count 1 (pre-policy) and its post-policy in routes_by_rib", p)
	}
}

// /api/v1/audit audits one RIB: adj-rib-in-pre by default, another by name
// or alias; an unknown RIB is a 400. A Loc-RIB is audited by its router.
func TestAuditRIBParameter(t *testing.T) {
	router := netip.MustParseAddr("192.0.2.1")
	peer := netip.MustParseAddr("10.0.12.1")
	table := routetable.New()
	for _, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost} {
		table.Insert(&types.Route{Router: router, PeerAddr: peer, Prefix: netip.MustParsePrefix("1.1.1.0/24"), RIBType: rib})
	}
	for _, p := range []string{"1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"} {
		table.Insert(&types.Route{Router: router, PeerType: types.PeerTypeLocRIB, PeerAddr: netip.IPv4Unspecified(),
			Prefix: netip.MustParsePrefix(p), RIBType: types.LocRIB})
	}
	mux := http.NewServeMux()
	NewAuditHandler(table).RegisterRoutes(mux)
	get := func(q string) (int, audit.RouterAuditReport) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit?"+q, nil))
		var rep audit.RouterAuditReport
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, rep
	}
	for q, want := range map[string]struct {
		rib    string
		routes int
	}{
		"router=10.0.12.1":                     {"adj-rib-in-pre", 1},
		"router=10.0.12.1&rib=pre-policy":      {"adj-rib-in-pre", 1},
		"router=10.0.12.1&rib=post-policy":     {"adj-rib-in-post", 1},
		"router=10.0.12.1&rib=adj-rib-in-post": {"adj-rib-in-post", 1},
		"router=192.0.2.1&rib=loc-rib":         {"loc-rib", 3},
	} {
		code, rep := get(q)
		if code != http.StatusOK || rep.RIB != want.rib || rep.TotalRoutes != want.routes {
			t.Errorf("audit?%s: %d, rib %q, %d routes; want 200, %s, %d", q, code, rep.RIB, rep.TotalRoutes, want.rib, want.routes)
		}
	}
	if code, _ := get("router=10.0.12.1&rib=bogus"); code != http.StatusBadRequest {
		t.Errorf("unknown rib: %d, want 400", code)
	}
}
