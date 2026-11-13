package server

import (
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/bmp/bmptest"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// The Fort 1.7.0 pattern through serve: a delta that announces VRPs the
// cache holds and withdraws them in the same answer changes nothing, so the
// routes they validate stay Valid; and while the self-healing resync it sets
// off is in flight (its Reset Query left unanswered here), routes validated
// meanwhile still see those VRPs. raven watch shows no Valid -> NotFound for
// them, and the VRP count never dips.
func TestResyncKeepsVRPsForRoutes(t *testing.T) {
	var vrps []rtrtest.VRP
	var prefixes []netip.Prefix
	for k := 0; k < 10; k++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(k), 0}), 24)
		vrps = append(vrps, rtrtest.VRP{Prefix: p, MaxLen: 24, ASN: 64500})
		prefixes = append(prefixes, p)
	}
	h := startE2E(t, e2eConfig{vrps: vrps})
	h.ready()
	var routes []bmptest.Route
	for _, p := range prefixes {
		routes = append(routes, bmptest.Route{Prefix: p, ASPath: []uint32{64501, 64500}})
	}
	h.announce(routes...)
	for _, p := range prefixes {
		if r := h.route(p); r.ROV.State != types.ROVValid {
			t.Fatalf("%s is %s before the delta, want Valid", p, r.ROV.State)
		}
	}
	w := h.watch("")

	// The delta is answered; the Reset Query after it is not: the resync
	// stays in flight for the rest of the test.
	h.cache.Then(rtrtest.Answer, rtrtest.Stall)
	added := rtrtest.VRP{Prefix: netip.MustParsePrefix("10.1.0.0/24"), MaxLen: 24, ASN: 64500}
	h.rtrUpdate(rtrtest.Delta{AnnounceVRPs: []rtrtest.VRP{added}, Reannounce: vrps[:5]})
	waitUntil(t, "the self-healing Reset Query", func() bool {
		n := 0
		for _, q := range h.cache.Received() {
			if q.Type == rtrtest.PDUResetQuery {
				n++
			}
		}
		return n == 2
	})
	if got := h.status().RTR.VRPCount; got != 11 {
		t.Errorf("during the resync vrp_count %d, want 11", got)
	}

	// Routes validated during the resync: new paths for the re-announced
	// prefixes, validated on ingest.
	for _, p := range prefixes[:5] {
		h.feed.Announce(h.peer, bmptest.Route{Prefix: p, ASPath: []uint32{64501, 64502, 64500}})
	}
	for _, p := range prefixes[:5] {
		waitUntil(t, "the new path for "+p.String(), func() bool { r := h.route(p); return r != nil && len(r.ASPath) == 3 })
	}
	h.sendMarker(1)
	evs := w.until(t)
	for _, p := range prefixes[:5] {
		for _, e := range forWatchPrefix(evs, p) {
			if e.ROV != "Valid" {
				t.Errorf("watch: %s became %s during the resync, want Valid throughout", p, e.ROV)
			}
		}
		if r := h.route(p); r.ROV.State != types.ROVValid {
			t.Errorf("%s is %s during the resync, want Valid", p, r.ROV.State)
		}
	}
}
