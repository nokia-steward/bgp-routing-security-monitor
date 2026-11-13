package server

import (
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

// #66 in serve: a VRP the cache announces twice counts once in the VRP
// store, /api/v1/status and raven_rtr_vrp_count, and the duplicate counts in
// raven_rtr_protocol_errors_total{cache,code="7"}: once in the first full
// sync, once in the self-healing resync's (whose own fault, within 5
// minutes, sets off no other).
func TestServeDuplicateVRPCountedOnce(t *testing.T) {
	vrps := rtrtest.GenVRPs(0, 4, 65001)
	h := startE2E(t, e2eConfig{vrps: vrps, repeat: vrps[:1]})
	h.ready()
	if got := h.status().RTR.VRPCount; got != 4 {
		t.Errorf("status vrp_count %d, want 4", got)
	}
	if got := rtrtest.Gauge("raven_rtr_vrp_count", h.cache.Addr()); got != 4 {
		t.Errorf("raven_rtr_vrp_count %v, want 4", got)
	}
	waitUntil(t, "the resync's full sync", func() bool {
		return rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.cache.Addr()) == 2
	})
	if got := h.status().RTR.VRPCount; got != 4 {
		t.Errorf("after the resync status vrp_count %d, want 4", got)
	}
}
