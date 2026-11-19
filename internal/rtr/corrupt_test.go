package rtr

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// withLen cuts a PDU to n bytes and sets its header's length to n.
func withLen(b []byte, n int) []byte {
	b = slices.Clone(b[:n])
	binary.BigEndian.PutUint32(b[4:8], uint32(n))
	return b
}

// setBytes returns a copy of b with each (offset, value) pair applied.
func setBytes(b []byte, kv ...int) []byte {
	b = slices.Clone(b)
	for i := 0; i < len(kv); i += 2 {
		b[kv[i]] = byte(kv[i+1])
	}
	return b
}

type corruptCase struct {
	name  string
	pdu   []byte
	first string // what the error event's text must name
}

// corruptCases are PDUs the parsers reject. Offsets are past the 8-byte
// header: 9 is the prefix length, 10 the maxLength.
func corruptCases() []corruptCase {
	v4 := rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 65009)
	v6 := rtrtest.IPv6Prefix(2, true, netip.MustParsePrefix("2001:db8::/32"), 32, 65009)
	return []corruptCase{
		{"IPv4 prefix length 33", setBytes(v4, 9, 33, 10, 33), "IPv4 Prefix PDU (invalid prefix length 33"},
		{"IPv4 maxLength below prefix length", setBytes(v4, 10, 23), "IPv4 Prefix PDU (invalid max length 23"},
		{"IPv6 prefix length 129", setBytes(v6, 9, 129, 10, 129), "IPv6 Prefix PDU (invalid prefix length 129"},
		{"ASPA too short", withLen(rtrtest.ASPA(true, 64999), 8), "ASPA PDU (ASPA PDU too short: 0"},
		{"ASPA extra bytes", withLen(rtrtest.ASPA(true, 64999, 64501), 14), "ASPA PDU (ASPA PDU malformed: 2 extra bytes"},
	}
}

// A PDU the client cannot parse is a code 0 (Corrupt Data) client fault:
// it is skipped, the rest of the sync applies, one error event names it,
// and a Reset Query on the same session follows.
func TestCorruptDataFault(t *testing.T) {
	for _, tc := range corruptCases() {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHealHarness(t)
			s := rtrtest.GenVRPs(0, 5, 65001)
			good := rtrtest.GenVRPs(500, 1, 65009)
			want := vrpSet(append(slices.Clone(s), good...))
			h.srv.SetData(s, nil)
			h.start(t)
			h.synced(t)
			h.waitEvents(t, telemetry.EventSync, 1)
			before := rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.srv.Addr())

			h.srv.AdvanceWire([]rtrtest.WirePDU{
				{Announce: true, VRP: good[0]},
				{Raw: tc.pdu},
			}, append(slices.Clone(s), good...))
			h.srv.Notify()
			h.waitEvents(t, telemetry.EventSync, 2)
			if got := heldSet(h); !slices.Equal(got, want) {
				t.Errorf("after the faulty delta the store holds %d VRPs, want %d", len(got), len(want))
			}
			ev := errorsOf(h, errCodeCorruptData)
			if len(ev) != 1 || len(errorsOf(h, 6)) != 0 || len(errorsOf(h, 7)) != 0 {
				t.Fatalf("%d code 0 error events, want 1 (and no 6 or 7); events: %s", len(ev), h.summary())
			}
			checkClientError(t, ev[0], errCodeCorruptData, 1, tc.first)
			if got := rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.srv.Addr()) - before; got != 1 {
				t.Errorf("raven_rtr_protocol_errors_total rose by %v, want 1", got)
			}
			waitResets(t, h, 2)
			h.waitEvents(t, telemetry.EventSync, 3)
			if got := heldSet(h); !slices.Equal(got, want) {
				t.Errorf("after the resync the store holds %d VRPs, want %d", len(got), len(want))
			}
		})
	}
}

// A cache that keeps serving a corrupt PDU is resynced at most once per
// healEvery.
func TestCorruptDataResyncRateLimit(t *testing.T) {
	h, clk := newHealHarness(t)
	s := rtrtest.GenVRPs(0, 3, 65001)
	bad := corruptCases()[0].pdu
	h.srv.SetData(s, nil)
	h.start(t)
	h.synced(t)
	h.waitEvents(t, telemetry.EventSync, 1)

	h.srv.AdvanceWire([]rtrtest.WirePDU{{Raw: bad}}, s)
	h.srv.Notify()
	waitResets(t, h, 2)
	h.waitEvents(t, telemetry.EventSync, 3)

	clk.advance(4 * time.Minute)
	h.srv.AdvanceWire([]rtrtest.WirePDU{{Raw: bad}}, s)
	h.srv.Notify()
	h.waitEvents(t, telemetry.EventSync, 4)
	h.srv.NoQuery(100*time.Millisecond, "a third Reset Query within 5 minutes of the resync")
	if r := resets(h); r != 2 {
		t.Fatalf("%d Reset Queries within the 5 minutes, want 2", r)
	}
	if n := len(errorsOf(h, errCodeCorruptData)); n != 2 {
		t.Fatalf("%d code 0 error events, want 2", n)
	}

	clk.advance(2 * time.Minute)
	h.srv.AdvanceWire([]rtrtest.WirePDU{{Raw: bad}}, s)
	h.srv.Notify()
	h.waitEvents(t, telemetry.EventSync, 5)
	waitResets(t, h, 3)
}
