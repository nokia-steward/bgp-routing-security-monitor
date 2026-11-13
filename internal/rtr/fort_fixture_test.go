package rtr

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// Replays of real Fort 1.7.0 deltas captured over RTR version 1 by Antonio
// Prado (University of Padova, ASPA Explorer); see testdata/README.md.

// fortDelta is one captured delta: its announcements and withdrawals, each
// in wire order, and, when captured, every PDU in wire order (seq).
type fortDelta struct {
	From, Serial uint32
	Ann, Wd      []rtrtest.VRP
	Seq          []fortPDU // nil when the capture has none
}

// fortPDU is one seq entry: an announcement or withdrawal, and whether the
// capturing client held the record before it (H) or not (N).
type fortPDU struct {
	Announce, Held bool
	VRP            rtrtest.VRP
}

// parseFortRecord parses a record as the captures write it:
// "prefix/length-maxlength ASn", e.g. "192.0.2.0/24-24 AS64500".
func parseFortRecord(s string) (rtrtest.VRP, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return rtrtest.VRP{}, fmt.Errorf("record %q: want prefix/length-maxlength ASn", s)
	}
	asText, ok := strings.CutPrefix(f[1], "AS")
	if !ok {
		return rtrtest.VRP{}, fmt.Errorf("record %q: no AS", s)
	}
	asn, err := strconv.ParseUint(asText, 10, 32)
	if err != nil {
		return rtrtest.VRP{}, fmt.Errorf("record %q: AS: %w", s, err)
	}
	i := strings.LastIndexByte(f[0], '-')
	if i < 0 {
		return rtrtest.VRP{}, fmt.Errorf("record %q: no max length", s)
	}
	p, err := netip.ParsePrefix(f[0][:i])
	if err != nil {
		return rtrtest.VRP{}, fmt.Errorf("record %q: %w", s, err)
	}
	maxLen, err := strconv.ParseUint(f[0][i+1:], 10, 8)
	if err != nil || int(maxLen) < p.Bits() || int(maxLen) > p.Addr().BitLen() {
		return rtrtest.VRP{}, fmt.Errorf("record %q: max length %q out of range", s, f[0][i+1:])
	}
	return rtrtest.VRP{Prefix: p, MaxLen: uint8(maxLen), ASN: uint32(asn)}, nil
}

// loadFortDelta reads and parses testdata/name.
func loadFortDelta(t *testing.T, name string) fortDelta {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var j struct {
		From   uint32   `json:"from"`
		Serial uint32   `json:"serial"`
		Ann    []string `json:"ann"`
		Wd     []string `json:"wd"`
		Seq    []string `json:"seq"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	d := fortDelta{From: j.From, Serial: j.Serial}
	records := func(in []string) []rtrtest.VRP {
		out := make([]rtrtest.VRP, len(in))
		for i, s := range in {
			v, err := parseFortRecord(s)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			out[i] = v
		}
		return out
	}
	d.Ann, d.Wd = records(j.Ann), records(j.Wd)
	for _, s := range j.Seq {
		if len(s) < 4 || (s[0] != '+' && s[0] != '-') || (s[1] != 'H' && s[1] != 'N') || s[2] != ' ' {
			t.Fatalf("%s: seq entry %q: want +H, +N, -H or -N, a space, then the record", name, s)
		}
		v, err := parseFortRecord(s[3:])
		if err != nil {
			t.Fatalf("%s: seq: %v", name, err)
		}
		d.Seq = append(d.Seq, fortPDU{Announce: s[0] == '+', Held: s[1] == 'H', VRP: v})
	}
	return d
}

// wireOf is the PDUs of a capture's seq, in its wire order.
func wireOf(pdus []fortPDU) []rtrtest.WirePDU {
	out := make([]rtrtest.WirePDU, len(pdus))
	for i, p := range pdus {
		out[i] = rtrtest.WirePDU{Announce: p.Announce, VRP: p.VRP}
	}
	return out
}

func setOf(vs []rtrtest.VRP) map[rtrtest.VRP]bool {
	m := make(map[rtrtest.VRP]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

func keys(m map[rtrtest.VRP]bool) []rtrtest.VRP {
	out := make([]rtrtest.VRP, 0, len(m))
	for v, ok := range m {
		if ok {
			out = append(out, v)
		}
	}
	return out
}

// replayFort loads baseline with a full sync at RTR version 1, replays wire
// as the next serial (the cache's data set after it being result), and
// waits for its End of Data. It returns the harness and the cache's
// raven_rtr_protocol_errors_total before the replay (a later test may reuse
// a port).
func replayFort(t *testing.T, baseline []rtrtest.VRP, wire []rtrtest.WirePDU, result []rtrtest.VRP) (*harness, float64) {
	t.Helper()
	h, _ := newHealHarnessAt(t, 1)
	h.srv.SetData(baseline, nil)
	h.start(t)
	h.synced(t)
	if s := h.waitEvents(t, telemetry.EventSync, 1)[0]; s.VRPTotal != len(baseline) || s.ProtoVersion != 1 {
		t.Fatalf("baseline full sync: vrp_total %d at version %d, want %d at 1", s.VRPTotal, s.ProtoVersion, len(baseline))
	}
	errs := rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.srv.Addr())
	h.srv.AdvanceWire(wire, result)
	h.srv.Notify()
	h.waitEvents(t, telemetry.EventSync, 2)
	return h, errs
}

// Fort 1.7.0, serial 220 -> 221: 2276 announcements, 2255 of records the
// client held (+H) and 21 new (+N), then 2263 withdrawals, all of held
// records (-H): 2268 announcements, the withdrawals, 8 more announcements.
// Every withdrawn record but 8 was also re-announced. The baseline is the
// records the client held before them: those whose first PDU is H.
//
// The store must end at baseline + the 21 new - the 8 withdrawn and not
// re-announced, with none of the 2255 re-announced records lost (ignoring
// the duplicates and applying the withdrawals lost them all). The 2255 are
// code 7, there is no code 6, and one self-healing resync follows, whose
// full sync (the cache's data: the same set) leaves the store as it was.
func TestFortDelta220To221(t *testing.T) {
	d := loadFortDelta(t, "fort-delta-220-221.txt")
	if d.From != 220 || d.Serial != 221 || len(d.Ann) != 2276 || len(d.Wd) != 2263 || len(d.Seq) != 4539 {
		t.Fatalf("fixture: %d -> %d, %d ann, %d wd, %d seq; want 220 -> 221, 2276, 2263, 4539",
			d.From, d.Serial, len(d.Ann), len(d.Wd), len(d.Seq))
	}
	var plus, minus []rtrtest.VRP
	flags := map[string]int{}
	held := map[rtrtest.VRP]bool{} // the baseline: first seen held
	seen := map[rtrtest.VRP]bool{}
	for _, p := range d.Seq {
		sign := "-"
		if p.Announce {
			sign = "+"
			plus = append(plus, p.VRP)
		} else {
			minus = append(minus, p.VRP)
		}
		flag := "N"
		if p.Held {
			flag = "H"
		}
		flags[sign+flag]++
		if !seen[p.VRP] {
			seen[p.VRP], held[p.VRP] = true, p.Held
		}
	}
	if flags["+H"] != 2255 || flags["+N"] != 21 || flags["-H"] != 2263 || flags["-N"] != 0 {
		t.Fatalf("seq flags %v, want +H 2255, +N 21, -H 2263", flags)
	}
	if !slices.Equal(plus, d.Ann) || !slices.Equal(minus, d.Wd) {
		t.Fatal("seq's announcements and withdrawals are not ann and wd in order")
	}
	baseline := keys(held)
	ann, wd := setOf(d.Ann), setOf(d.Wd)
	want := setOf(baseline)
	var added, gone, reannounced []rtrtest.VRP
	for v := range ann {
		if !want[v] {
			added = append(added, v)
		} else if wd[v] {
			reannounced = append(reannounced, v)
		}
	}
	for v := range wd {
		if !ann[v] {
			gone = append(gone, v)
		}
	}
	if len(added) != 21 || len(gone) != 8 || len(reannounced) != 2255 {
		t.Fatalf("fixture: %d new, %d withdrawn only, %d re-announced and withdrawn; want 21, 8, 2255",
			len(added), len(gone), len(reannounced))
	}
	for _, v := range added {
		want[v] = true
	}
	for _, v := range gone {
		want[v] = false
	}
	expected := keys(want)

	h, errsBefore := replayFort(t, baseline, wireOf(d.Seq), expected)
	sy := h.eventsOf(telemetry.EventSync)[1]
	if sy.VRPAnnounced != 2276 || sy.VRPWithdrawn != 2263 || sy.VRPTotal != len(expected) {
		t.Errorf("delta sync announced %d withdrawn %d total %d, want 2276, 2263, %d",
			sy.VRPAnnounced, sy.VRPWithdrawn, sy.VRPTotal, len(expected))
	}
	if got := heldSet(h); !slices.Equal(got, vrpSet(expected)) {
		t.Errorf("after the delta the store holds %d VRPs, want %d (baseline %d + 21 - 8)", len(got), len(expected), len(baseline))
	}
	lost, now := 0, heldSet(h)
	for _, v := range reannounced {
		if _, ok := slices.BinarySearchFunc(now, toVRP(v), cmpVRP); !ok {
			lost++
		}
	}
	if lost != 0 {
		t.Errorf("%d of the 2255 re-announced records lost", lost)
	}
	dups, unknown := errorsOf(h, 7), errorsOf(h, 6)
	if len(dups) != 1 || dups[0].ErrorCount != 2255 || len(unknown) != 0 {
		t.Errorf("%d code 7 events (count %v) and %d code 6, want one of 2255 and none; events: %s",
			len(dups), dups, len(unknown), h.summary())
	}
	if got := rtrtest.CounterSum("raven_rtr_protocol_errors_total", h.srv.Addr()) - errsBefore; got != 2255 {
		t.Errorf("raven_rtr_protocol_errors_total %v, want 2255 (all code 7)", got)
	}

	waitResets(t, h, 2)
	if s := h.waitEvents(t, telemetry.EventSync, 3)[2]; s.SyncType != telemetry.SyncTypeFull {
		t.Errorf("sync after the resync is %s, want full", s.SyncType)
	}
	if got := heldSet(h); !slices.Equal(got, vrpSet(expected)) {
		t.Errorf("after the resync the store holds %d VRPs, want the same %d", len(got), len(expected))
	}
	h.srv.NoQuery(100*time.Millisecond, "a second self-healing resync")
	if r := resets(h); r != 2 {
		t.Errorf("%d Reset Queries, want 2: the baseline and one resync", r)
	}
}

// Fort 1.7.0, serial 219 -> 220: 764 announcements and 760 withdrawals,
// captured before seq existed, so the file does not say how they were
// interleaved or which records the client held. No record appears twice in
// either list; 731 are both announced and withdrawn, 29 only withdrawn, 33
// only announced.
//
// One baseline makes the delta well defined: every withdrawn record held
// beforehand (a cache withdraws only what it announced). Each record is then
// withdrawn at most once from a count of 1, so no count can go below 0 in
// any order: the outcome is baseline + announcements - withdrawals per
// record, whatever the interleaving. That is every announced record held and
// the 29 withdrawn-only records gone. The test replays four interleavings
// (announcements first, as Fort sent 220 -> 221; withdrawals first;
// alternating; a seeded shuffle) and checks each ends at that set with no
// code 6. Code 7 counts are not asserted: they depend on the order.
func TestFortDelta219To220(t *testing.T) {
	d := loadFortDelta(t, "fort-delta-219-220.txt")
	if d.From != 219 || d.Serial != 220 || len(d.Ann) != 764 || len(d.Wd) != 760 || d.Seq != nil {
		t.Fatalf("fixture: %d -> %d, %d ann, %d wd, seq %v; want 219 -> 220, 764, 760, no seq",
			d.From, d.Serial, len(d.Ann), len(d.Wd), d.Seq != nil)
	}
	ann, wd := setOf(d.Ann), setOf(d.Wd)
	if len(ann) != len(d.Ann) || len(wd) != len(d.Wd) {
		t.Fatal("a record appears twice in ann or wd: the baseline below no longer makes the delta order-independent")
	}
	baseline := d.Wd
	count := map[rtrtest.VRP]int{}
	for _, v := range baseline {
		count[v]++
	}
	for _, v := range d.Ann {
		count[v]++
	}
	for _, v := range d.Wd {
		count[v]--
	}
	want := map[rtrtest.VRP]bool{}
	for v, n := range count {
		want[v] = n > 0
	}
	expected := keys(want)
	if !slices.Equal(vrpSet(expected), vrpSet(d.Ann)) {
		t.Fatalf("expected outcome is %d records, want every announced record (%d)", len(expected), len(d.Ann))
	}

	pdus := func(announce bool, vs []rtrtest.VRP) []rtrtest.WirePDU {
		out := make([]rtrtest.WirePDU, len(vs))
		for i, v := range vs {
			out[i] = rtrtest.WirePDU{Announce: announce, VRP: v}
		}
		return out
	}
	annPDUs, wdPDUs := pdus(true, d.Ann), pdus(false, d.Wd)
	var alternating []rtrtest.WirePDU
	for i := 0; i < max(len(annPDUs), len(wdPDUs)); i++ {
		if i < len(annPDUs) {
			alternating = append(alternating, annPDUs[i])
		}
		if i < len(wdPDUs) {
			alternating = append(alternating, wdPDUs[i])
		}
	}
	shuffled := append(slices.Clone(annPDUs), wdPDUs...)
	rand.New(rand.NewPCG(219, 220)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	for _, tc := range []struct {
		name string
		wire []rtrtest.WirePDU
	}{
		{"announcements first", append(slices.Clone(annPDUs), wdPDUs...)},
		{"withdrawals first", append(slices.Clone(wdPDUs), annPDUs...)},
		{"alternating", alternating},
		{"shuffled", shuffled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := replayFort(t, baseline, tc.wire, expected)
			if got := heldSet(h); !slices.Equal(got, vrpSet(expected)) {
				t.Errorf("store holds %d VRPs, want %d", len(got), len(expected))
			}
			if n := len(errorsOf(h, 6)); n != 0 {
				t.Errorf("%d code 6 events, want none: every withdrawn record was held", n)
			}
		})
	}
}

// parseFortRecord reads the captures' record format, IPv4 and IPv6, and
// refuses malformed records.
func TestParseFortRecord(t *testing.T) {
	for in, want := range map[string]rtrtest.VRP{
		"199.36.123.0/24-24 AS16509":            {Prefix: netip.MustParsePrefix("199.36.123.0/24"), MaxLen: 24, ASN: 16509},
		"177.84.24.0/22-32 AS262577":            {Prefix: netip.MustParsePrefix("177.84.24.0/22"), MaxLen: 32, ASN: 262577},
		"2804:2540:0:0:0:0:0:0/32-128 AS264268": {Prefix: netip.MustParsePrefix("2804:2540::/32"), MaxLen: 128, ASN: 264268},
	} {
		if got, err := parseFortRecord(in); err != nil || got != want {
			t.Errorf("parseFortRecord(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "199.36.123.0/24 AS16509", "199.36.123.0/24-24", "199.36.123.0/24-20 AS1", "199.36.123.0/24-33 AS1", "199.36.123.0/24-24 16509"} {
		if _, err := parseFortRecord(bad); err == nil {
			t.Errorf("parseFortRecord(%q): no error", bad)
		}
	}
}
