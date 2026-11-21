package bmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// RFC 7606 error handling: one test per row of the gap table, then the
// cases around it. Section numbers are RFC 7606's unless said otherwise.

// rawUpdate is an UPDATE body from its parts: Withdrawn Routes bytes, path
// attribute bytes, then NLRI bytes.
func rawUpdate(withdrawn, attrs []byte, nlri ...byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
	b = append(b, withdrawn...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(attrs)))
	b = append(b, attrs...)
	return append(b, nlri...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

var (
	attrOriginIGP = []byte{0x40, attrOrigin, 1, 0}
	attrPath      = asPathAttr(attrASPath, 4, seq(64501, 13335))
	attrNH        = []byte{0x40, attrNextHop, 4, 192, 0, 2, 254}
	goodAttrs     = cat(attrOriginIGP, attrPath, attrNH)

	nlri1111 = []byte{24, 1, 1, 1} // 1.1.1.0/24
	nlri8888 = []byte{24, 8, 8, 8} // 8.8.8.0/24
	nlri9999 = []byte{24, 9, 9, 9} // 9.9.9.0/24

	p1111 = netip.MustParsePrefix("1.1.1.0/24")
	p8888 = netip.MustParsePrefix("8.8.8.0/24")
	p9999 = netip.MustParsePrefix("9.9.9.0/24")
	pV6   = netip.MustParsePrefix("2001:db8:1::/48")
	v6NH  = netip.MustParseAddr("2001:db8::fe").AsSlice()
)

var testPPH = BMPPerPeerHeader{PeerAddr: netip.MustParseAddr("80.81.194.180"), PeerASN: 64501}

// decode7606 decodes an UPDATE body from testPPH with flags, the monitoring
// router in AS 64500 and no ADD-PATH.
func decode7606(body []byte, flags uint8) ([]types.Route, []types.Withdrawal, malformation) {
	pph := testPPH
	pph.Flags = flags
	return parseBGPUpdate(body, pph, netip.MustParseAddr("192.0.2.1"), 64500, 0)
}

func prefixesOf(ws []types.Withdrawal) []netip.Prefix {
	var out []netip.Prefix
	for _, w := range ws {
		out = append(out, w.Prefix)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return out
}

// wantWithdrawn checks an UPDATE gave no routes, the action and reason, and
// withdrawals of exactly the prefixes given.
func wantWithdrawn(t *testing.T, body []byte, flags uint8, action errAction, reason string, prefixes ...netip.Prefix) {
	t.Helper()
	rs, ws, m := decode7606(body, flags)
	if len(rs) != 0 {
		t.Errorf("routes %v stored, want none", rs)
	}
	if m.action != action || m.reason != reason {
		t.Errorf("classified %s/%s (%s), want %s/%s", m.action, m.reason, m.detail, action, reason)
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	if got := prefixesOf(ws); !slices.Equal(got, prefixes) {
		t.Errorf("withdrew %v, want %v", got, prefixes)
	}
}

// Gap row 1, §7.2: an AS_PATH segment running past the attribute, an
// unknown segment type, a zero-length segment or a lone trailing byte is a
// malformed AS_PATH, treat-as-withdraw. RAVEN used to keep the segments
// before the error, and the truncated path's last AS became the ROV origin.
func TestRFC7606MalformedASPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path []byte
	}{
		{"segment past the attribute", []byte{0x40, 2, 11, 2, 1, 0, 0, 0xfb, 0xf5, 2, 2, 0, 0, 0x34}},
		{"unknown segment type", []byte{0x40, 2, 6, 7, 1, 0, 0, 0xfb, 0xf5}},
		{"zero-length segment", []byte{0x40, 2, 8, 2, 1, 0, 0, 0xfb, 0xf5, 2, 0}},
		{"lone trailing byte", []byte{0x40, 2, 7, 2, 1, 0, 0, 0xfb, 0xf5, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := rawUpdate(nil, cat(attrOriginIGP, tc.path, attrNH), nlri1111...)
			wantWithdrawn(t, body, 0, actTreatAsWithdraw, "as_path", p1111)
		})
	}
	// The same with 2-octet ASNs.
	body := rawUpdate(nil, cat(attrOriginIGP, []byte{0x40, 2, 6, 2, 3, 0xfb, 0xf5, 0x34, 0x17}, attrNH), nlri1111...)
	wantWithdrawn(t, body, PeerFlagAS2, actTreatAsWithdraw, "as_path", p1111)
}

// Gap row 2, §4: an attribute whose length runs past the path attributes,
// or fewer bytes left than an attribute header, is treat-as-withdraw; the
// NLRI field is still found from the Total Path Attribute Length.
func TestRFC7606AttributeOverrun(t *testing.T) {
	overrun := cat(goodAttrs, []byte{0xc0, attrCommunities, 8, 0, 1, 0, 1})
	wantWithdrawn(t, rawUpdate(nil, overrun, nlri1111...), 0, actTreatAsWithdraw, "attr_length", p1111)

	extOverrun := cat(goodAttrs, []byte{0xd0, attrCommunities, 0, 8, 0, 1, 0, 1})
	wantWithdrawn(t, rawUpdate(nil, extOverrun, nlri1111...), 0, actTreatAsWithdraw, "attr_length", p1111)

	underrun := cat(goodAttrs, []byte{0x40, 99})
	wantWithdrawn(t, rawUpdate(nil, underrun, nlri1111...), 0, actTreatAsWithdraw, "attr_length", p1111)
}

// Gap row 3: ORIGIN (§7.1), NEXT_HOP (§7.3), MULTI_EXIT_DISC (§7.4),
// COMMUNITIES (§7.8) or LARGE_COMMUNITY (RFC 8092 §6) with a bad length,
// and ORIGIN with an undefined value, are treat-as-withdraw. So are
// LOCAL_PREF, ORIGINATOR_ID and CLUSTER_LIST errors from an internal peer
// (§7.5, §7.9, §7.10); from an external one they are discarded unread.
func TestRFC7606BadAttributeLengths(t *testing.T) {
	base := cat(attrPath, attrNH)
	for _, tc := range []struct {
		name, reason string
		attr         []byte
	}{
		{"ORIGIN length 2", "origin", []byte{0x40, 1, 2, 0, 0}},
		{"ORIGIN length 0", "origin", []byte{0x40, 1, 0}},
		{"ORIGIN value 3", "origin", []byte{0x40, 1, 1, 3}},
		{"NEXT_HOP length 5", "next_hop", cat(attrOriginIGP, []byte{0x40, 3, 5, 192, 0, 2, 254, 0})},
		{"MED length 3", "med", cat(attrOriginIGP, []byte{0x80, 4, 3, 0, 0, 1})},
		{"COMMUNITIES length 6", "communities", cat(attrOriginIGP, []byte{0xc0, 8, 6, 0, 1, 0, 1, 0, 2})},
		{"COMMUNITIES length 0", "communities", cat(attrOriginIGP, []byte{0xc0, 8, 0})},
		{"LARGE_COMMUNITY length 13", "large_communities", cat(attrOriginIGP, []byte{0xc0, 32, 13}, make([]byte, 13))},
		{"LARGE_COMMUNITY length 0", "large_communities", cat(attrOriginIGP, []byte{0xc0, 32, 0})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// NEXT_HOP's own case replaces the good one.
			attrs := cat(tc.attr, base)
			if tc.reason == "next_hop" {
				attrs = cat(tc.attr, attrPath)
			}
			wantWithdrawn(t, rawUpdate(nil, attrs, nlri1111...), 0, actTreatAsWithdraw, tc.reason, p1111)
		})
	}

	// Internal-only attributes: withdrawn from an iBGP peer (PeerASN equal
	// to the monitoring router's AS), ignored from an eBGP one.
	for _, tc := range []struct {
		name, reason string
		attr         []byte
	}{
		{"LOCAL_PREF length 3", "local_pref", []byte{0x40, 5, 3, 0, 0, 100}},
		{"ORIGINATOR_ID length 3", "originator_id", []byte{0x80, 9, 3, 10, 0, 0}},
		{"CLUSTER_LIST length 6", "cluster_list", []byte{0x80, 10, 6, 10, 0, 0, 1, 10, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := rawUpdate(nil, cat(goodAttrs, tc.attr), nlri1111...)
			internal := testPPH
			internal.PeerASN = 64500
			rs, ws, m := parseBGPUpdate(body, internal, netip.MustParseAddr("192.0.2.1"), 64500, 0)
			if len(rs) != 0 || m.action != actTreatAsWithdraw || m.reason != tc.reason || !slices.Equal(prefixesOf(ws), []netip.Prefix{p1111}) {
				t.Errorf("internal peer: routes %v withdrawals %v %+v, want %s treat-as-withdraw", rs, ws, m, tc.reason)
			}
			rs, _, m = decode7606(body, 0)
			if len(rs) != 1 || m.action != actNone {
				t.Errorf("external peer: routes %v %+v, want the route and no error", rs, m)
			}
		})
	}
}

// Gap row 4, §3 (g): of a repeated attribute the first is kept and the
// others discarded; a repeated MP_REACH_NLRI or MP_UNREACH_NLRI is a
// session reset, and every prefix in every copy is withdrawn. RAVEN used
// to keep the last.
func TestRFC7606DuplicateAttribute(t *testing.T) {
	attrs := cat(attrOriginIGP, []byte{0x40, 1, 1, 2}, attrPath, attrNH,
		[]byte{0xc0, 8, 4, 0, 1, 0, 1}, []byte{0xc0, 8, 4, 0, 2, 0, 2})
	rs, ws, m := decode7606(rawUpdate(nil, attrs, nlri1111...), 0)
	if len(rs) != 1 || len(ws) != 0 {
		t.Fatalf("routes %v withdrawals %v, want the route", rs, ws)
	}
	if m.action != actAttributeDiscard || m.reason != "duplicate_attr" {
		t.Errorf("classified %+v, want attribute_discard/duplicate_attr", m)
	}
	if rs[0].Origin != types.OriginIGP || !slices.Equal(rs[0].Communities, []types.Community{{High: 1, Low: 1}}) {
		t.Errorf("origin %d communities %v, want the first of each: IGP, [1:1]", rs[0].Origin, rs[0].Communities)
	}

	reach := mpReachAttr(2, 1, v6NH, encodeNLRI(false, pathNLRI{0, pV6}))
	reach2 := mpReachAttr(1, 1, []byte{192, 0, 2, 254}, nlri9999)
	wantWithdrawn(t, rawUpdate(nil, cat(attrOriginIGP, attrPath, reach, reach2)), 0,
		actSessionReset, "duplicate_mp", pV6, p9999)

	unreach := mpUnreachAttr(1, 1, nlri8888)
	wantWithdrawn(t, rawUpdate(nil, cat(unreach, unreach, mpUnreachAttr(1, 1, nlri9999))), 0,
		actSessionReset, "duplicate_mp", p8888, p8888, p9999)
}

// Gap row 5, §3 (d): ORIGIN and AS_PATH are mandatory in an UPDATE that
// announces anything, NEXT_HOP for prefixes in the NLRI field (not with
// MP_REACH_NLRI alone, RFC 4760). One carrying only withdrawals needs none,
// nor does an End-of-RIB.
func TestRFC7606MissingMandatory(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs []byte
	}{
		{"no ORIGIN", cat(attrPath, attrNH)},
		{"no AS_PATH", cat(attrOriginIGP, attrNH)},
		{"no NEXT_HOP", cat(attrOriginIGP, attrPath)},
		{"none", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantWithdrawn(t, rawUpdate(nil, tc.attrs, nlri1111...), 0, actTreatAsWithdraw, "missing_mandatory", p1111)
		})
	}

	// MP_REACH_NLRI without NEXT_HOP is complete.
	rs, _, m := decode7606(rawUpdate(nil, cat(attrOriginIGP, attrPath, mpReachAttr(2, 1, v6NH, encodeNLRI(false, pathNLRI{0, pV6})))), 0)
	if len(rs) != 1 || m.action != actNone {
		t.Errorf("MP_REACH_NLRI without NEXT_HOP: routes %v %+v, want the route", rs, m)
	}
	// MP_REACH_NLRI without ORIGIN is not.
	wantWithdrawn(t, rawUpdate(nil, cat(attrPath, mpReachAttr(2, 1, v6NH, encodeNLRI(false, pathNLRI{0, pV6})))), 0,
		actTreatAsWithdraw, "missing_mandatory", pV6)

	// Withdrawals only, in either form, and End-of-RIB in both forms.
	for _, body := range [][]byte{
		rawUpdate(nlri8888, nil),
		rawUpdate(nil, mpUnreachAttr(1, 1, nlri8888)),
	} {
		rs, ws, m := decode7606(body, 0)
		if len(rs) != 0 || m.action != actNone || !slices.Equal(prefixesOf(ws), []netip.Prefix{p8888}) {
			t.Errorf("withdrawal-only UPDATE % x: routes %v withdrawals %v %+v, want the withdrawal, no error", body, rs, ws, m)
		}
	}
	for _, body := range [][]byte{rawUpdate(nil, nil), rawUpdate(nil, mpUnreachAttr(2, 1, nil))} {
		if rs, ws, m := decode7606(body, 0); len(rs)+len(ws) != 0 || m.action != actNone {
			t.Errorf("End-of-RIB % x: routes %v withdrawals %v %+v, want nothing", body, rs, ws, m)
		}
	}
}

// Gap row 6, §3 (c): an attribute whose Optional or Transitive bit is
// wrong is malformed: treat-as-withdraw for the attributes that are,
// session reset for MP_REACH_NLRI / MP_UNREACH_NLRI (§5.3), discard for
// AS4_PATH (RFC 6793 §6). The Partial and Extended Length bits are not
// checked.
func TestRFC7606AttributeFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs []byte
	}{
		{"ORIGIN optional", cat([]byte{0xc0, 1, 1, 0}, attrPath, attrNH)},
		{"AS_PATH not transitive", cat(attrOriginIGP, []byte{0x00, 2, 0}, attrNH)},
		{"NEXT_HOP optional", cat(attrOriginIGP, attrPath, []byte{0x80, 3, 4, 192, 0, 2, 254})},
		{"MED transitive", cat(goodAttrs, []byte{0xc0, 4, 4, 0, 0, 0, 1})},
		{"COMMUNITIES well-known", cat(goodAttrs, []byte{0x40, 8, 4, 0, 1, 0, 1})},
		{"LARGE_COMMUNITY not transitive", cat(goodAttrs, []byte{0x80, 32, 12}, make([]byte, 12))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantWithdrawn(t, rawUpdate(nil, tc.attrs, nlri1111...), 0, actTreatAsWithdraw, "attr_flags", p1111)
		})
	}

	// The Partial bit on an optional transitive attribute, and Extended
	// Length on a short one: fine.
	ok := cat([]byte{0x50, 1, 0, 1, 0}, attrPath, attrNH, []byte{0xe0, 8, 4, 0, 1, 0, 1})
	if rs, _, m := decode7606(rawUpdate(nil, ok, nlri1111...), 0); len(rs) != 1 || m.action != actNone {
		t.Errorf("Partial/Extended Length: routes %v %+v, want the route, no error", rs, m)
	}

	reach := mpReachAttr(2, 1, v6NH, encodeNLRI(false, pathNLRI{0, pV6}))
	reach[0] = 0xd0 // optional transitive
	wantWithdrawn(t, rawUpdate(nil, cat(attrOriginIGP, attrPath, reach)), 0, actSessionReset, "mp_reach", pV6)

	unreach := mpUnreachAttr(1, 1, nlri8888)
	unreach[0] = 0x50 // well-known
	wantWithdrawn(t, rawUpdate(nil, unreach), 0, actSessionReset, "mp_unreach", p8888)
}

// Gap row 7, §5.3: NLRI that is syntactically incorrect (a prefix longer
// than the address, or an entry running past the field) can only be
// answered by a session reset. Every prefix before the error is withdrawn,
// as are the UPDATE's withdrawals. RAVEN used to keep the prefixes before
// the error as routes.
func TestRFC7606MalformedNLRI(t *testing.T) {
	wantWithdrawn(t, rawUpdate(nil, goodAttrs, cat(nlri1111, []byte{33, 1, 2, 3, 4, 5})...), 0,
		actSessionReset, "nlri", p1111)
	wantWithdrawn(t, rawUpdate(nlri9999, goodAttrs, cat(nlri1111, []byte{24, 8, 8})...), 0,
		actSessionReset, "nlri", p1111, p9999)
	// In the Withdrawn Routes field (§3 (i)).
	wantWithdrawn(t, rawUpdate(cat(nlri9999, []byte{40}), goodAttrs, nlri1111...), 0,
		actSessionReset, "nlri", p1111, p9999)
	// In MP_REACH_NLRI: an IPv6 prefix longer than 128.
	reach := mpReachAttr(2, 1, v6NH, cat(encodeNLRI(false, pathNLRI{0, pV6}), []byte{129}))
	wantWithdrawn(t, rawUpdate(nil, cat(attrOriginIGP, attrPath, reach)), 0, actSessionReset, "nlri", pV6)
	// ADD-PATH: a path identifier with no prefix after it.
	pph := testPPH
	rs, ws, m := parseBGPUpdate(rawUpdate(nil, goodAttrs, cat(encodeNLRI(true, pathNLRI{4, p1111}), []byte{0, 0, 0, 5})...),
		pph, netip.MustParseAddr("192.0.2.1"), 64500, AFIIPv4Unicast)
	if len(rs) != 0 || m.reason != "nlri" || len(ws) != 1 || ws[0].Prefix != p1111 || ws[0].PathID != 4 {
		t.Errorf("ADD-PATH truncation: routes %v withdrawals %+v %+v, want 1.1.1.0/24 path 4 withdrawn", rs, ws, m)
	}
}

// Gap row 8, §7.11 and §5.3: an MP_REACH_NLRI next hop of a length the
// address family does not allow, or running past the attribute, and an
// MP_REACH_NLRI under 5 bytes or MP_UNREACH_NLRI under 3, are session
// resets. RAVEN used to store such routes with no next hop, or drop them
// silently.
func TestRFC7606MPReachNextHop(t *testing.T) {
	v6 := encodeNLRI(false, pathNLRI{0, pV6})
	wantWithdrawn(t, rawUpdate(nil, cat(attrOriginIGP, attrPath, mpReachAttr(2, 1, []byte{192, 0, 2, 1}, v6))), 0,
		actSessionReset, "mp_reach_next_hop", pV6)
	wantWithdrawn(t, rawUpdate(nil, cat(attrOriginIGP, attrPath, mpReachAttr(1, 1, make([]byte, 12), nlri1111))), 0,
		actSessionReset, "mp_reach_next_hop", p1111)
	past := []byte{0x90, attrMPReach, 0, 8, 0, 2, 1, 16, 0x20, 0x01, 0x0d, 0xb8}
	wantWithdrawn(t, rawUpdate(nil, cat(attrOriginIGP, attrPath, past)), 0, actSessionReset, "mp_reach_next_hop")
	wantWithdrawn(t, rawUpdate(nil, cat(attrOriginIGP, attrPath, []byte{0x90, attrMPReach, 0, 4, 0, 2, 1, 0})), 0,
		actSessionReset, "mp_reach")
	wantWithdrawn(t, rawUpdate(nlri8888, []byte{0x90, attrMPUnreach, 0, 2, 0, 2}), 0, actSessionReset, "mp_unreach", p8888)
}

// Gap row 9, RFC 6793 §6: a malformed AS4_PATH (or AS4_AGGREGATOR) is
// discarded and the route kept with AS_PATH alone. RAVEN used to merge
// what parsed of it.
func TestRFC7606AS4PathDiscard(t *testing.T) {
	const big = 4200000001
	path2 := asPathAttr(attrASPath, 2, seq(64501, asTrans))
	for _, tc := range []struct {
		name, reason string
		attr         []byte
	}{
		{"AS4_PATH truncated", "as4_path", []byte{0xc0, attrAS4Path, 6, 2, 2, 0xfa, 0x56, 0xea, 0x01}},
		{"AS4_PATH unknown segment type", "as4_path", []byte{0xc0, attrAS4Path, 6, 9, 1, 0xfa, 0x56, 0xea, 0x01}},
		{"AS4_PATH well-known flags", "as4_path", []byte{0x40, attrAS4Path, 6, 2, 1, 0xfa, 0x56, 0xea, 0x01}},
		{"AS4_AGGREGATOR length 6", "as4_aggregator", []byte{0xc0, attrAS4Aggregator, 6, 0, 0, 0xfb, 0xf5, 10, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := rawUpdate(nil, cat(attrOriginIGP, path2, attrNH, tc.attr), nlri1111...)
			rs, ws, m := decode7606(body, PeerFlagAS2)
			if len(rs) != 1 || len(ws) != 0 {
				t.Fatalf("routes %v withdrawals %v, want the route kept", rs, ws)
			}
			if m.action != actAttributeDiscard || m.reason != tc.reason {
				t.Errorf("classified %+v, want attribute_discard/%s", m, tc.reason)
			}
			if !slices.Equal(rs[0].ASPath, []uint32{64501, asTrans}) {
				t.Errorf("path %v, want AS_PATH alone [64501 %d]", rs[0].ASPath, asTrans)
			}
		})
	}
	// A good AS4_PATH still merges.
	body := rawUpdate(nil, cat(attrOriginIGP, path2, attrNH, asPathAttr(attrAS4Path, 4, seq(big))), nlri1111...)
	if rs, _, m := decode7606(body, PeerFlagAS2); len(rs) != 1 || m.action != actNone || rs[0].OriginASN() != big {
		t.Errorf("good AS4_PATH: routes %+v %+v, want origin AS%d", rs, m, uint32(big))
	}
	// Over a 4-octet session AS4_PATH is ignored, malformed or not.
	body = rawUpdate(nil, cat(goodAttrs, []byte{0xc0, attrAS4Path, 3, 2, 9, 0}), nlri1111...)
	if rs, _, m := decode7606(body, 0); len(rs) != 1 || m.action != actNone {
		t.Errorf("4-octet session: routes %v %+v, want the route, no error", rs, m)
	}
}

// Gap row 10, §3 (b): UPDATE length fields that overflow the message are a
// session reset. The withdrawals still apply when the Withdrawn Routes
// field can be delimited; RAVEN used to drop the whole UPDATE, leaving them
// in the table.
func TestRFC7606LengthOverflow(t *testing.T) {
	body := rawUpdate(nlri8888, nil)
	binary.BigEndian.PutUint16(body[2+len(nlri8888):], 200) // attributes length past the end
	wantWithdrawn(t, body, 0, actSessionReset, "update_length", p8888)

	wantWithdrawn(t, []byte{0, 0, 0}, 0, actSessionReset, "update_length")
}

// A BGP Length field below the 19-byte header was sliced as given and
// panicked the session goroutine, and the process with it. The fuzz
// targets reimplemented this step with a guard, so they never reached it;
// they now call decodeRouteMonitoring. A Length past the message is a
// session reset too, with what parses withdrawn.
func TestBGPLengthField(t *testing.T) {
	update := rawUpdate(nlri8888, goodAttrs, nlri1111...)
	for _, tc := range []struct {
		name   string
		length int
		want   []netip.Prefix
	}{
		{"below the header", 5, []netip.Prefix{p1111, p8888}},
		{"zero", 0, []netip.Prefix{p1111, p8888}},
		{"past the message", 19 + len(update) + 10, []netip.Prefix{p1111, p8888}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := routeMonitoringWithBGPLength(testPPH.PeerAddr, tc.length, update)
			rm, err := ParseRouteMonitoring(msg[CommonHeaderLen:])
			if err != nil {
				t.Fatal(err)
			}
			rs, ws, m := decodeRouteMonitoring(rm, netip.MustParseAddr("192.0.2.1"), 0, 0)
			if len(rs) != 0 || m.action != actSessionReset || m.reason != "update_length" {
				t.Errorf("routes %v %+v, want none and an update_length session reset", rs, m)
			}
			if got := prefixesOf(ws); !slices.Equal(got, tc.want) {
				t.Errorf("withdrew %v, want %v", got, tc.want)
			}
		})
	}
}

// routeMonitoringWithBGPLength is a Route Monitoring message from peer
// carrying update with the BGP header's Length field set to length.
func routeMonitoringWithBGPLength(peer netip.Addr, length int, update []byte) []byte {
	bgp := bytes.Repeat([]byte{0xff}, 16)
	bgp = binary.BigEndian.AppendUint16(bgp, uint16(length))
	bgp = append(bgp, bgpMsgTypeUpdate)
	bgp = append(bgp, update...)
	return bmpMsg(MsgTypeRouteMonitoring, append(perPeerHeader(peer), bgp...))
}

// §5.2: an attribute error in an UPDATE that announces nothing is a session
// reset, since nothing assures RAVEN it found all the NLRI. Its withdrawals
// still apply.
func TestRFC7606NoReachableNLRIEscalates(t *testing.T) {
	wantWithdrawn(t, rawUpdate(nlri8888, []byte{0x40, 1, 1, 7}), 0, actSessionReset, "origin", p8888)
	wantWithdrawn(t, rawUpdate(nil, cat([]byte{0x40, 1, 2, 0, 0}, mpUnreachAttr(1, 1, nlri8888))), 0,
		actSessionReset, "origin", p8888)
	// Attribute discard alone is not escalated.
	rs, ws, m := decode7606(rawUpdate(nlri8888, cat(attrOriginIGP, attrOriginIGP)), 0)
	if len(rs) != 0 || len(ws) != 1 || m.action != actAttributeDiscard {
		t.Errorf("duplicate ORIGIN, withdrawals only: routes %v withdrawals %v %+v, want attribute discard", rs, ws, m)
	}
}

// §3 (h): with several errors the strongest approach wins, and the first
// error calling for it is the reason given, whatever order they come in.
func TestRFC7606StrongestActionWins(t *testing.T) {
	attrs := cat([]byte{0x40, 1, 1, 9}, attrPath, attrNH, mpReachAttr(2, 1, []byte{1, 2, 3, 4}, nil))
	_, _, m := decode7606(rawUpdate(nil, attrs, nlri1111...), 0)
	if m.action != actSessionReset || m.reason != "mp_reach_next_hop" {
		t.Errorf("classified %+v, want session_reset/mp_reach_next_hop", m)
	}
	// A weaker error after a stronger one changes nothing.
	attrs = cat(attrOriginIGP, attrPath, attrNH, []byte{0xc0, 8, 3, 0, 0, 0}, attrNH)
	_, _, m = decode7606(rawUpdate(nil, attrs, nlri1111...), 0)
	if m.action != actTreatAsWithdraw || m.reason != "communities" {
		t.Errorf("classified %+v, want treat_as_withdraw/communities over the later duplicate NEXT_HOP", m)
	}
	// Of two equally strong errors, the first is the reason.
	attrs = cat([]byte{0x40, 1, 1, 9}, attrPath, attrNH, []byte{0xc0, 8, 3, 0, 0, 0})
	_, _, m = decode7606(rawUpdate(nil, attrs, nlri1111...), 0)
	if m.action != actTreatAsWithdraw || m.reason != "origin" {
		t.Errorf("classified %+v, want treat_as_withdraw/origin, the first error", m)
	}
}

// RFC 5065 confederation segments are parsed and kept: a route from a peer
// inside the router's confederation is well-formed. Its origin AS comes
// from the final AS_SEQUENCE (RFC 6811 §2), never a member AS in the path.
func TestDecodeConfederationPath(t *testing.T) {
	path := asPathAttr(attrASPath, 4, confed(65001, 65002), seq(64500, 13335))
	rs, _, m := decode7606(rawUpdate(nil, cat(attrOriginIGP, path, attrNH), nlri1111...), 0)
	if len(rs) != 1 || m.action != actNone {
		t.Fatalf("routes %v %+v, want the route", rs, m)
	}
	if len(rs[0].ASPathRaw) != 2 || rs[0].ASPathRaw[0].Type != types.ASSegmentConfedSequence || rs[0].OriginASN() != 13335 {
		t.Errorf("segments %+v origin AS%d, want a confederation segment kept and origin AS13335", rs[0].ASPathRaw, rs[0].OriginASN())
	}
	// Only confederation segments: originated inside the confederation, so
	// the origin is the router's own AS (RFC 6811 §2), here the session's
	// local AS64500 with no confederation identifier known.
	path = asPathAttr(attrASPath, 4, confed(65001, 65002))
	rs, _, _ = decode7606(rawUpdate(nil, cat(attrOriginIGP, path, attrNH), nlri1111...), 0)
	if len(rs) != 1 || rs[0].OriginASN() != 64500 {
		t.Errorf("confederation-only path: routes %+v, want origin AS64500, the local AS (not AS65002)", rs)
	}
}

func malformedCount(t *testing.T, action, reason string) float64 {
	t.Helper()
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() != "raven_bmp_malformed_updates_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var a, r string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "action":
					a = l.GetValue()
				case "reason":
					r = l.GetValue()
				}
			}
			if a == action && r == reason {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("no raven_bmp_malformed_updates_total{action=%q,reason=%q} series", action, reason)
	return 0
}

// End to end through a BMP session: withdrawals in a malformed UPDATE are
// applied (RAVEN used to drop the UPDATE whole, leaving the routes), a
// treat-as-withdraw UPDATE removes its prefixes instead of storing them, a
// session-reset UPDATE marks the peer while the BMP session stays up, every
// malformed UPDATE is counted, and the WARN is rate-limited. A new Peer Up
// clears the mark.
func TestMalformedUpdatesThroughSession(t *testing.T) {
	ingest := make(chan types.IngestEvent, 64)
	h := newSessionHarness(t, ingest)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, done := h.connect(ctx, t)
	peer := testPPH.PeerAddr
	rm := func(update []byte) []byte { return routeMonitoringRD(peer, 0, update) }

	resetBefore := malformedCount(t, "session_reset", "update_length")
	withdrawBefore := malformedCount(t, "treat_as_withdraw", "origin")

	send(t, client, initiationMsg("br1.nyc"), peerUpMsg(peer))
	key := PeerKey{RouterAddr: netip.MustParseAddr("127.0.0.1"), PeerAddr: peer}
	peerState := func() (Peer, bool) {
		h.l.peerMu.RLock()
		defer h.l.peerMu.RUnlock()
		p, ok := h.l.peers[key]
		if !ok {
			return Peer{}, false
		}
		return *p, true
	}
	waitFor(t, "peer up", func() bool { _, ok := peerState(); return ok })

	// 1. Attributes length past the end, withdrawing 8.8.8.0/24.
	overflow := rawUpdate(nlri8888, nil)
	binary.BigEndian.PutUint16(overflow[2+len(nlri8888):], 300)
	send(t, client, rm(overflow))
	if ev := h.next(t); ev.Withdrawal == nil || ev.Withdrawal.Prefix != p8888 {
		t.Fatalf("got %+v, want the 8.8.8.0/24 withdrawal", ev)
	}
	// 2. A bad ORIGIN announcing 1.1.1.0/24 and withdrawing 9.9.9.0/24.
	send(t, client, rm(rawUpdate(nlri9999, cat([]byte{0x40, 1, 1, 5}, attrPath, attrNH), nlri1111...)))
	var got []netip.Prefix
	for range 2 {
		ev := h.next(t)
		if ev.Route != nil {
			t.Fatalf("treat-as-withdraw UPDATE stored route %s", ev.Route.Prefix)
		}
		got = append(got, ev.Withdrawal.Prefix)
	}
	slices.SortFunc(got, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	if !slices.Equal(got, []netip.Prefix{p1111, p9999}) {
		t.Errorf("withdrew %v, want 1.1.1.0/24 and 9.9.9.0/24", got)
	}
	// 3. The same overflow again: counted, not logged again.
	send(t, client, rm(overflow))
	h.next(t)
	// 4. A good UPDATE still goes through: the BMP session is up.
	send(t, client, rm(rawUpdate(nil, goodAttrs, nlri1111...)))
	if ev := h.next(t); ev.Route == nil || ev.Route.Prefix != p1111 {
		t.Fatalf("got %+v, want the 1.1.1.0/24 route", ev)
	}

	if d := malformedCount(t, "session_reset", "update_length") - resetBefore; d != 2 {
		t.Errorf("session_reset/update_length rose by %v, want 2", d)
	}
	if d := malformedCount(t, "treat_as_withdraw", "origin") - withdrawBefore; d != 1 {
		t.Errorf("treat_as_withdraw/origin rose by %v, want 1", d)
	}
	p, _ := peerState()
	if !p.MalformedInput || p.MalformedReason != "update_length" || p.MalformedAt.IsZero() {
		t.Errorf("peer malformed=%v reason=%q at=%v, want marked update_length", p.MalformedInput, p.MalformedReason, p.MalformedAt)
	}
	logs := h.logs.String()
	var warns []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "malformed BGP UPDATE") {
			warns = append(warns, line)
		}
	}
	if len(warns) != 2 {
		t.Fatalf("%d WARNs, want 2 (one per reason; the repeat suppressed):\n%s", len(warns), logs)
	}
	for _, field := range []string{"router=127.0.0.1:", "router_name=br1.nyc", "peer=80.81.194.180",
		"action=session_reset", "reason=update_length", "withdrawals=1"} {
		if !strings.Contains(warns[0], field) {
			t.Errorf("WARN lacks %q: %s", field, warns[0])
		}
	}
	if !strings.Contains(warns[1], "action=treat_as_withdraw") || !strings.Contains(warns[1], "reason=origin") {
		t.Errorf("second WARN: %s", warns[1])
	}

	// A new Peer Up starts the peer afresh.
	send(t, client, peerUpMsg(peer))
	waitFor(t, "mark cleared", func() bool { p, _ := peerState(); return !p.MalformedInput })
	client.Close()
	<-done
}

// The WARN limiter allows one line per peer and reason a minute and counts
// what it held back; other peers and reasons are not held back.
func TestWarnLimiter(t *testing.T) {
	var w warnLimiter
	now := testPPH.Timestamp
	a := warnKey{peer: PeerKey{PeerAddr: testPPH.PeerAddr}, reason: "nlri"}
	b := warnKey{peer: PeerKey{PeerAddr: testPPH.PeerAddr}, reason: "origin"}
	if ok, n := w.allow(a, now); !ok || n != 0 {
		t.Fatalf("first: %v %d", ok, n)
	}
	for range 3 {
		if ok, _ := w.allow(a, now.Add(malformedWarnInterval/2)); ok {
			t.Fatal("allowed within the interval")
		}
	}
	if ok, _ := w.allow(b, now); !ok {
		t.Error("another reason held back")
	}
	if ok, n := w.allow(a, now.Add(malformedWarnInterval)); !ok || n != 3 {
		t.Errorf("after the interval: %v, %d suppressed, want true, 3", ok, n)
	}
}

// A route's Timestamp is the per-peer header's, the router's receive time;
// a header timestamp of 0 (none given, RFC 7854 §4.2) becomes RAVEN's.
func TestRouteTimestampFromPerPeerHeader(t *testing.T) {
	ingest := make(chan types.IngestEvent, 8)
	h := newSessionHarness(t, ingest)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, done := h.connect(ctx, t)
	peer := testPPH.PeerAddr

	before := time.Now()
	send(t, client, routeMonitoringMsg(peer, p1111))
	ev := h.next(t)
	if ev.Route == nil || ev.Route.Timestamp.Before(before) || ev.Route.Timestamp.After(time.Now()) {
		t.Fatalf("zero header timestamp: route %+v, want RAVEN's receive time", ev.Route)
	}

	msg := routeMonitoringMsg(peer, p8888)
	off := CommonHeaderLen + 34 // per-peer header seconds, then microseconds
	binary.BigEndian.PutUint32(msg[off:], 1760790605)
	binary.BigEndian.PutUint32(msg[off+4:], 250000)
	send(t, client, msg)
	ev = h.next(t)
	if want := time.Unix(1760790605, 250000000); ev.Route == nil || !ev.Route.Timestamp.Equal(want) {
		t.Fatalf("route %+v, want the header's timestamp %v", ev.Route, want)
	}
	client.Close()
	<-done
}
