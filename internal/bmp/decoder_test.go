package bmp

import (
	"context"
	"encoding/binary"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// asPathAttr encodes an AS_PATH-style attribute (flags, type, length, value)
// from segments with asnLen-byte AS numbers: AS_PATH well-known, AS4_PATH
// optional transitive.
func asPathAttr(attrType byte, asnLen int, segs ...types.ASSegment) []byte {
	var v []byte
	for _, s := range segs {
		v = append(v, byte(s.Type), byte(len(s.ASNs)))
		for _, a := range s.ASNs {
			if asnLen == 2 {
				v = binary.BigEndian.AppendUint16(v, uint16(a))
			} else {
				v = binary.BigEndian.AppendUint32(v, a)
			}
		}
	}
	flags := byte(attrFlagTransitive)
	if attrType == attrAS4Path {
		flags |= attrFlagOptional
	}
	return append([]byte{flags, attrType, byte(len(v))}, v...)
}

func seq(asns ...uint32) types.ASSegment {
	return types.ASSegment{Type: types.ASSegmentSequence, ASNs: asns}
}

func set(asns ...uint32) types.ASSegment {
	return types.ASSegment{Type: types.ASSegmentSet, ASNs: asns}
}

func confed(asns ...uint32) types.ASSegment {
	return types.ASSegment{Type: types.ASSegmentConfedSequence, ASNs: asns}
}

// RFC 6793 §4.2.3: over a 2-octet session (A flag), AS_PATH holds 2-octet
// ASNs with AS_TRANS standing in for 4-octet ones, and the path is AS_PATH's
// leading part followed by AS4_PATH. Over a 4-octet session AS_PATH is read
// with 4-octet ASNs and AS4_PATH is ignored.
func TestAS4PathMerge(t *testing.T) {
	const big1, big2 = 4200000001, 4200000002
	for _, tc := range []struct {
		name  string
		as2   bool
		attrs []byte
		want  []uint32
		segs  int
	}{
		{"AS_TRANS replaced", true,
			append(asPathAttr(2, 2, seq(64500, asTrans, 64501, asTrans)), asPathAttr(17, 4, seq(big1, 64501, big2))...),
			[]uint32{64500, big1, 64501, big2}, 2},
		{"no AS4_PATH: AS_PATH as is", true,
			asPathAttr(2, 2, seq(64500, asTrans)), []uint32{64500, asTrans}, 1},
		{"AS4_PATH longer than AS_PATH: ignored", true,
			append(asPathAttr(2, 2, seq(64500, asTrans)), asPathAttr(17, 4, seq(big1, big2, 64501))...),
			[]uint32{64500, asTrans}, 1},
		{"AS_SET counts one", true,
			append(asPathAttr(2, 2, seq(64500), set(64510, 64511), seq(asTrans)), asPathAttr(17, 4, seq(big1))...),
			[]uint32{64500, 64510, 64511, big1}, 3},
		{"confederation segments count none, kept leading; dropped from AS4_PATH", true,
			append(asPathAttr(2, 2, confed(65001), seq(64500, asTrans)),
				asPathAttr(17, 4, confed(65009), seq(big1))...),
			[]uint32{65001, 64500, big1}, 3},
		{"4-octet session: AS_PATH 4-octet, AS4_PATH ignored", false,
			append(asPathAttr(2, 4, seq(64500, big1)), asPathAttr(17, 4, seq(big2))...),
			[]uint32{64500, big1}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m malformation
			a := parsePathAttributes(tc.attrs, tc.as2, false, &m)
			if !slices.Equal(a.asPath, tc.want) || len(a.asPathRaw) != tc.segs || m.action != actNone {
				t.Errorf("path %v in %d segments (%+v), want %v in %d", a.asPath, len(a.asPathRaw), m, tc.want, tc.segs)
			}
		})
	}

	// End to end: the per-peer header's A flag selects 2-octet parsing.
	pph := BMPPerPeerHeader{Flags: PeerFlagAS2, PeerAddr: netip.MustParseAddr("80.81.194.180")}
	attrs := append(asPathAttr(2, 2, seq(64500, asTrans)), asPathAttr(17, 4, seq(big1))...)
	attrs = append(attrs, 0x40, 1, 1, 0, 0x40, 3, 4, 192, 0, 2, 254)
	body := binary.BigEndian.AppendUint16([]byte{0, 0}, uint16(len(attrs)))
	body = append(append(body, attrs...), encodeNLRI(false, pathNLRI{0, netip.MustParsePrefix("1.1.1.0/24")})...)
	rs, _, err := parseBGPUpdate(body, pph, netip.MustParseAddr("192.0.2.1"), 0, 0)
	if err.action != actNone || len(rs) != 1 || !slices.Equal(rs[0].ASPath, []uint32{64500, big1}) || rs[0].OriginASN() != big1 {
		t.Errorf("A-flag UPDATE: routes %+v err %v, want path [64500 %d]", rs, err, uint32(big1))
	}
}

// mpReachAttr is an MP_REACH_NLRI attribute (extended length).
func mpReachAttr(afi uint16, safi uint8, nh []byte, nlri []byte) []byte {
	v := binary.BigEndian.AppendUint16(nil, afi)
	v = append(v, safi, byte(len(nh)))
	v = append(v, nh...)
	v = append(v, 0)
	v = append(v, nlri...)
	return append(binary.BigEndian.AppendUint16([]byte{0x90, attrMPReach}, uint16(len(v))), v...)
}

func mpUnreachAttr(afi uint16, safi uint8, nlri []byte) []byte {
	v := binary.BigEndian.AppendUint16(nil, afi)
	v = append(v, safi)
	v = append(v, nlri...)
	return append(binary.BigEndian.AppendUint16([]byte{0x90, attrMPUnreach}, uint16(len(v))), v...)
}

func updateWithAttrs(attrs []byte) []byte {
	base := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfb, 0xf5}
	attrs = append(base, attrs...)
	return append(binary.BigEndian.AppendUint16([]byte{0, 0}, uint16(len(attrs))), attrs...)
}

func unsupportedCount(t *testing.T, afi, safi string) float64 {
	t.Helper()
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() != "raven_bmp_unsupported_nlri_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			l := map[string]string{}
			for _, lp := range m.GetLabel() {
				l[lp.GetName()] = lp.GetValue()
			}
			if l["afi"] == afi && l["safi"] == safi {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// IPv4 unicast in MP_REACH_NLRI / MP_UNREACH_NLRI is decoded, with an IPv4
// next hop or an RFC 8950 IPv6 one (global, or global and link-local), and
// with ADD-PATH by the IPv4 setting. Other address families are counted.
func TestIPv4InMPReach(t *testing.T) {
	pph := BMPPerPeerHeader{PeerAddr: netip.MustParseAddr("80.81.194.180")}
	router := netip.MustParseAddr("192.0.2.1")
	p := netip.MustParsePrefix("1.1.1.0/24")
	v4nh, v6nh := netip.MustParseAddr("192.0.2.254"), netip.MustParseAddr("2001:db8::fe")
	ll := netip.MustParseAddr("fe80::1")
	for _, tc := range []struct {
		name    string
		nh      []byte
		addPath AFIMask
		wantNH  netip.Addr
	}{
		{"IPv4 next hop", v4nh.AsSlice(), 0, v4nh},
		{"RFC 8950 IPv6 next hop", v6nh.AsSlice(), 0, v6nh},
		{"RFC 8950 IPv6 next hop with link-local", append(v6nh.AsSlice(), ll.AsSlice()...), 0, v6nh},
		{"ADD-PATH", v4nh.AsSlice(), AFIIPv4Unicast, v4nh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ap := tc.addPath != 0
			attrs := mpReachAttr(1, 1, tc.nh, encodeNLRI(ap, pathNLRI{5, p}))
			attrs = append(attrs, mpUnreachAttr(1, 1, encodeNLRI(ap, pathNLRI{6, netip.MustParsePrefix("8.8.8.0/24")}))...)
			rs, ws, err := parseBGPUpdate(updateWithAttrs(attrs), pph, router, 0, tc.addPath)
			if err.action != actNone || len(rs) != 1 || len(ws) != 1 {
				t.Fatalf("routes %v withdrawals %v err %v, want one each", rs, ws, err)
			}
			wantID := map[bool]uint32{true: 5, false: 0}[ap]
			if rs[0].Prefix != p || rs[0].NextHop != tc.wantNH || rs[0].PathID != wantID {
				t.Errorf("route %s via %s path %d, want %s via %s path %d", rs[0].Prefix, rs[0].NextHop, rs[0].PathID, p, tc.wantNH, wantID)
			}
			if ws[0].Prefix != netip.MustParsePrefix("8.8.8.0/24") {
				t.Errorf("withdrawal %s, want 8.8.8.0/24", ws[0].Prefix)
			}
		})
	}

	// IPv4 and IPv6 ADD-PATH settings apply to their own family.
	attrs := append(mpReachAttr(2, 1, v6nh.AsSlice(), encodeNLRI(false, pathNLRI{0, netip.MustParsePrefix("2001:db8:1::/48")})),
		mpUnreachAttr(1, 1, encodeNLRI(true, pathNLRI{9, p}))...)
	rs, ws, _ := parseBGPUpdate(updateWithAttrs(attrs), pph, router, 0, AFIIPv4Unicast)
	if len(rs) != 1 || rs[0].PathID != 0 || len(ws) != 1 || ws[0].PathID != 9 {
		t.Errorf("per-family ADD-PATH: routes %+v withdrawals %+v", rs, ws)
	}

	// Unsupported families are counted, reach and unreach.
	before := unsupportedCount(t, "1", "128")
	attrs = append(mpReachAttr(1, 128, make([]byte, 12), []byte{0x70, 0, 0, 1}), mpUnreachAttr(1, 128, nil)...)
	rs, _, _ = parseBGPUpdate(updateWithAttrs(attrs), pph, router, 0, 0)
	if len(rs) != 0 {
		t.Errorf("VPNv4 NLRI decoded as %v", rs)
	}
	if got := unsupportedCount(t, "1", "128") - before; got != 2 {
		t.Errorf("raven_bmp_unsupported_nlri_total{afi=1,safi=128} rose by %v, want 2", got)
	}
}

// extendedOpen is an OPEN in the RFC 9072 extended optional parameters
// format: Opt Parm Len 255, a 255 type marker, a 2-byte length, and
// parameters with 2-byte lengths.
func extendedOpen(asn uint16, caps ...[]byte) []byte {
	var capParam []byte
	for _, c := range caps {
		capParam = append(capParam, c...)
	}
	param := binary.BigEndian.AppendUint16([]byte{bgpOptParamCapabilities}, uint16(len(capParam)))
	param = append(param, capParam...)
	body := binary.BigEndian.AppendUint16([]byte{4}, asn)
	body = append(body, 0, 90, 192, 0, 2, 1, 255, 255)
	body = binary.BigEndian.AppendUint16(body, uint16(len(param)))
	body = append(body, param...)
	msg := make([]byte, 16)
	for i := range msg {
		msg[i] = 0xff
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(19+len(body)))
	return append(append(msg, bgpMsgTypeOpen), body...)
}

// RFC 9072 OPENs give the local AS (4-octet capability) and ADD-PATH like
// the classic format does.
func TestExtendedOptionalParameters(t *testing.T) {
	as4 := []byte{bgpCap4ByteASN, 4, 0xfa, 0x56, 0xea, 0x01} // 4200000001
	o, err := parseOpen(extendedOpen(asTrans, as4, addPathCap(withSR(v4uni, 1))))
	if err != nil || o.asn != 4200000001 || o.addPath[afiSafi{1, 1}] != 1 {
		t.Fatalf("extended OPEN: %+v err %v, want AS 4200000001 and ADD-PATH receive", o, err)
	}
	msg := peerUpWithOpens(netip.MustParseAddr("80.81.194.180"), 0,
		extendedOpen(64500, addPathCap(withSR(v4uni, 1))), openMsg(64501, addPathCap(withSR(v4uni, 2))))
	pu, err := ParsePeerUp(msg[CommonHeaderLen:])
	if err != nil || pu.LocalASN != 64500 || pu.AddPath.In != AFIIPv4Unicast {
		t.Errorf("Peer Up with an extended Sent OPEN: %+v err %v", pu, err)
	}
}

// The O and L flags give the RIB: Adj-RIB-Out (RFC 8671) never lands in an
// Adj-RIB-In type.
func TestRIBTypeFromFlags(t *testing.T) {
	for flags, want := range map[uint8]types.RIBType{
		0:                                      types.AdjRIBInPre,
		PeerFlagPostPolicy:                     types.AdjRIBInPost,
		PeerFlagAdjRIBOut:                      types.AdjRIBOutPre,
		PeerFlagAdjRIBOut | PeerFlagPostPolicy: types.AdjRIBOutPost,
	} {
		if got := ribTypeOf(BMPPerPeerHeader{Flags: flags}); got != want {
			t.Errorf("flags %#x: %s, want %s", flags, got, want)
		}
	}
}

// raven_bmp_peer_state has one series per peer per router per instance.
func TestPeerStateMetricLabels(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 64))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, _ := h.connect(ctx, t)
	peer := netip.MustParseAddr("80.81.194.199")
	send(t, client, initiationMsg("br7.test"),
		peerUpWithOpens(peer, 0, openMsg(64500), openMsg(64501)),
		peerUpWithOpens(peer, 0x0000fde8_00000064, openMsg(64500), openMsg(64501)))
	want := map[string]bool{"": false, "65000:100": false}
	waitFor(t, "both peer_state series", func() bool {
		mfs, _ := prometheus.DefaultGatherer.Gather()
		for _, mf := range mfs {
			if mf.GetName() != "raven_bmp_peer_state" {
				continue
			}
			for _, m := range mf.GetMetric() {
				l := map[string]string{}
				for _, lp := range m.GetLabel() {
					l[lp.GetName()] = lp.GetValue()
				}
				if l["router"] == "br7.test" && l["router_addr"] == "127.0.0.1" && l["peer"] == peer.String() && m.GetGauge().GetValue() == 1 {
					want[l["peer_distinguisher"]] = true
				}
			}
		}
		return want[""] && want["65000:100"]
	})
}

// Regression: a Withdrawn Routes Length running past the UPDATE was sliced as
// given and panicked the session goroutine, taking down the process. Now it
// is a session reset (RFC 7606 §3 (b)) with nothing to withdraw: the field
// cannot be delimited.
func TestWithdrawnLengthOverflow(t *testing.T) {
	for _, body := range [][]byte{
		{0xff, 0xff, 0, 0}, // 65535 withdrawn bytes in a 4-byte UPDATE
		{0, 3, 24, 1, 1},   // withdrawn routes, no room for the attributes length
	} {
		rs, ws, m := parseBGPUpdate(body, BMPPerPeerHeader{}, netip.Addr{}, 0, 0)
		if m.action != actSessionReset || m.reason != "update_length" || rs != nil || ws != nil {
			t.Errorf("UPDATE % x: routes %v withdrawals %v %+v, want update_length session reset and nothing", body, rs, ws, m)
		}
	}
}

// Regression: a Statistics Report's 32-bit count sized a map, so one report
// could ask for billions of entries.
func TestStatsReportCountDoesNotSizeAllocation(t *testing.T) {
	body := append(perPeerHeader(netip.MustParseAddr("80.81.194.180")), 0xff, 0xff, 0xff, 0xff, 0, 1, 0, 4, 0, 0, 0, 9)
	var sr BMPStatsReport
	var err error
	checkAlloc(t, len(body), func() { sr, err = ParseStatsReport(body) })
	if err != nil || sr.Counters[1] != 9 || len(sr.Counters) != 1 {
		t.Errorf("stats report %+v err %v, want the one counter", sr, err)
	}
}

// A BMP header announcing a message over MaxMessageLen closes the session
// before anything is allocated for it.
func TestOversizedMessageClosesSession(t *testing.T) {
	h := newSessionHarness(t, make(chan types.IngestEvent, 8))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, done := h.connect(ctx, t)
	hdr := []byte{3, 0xff, 0xff, 0xff, 0xff, MsgTypeRouteMonitoring} // 4 GB
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	send(t, client, hdr)
	client.Close() // without the cap the session would wait for the 4 GB body
	<-done
	runtime.ReadMemStats(&m1)
	if got := m1.TotalAlloc - m0.TotalAlloc; got > 64<<20 {
		t.Errorf("an oversized header allocated %d bytes", got)
	}
	if !strings.Contains(h.logs.String(), "invalid BMP message length") {
		t.Errorf("no log of the rejected length:\n%s", h.logs.String())
	}
}
