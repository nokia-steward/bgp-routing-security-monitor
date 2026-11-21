package bmp

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"runtime"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Fuzz targets for RAVEN's BMP and BGP decoding, which reads untrusted input
// from routers. Each checks three properties on every input:
//
//   - no panic;
//   - allocation bounded by the input, not by length fields in it: total
//     allocation stays under allocBound(len(input));
//   - nothing read past the message: decoding the input from a slice with
//     hidden bytes after it (len < cap) gives exactly what decoding an exact
//     copy gives.
//
// The UPDATE decoders are also checked for the RFC 7606 invariants
// (checkUpdateInvariants) and for classifying the same input the same way
// every time.
//
// Run with `make fuzz` (FUZZTIME per target, default 5m). Inputs that fail
// are saved under testdata/fuzz/<Target>/ and replayed by every `go test`.

// allocBound is the most a decode may allocate for n input bytes: a route
// (a few hundred bytes) per NLRI byte at worst, plus a fixed allowance.
func allocBound(n int) uint64 { return uint64(n)*1024 + 1<<20 }

// checkAlloc runs f and fails if it allocated more than allocBound(n).
func checkAlloc(t *testing.T, n int, f func()) {
	t.Helper()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	f()
	runtime.ReadMemStats(&m1)
	if got := m1.TotalAlloc - m0.TotalAlloc; got > allocBound(n) {
		t.Fatalf("decoding %d bytes allocated %d bytes (bound %d): a length field is trusted", n, got, allocBound(n))
	}
}

// withHiddenTail returns data in a slice whose capacity runs into 64 bytes of
// garbage: a decoder that reslices past len would see them.
func withHiddenTail(data []byte) []byte {
	buf := make([]byte, len(data), len(data)+64)
	copy(buf, data)
	tail := buf[len(data) : len(data)+64]
	for i := range tail {
		tail[i] = 0xa5
	}
	return buf
}

func exactCopy(data []byte) []byte { return append([]byte(nil), data...) }

// sameOnBothSlices decodes data as an exact copy and with a hidden tail and
// fails if the results differ.
func sameOnBothSlices[T any](t *testing.T, data []byte, decode func([]byte) T) T {
	t.Helper()
	var exact, tailed T
	checkAlloc(t, len(data), func() { exact = decode(exactCopy(data)) })
	tailed = decode(withHiddenTail(data))
	if !reflect.DeepEqual(exact, tailed) {
		t.Fatalf("decode read past the message:\n exact  %+v\n tailed %+v", exact, tailed)
	}
	return exact
}

type updateResult struct {
	Routes      []types.Route
	Withdrawals []types.Withdrawal
	// The RFC 7606 classification.
	Action, Reason, Detail string
}

func toResult(rs []types.Route, ws []types.Withdrawal, m malformation) updateResult {
	return updateResult{Routes: rs, Withdrawals: ws, Action: m.action.String(), Reason: m.reason, Detail: m.detail}
}

func decodeUpdate(data []byte, flags uint8, addPath AFIMask) updateResult {
	pph := BMPPerPeerHeader{Flags: flags, PeerAddr: netip.MustParseAddr("80.81.194.180"), PeerASN: 64501}
	return toResult(parseBGPUpdate(data, pph, netip.MustParseAddr("192.0.2.1"), fuzzLocalAS, addPath))
}

// checkDeterministic decodes data twice more, each from a fresh copy, and
// fails unless both give exactly want, classification included.
func checkDeterministic[T any](t *testing.T, data []byte, want T, decode func([]byte) T) {
	t.Helper()
	for range 2 {
		if got := decode(exactCopy(data)); !reflect.DeepEqual(got, want) {
			t.Fatalf("same input decoded differently:\n first %+v\n again %+v", want, got)
		}
	}
}

// strictAttrs is the fuzz oracle for routes: an independent, strict reading
// of an UPDATE body's ORIGIN, AS_PATH and NEXT_HOP (the first of each). ok
// is false if any attribute cannot be delimited, or if ORIGIN or AS_PATH is
// missing or malformed, or NEXT_HOP is when the NLRI field is not empty:
// an UPDATE whose prefixes the router would never install.
func strictAttrs(body []byte, as2 bool) (origin uint8, path []types.ASSegment, ok bool) {
	if len(body) < 4 {
		return 0, nil, false
	}
	wl := int(body[0])<<8 | int(body[1])
	if 2+wl+2 > len(body) {
		return 0, nil, false
	}
	al := int(body[2+wl])<<8 | int(body[3+wl])
	attrs, end := body[4+wl:], 4+wl+al
	if end > len(body) {
		return 0, nil, false
	}
	attrs = attrs[:al]
	nlriPresent := end < len(body)
	var haveOrigin, havePath, haveNH bool
	for i := 0; i < len(attrs); {
		if i+3 > len(attrs) {
			return 0, nil, false
		}
		flags, typ, hl, l := attrs[i], attrs[i+1], 3, int(attrs[i+2])
		if flags&0x10 != 0 {
			if i+4 > len(attrs) {
				return 0, nil, false
			}
			hl, l = 4, int(attrs[i+2])<<8|int(attrs[i+3])
		}
		if i+hl+l > len(attrs) {
			return 0, nil, false
		}
		v := attrs[i+hl : i+hl+l]
		i += hl + l
		wellKnown := flags&0xc0 == 0x40
		switch {
		case typ == 1 && !haveOrigin:
			haveOrigin = true
			if !wellKnown || l != 1 || v[0] > 2 {
				return 0, nil, false
			}
			origin = v[0]
		case typ == 2 && !havePath:
			havePath = true
			if !wellKnown {
				return 0, nil, false
			}
			n := 4
			if as2 {
				n = 2
			}
			for j := 0; j < len(v); {
				if j+2 > len(v) || v[j] < 1 || v[j] > 4 || v[j+1] == 0 || j+2+int(v[j+1])*n > len(v) {
					return 0, nil, false
				}
				seg := types.ASSegment{Type: types.ASSegmentType(v[j])}
				for k := 0; k < int(v[j+1]); k++ {
					var a uint32
					for b := 0; b < n; b++ {
						a = a<<8 | uint32(v[j+2+k*n+b])
					}
					seg.ASNs = append(seg.ASNs, a)
				}
				path = append(path, seg)
				j += 2 + int(v[j+1])*n
			}
		case typ == 3 && !haveNH:
			haveNH = true
			if !wellKnown || l != 4 {
				return 0, nil, false
			}
		}
	}
	if !haveOrigin || !havePath || (nlriPresent && !haveNH) {
		return 0, nil, false
	}
	return origin, path, true
}

// fuzzLocalAS is the monitored router's own AS the fuzz targets decode with.
const fuzzLocalAS = 64500

// rfc6811Origin is the origin AS of a path per RFC 6811 §2, written apart
// from types.Route.OriginASN: the last AS of a final AS_SEQUENCE; the BGP
// speaker's own AS, localAS, for an empty path or after a final
// confederation segment (the decoder knows no confederation identifier);
// 0 after a final AS_SET (NONE).
func rfc6811Origin(path []types.ASSegment, localAS uint32) uint32 {
	if len(path) == 0 {
		return localAS
	}
	last := path[len(path)-1]
	switch last.Type {
	case types.ASSegmentConfedSequence, types.ASSegmentConfedSet:
		return localAS
	case types.ASSegmentSequence:
		if len(last.ASNs) > 0 {
			return last.ASNs[len(last.ASNs)-1]
		}
	}
	return 0
}

// checkUpdateInvariants checks what a decoded UPDATE may contain:
//
//   - a treat-as-withdraw or session-reset UPDATE yields no route;
//   - every route comes from an UPDATE the oracle (strictAttrs) finds a
//     valid ORIGIN, AS_PATH and, for NLRI-field prefixes, NEXT_HOP in, and
//     carries that ORIGIN and, over a 4-octet session, that AS_PATH and its
//     RFC 6811 origin AS (the session's local AS, fuzzLocalAS, for an
//     empty or confederation-terminated path). Over a 2-octet session
//     AS4_PATH may rewrite the
//     path, so the origin AS is checked against the route's own path.
//
// So no route is stored without a valid origin; anything else must have
// come back as a withdrawal.
func checkUpdateInvariants(t *testing.T, body []byte, flags uint8, r updateResult) {
	t.Helper()
	if r.Action == actTreatAsWithdraw.String() || r.Action == actSessionReset.String() {
		if len(r.Routes) != 0 {
			t.Fatalf("%s (%s) UPDATE produced %d routes", r.Action, r.Reason, len(r.Routes))
		}
		return
	}
	if len(r.Routes) == 0 {
		return
	}
	as2 := flags&PeerFlagAS2 != 0
	origin, path, ok := strictAttrs(body, as2)
	if !ok {
		t.Fatalf("route stored from an UPDATE without a valid ORIGIN/AS_PATH/NEXT_HOP (classified %q %q): %+v",
			r.Action, r.Reason, r.Routes[0])
	}
	for _, rt := range r.Routes {
		if !rt.Prefix.IsValid() {
			t.Fatalf("decoded an invalid prefix %v", rt.Prefix)
		}
		if uint8(rt.Origin) != origin {
			t.Fatalf("route ORIGIN %d, UPDATE has %d", rt.Origin, origin)
		}
		want := path
		if as2 {
			want = rt.ASPathRaw
		} else if !reflect.DeepEqual(rt.ASPathRaw, path) {
			t.Fatalf("route AS_PATH %+v, UPDATE has %+v", rt.ASPathRaw, path)
		}
		if got := rt.OriginASN(); got != rfc6811Origin(want, fuzzLocalAS) {
			t.Fatalf("route origin AS%d, RFC 6811 gives AS%d for %+v", got, rfc6811Origin(want, fuzzLocalAS), want)
		}
	}
}

// FuzzDecodeUpdate fuzzes the BGP UPDATE decoder: withdrawn routes, path
// attributes (AS_PATH and AS4_PATH with 2- and 4-octet ASNs, communities,
// MP_REACH_NLRI / MP_UNREACH_NLRI for every AFI/SAFI) and NLRI, with
// ADD-PATH on and off per address family and every per-peer flag. Besides
// the common checks it checks the RFC 7606 invariants
// (checkUpdateInvariants) and that classification is deterministic.
func FuzzDecodeUpdate(f *testing.F) {
	p, v6 := netip.MustParsePrefix("1.1.1.0/24"), netip.MustParsePrefix("2001:db8:1::/48")
	nh := []byte{0x40, 3, 4, 192, 0, 2, 254}
	for _, seed := range [][]byte{
		updateBody(false, false, []pathNLRI{{0, p}}, []pathNLRI{{0, p}}, []pathNLRI{{0, v6}}),
		updateBody(true, true, []pathNLRI{{3, p}}, []pathNLRI{{1, p}, {2, p}}, []pathNLRI{{7, v6}}),
		updateWithAttrs(append(mpReachAttr(1, 1, []byte{192, 0, 2, 1}, encodeNLRI(false, pathNLRI{0, p})),
			mpUnreachAttr(1, 1, encodeNLRI(true, pathNLRI{9, p}))...)),
		updateWithAttrs(mpReachAttr(1, 1, netip.MustParseAddr("2001:db8::fe").AsSlice(), encodeNLRI(false, pathNLRI{0, p}))),
		updateWithAttrs(mpReachAttr(1, 128, make([]byte, 12), []byte{0x70, 0, 0, 1})),
		updateWithAttrs(append(asPathAttr(2, 2, seq(64500, asTrans)), asPathAttr(17, 4, seq(4200000001))...)),
		updateWithAttrs([]byte{0xc0, 8, 4, 0xfd, 0xe8, 0, 1, 0xc0, 32, 12, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0, 0, 0, 2}),
		// RFC 7606 cases: a truncated AS_PATH, a confederation path, a
		// repeated MP_REACH_NLRI, and an attribute overrun with withdrawals.
		append(rawUpdate(nil, append([]byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 2, 0, 0, 0xfb, 0xf5}, nh...)), 24, 1, 1, 1),
		append(rawUpdate(nil, append(append([]byte{0x40, 1, 1, 0}, asPathAttr(2, 4, confed(65001), seq(64500))...), nh...)), 24, 1, 1, 1),
		// Paths whose origin is the local AS (RFC 6811 §2): empty, and
		// ending in a confederation segment.
		append(rawUpdate(nil, append([]byte{0x40, 1, 1, 0, 0x40, 2, 0}, nh...)), 24, 1, 1, 1),
		append(rawUpdate(nil, append(append([]byte{0x40, 1, 1, 0}, asPathAttr(2, 4, confed(65001, 65002))...), nh...)), 24, 1, 1, 1),
		updateWithAttrs(append(mpReachAttr(2, 1, netip.MustParseAddr("2001:db8::fe").AsSlice(), encodeNLRI(false, pathNLRI{0, v6})),
			mpReachAttr(2, 1, netip.MustParseAddr("2001:db8::fe").AsSlice(), encodeNLRI(false, pathNLRI{0, v6}))...)),
		rawUpdate([]byte{24, 8, 8, 8}, []byte{0x40, 1, 5, 0}),
	} {
		for _, flags := range []uint8{0, PeerFlagAS2, PeerFlagAdjRIBOut | PeerFlagPostPolicy} {
			f.Add(seed, flags, uint8(0))
			f.Add(seed, flags, uint8(AFIIPv4Unicast|AFIIPv6Unicast))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, flags, addPath uint8) {
		decode := func(b []byte) updateResult {
			return decodeUpdate(b, flags, AFIMask(addPath)&(AFIIPv4Unicast|AFIIPv6Unicast))
		}
		r := sameOnBothSlices(t, data, decode)
		checkDeterministic(t, data, r, decode)
		checkUpdateInvariants(t, data, flags, r)
	})
}

type peerUpResult struct {
	PeerUp BMPPeerUp
	Err    string
	Open   openInfo
	OErr   string
}

// FuzzPeerUpOpen fuzzes Peer Up parsing, including the embedded Sent and
// Received OPENs (classic and RFC 9072 extended optional parameters, the
// 4-octet AS and ADD-PATH capabilities), and OPEN parsing on its own.
func FuzzPeerUpOpen(f *testing.F) {
	peer := netip.MustParseAddr("80.81.194.180")
	for _, msg := range [][]byte{
		peerUpMsg(peer),
		peerUpWithOpens(peer, 0, openMsg(64500), openMsg(64501)),
		peerUpWithOpens(peer, 0x0000fde8_00000064, openMsg(64500, addPathCap(withSR(v4uni, 3), withSR(v6uni, 1))),
			openMsg(64501, addPathCap(withSR(v4uni, 3)), []byte{bgpCap4ByteASN, 4, 0xfa, 0x56, 0xea, 0x01})),
		peerUpWithOpens(peer, 0, extendedOpen(64500, addPathCap(withSR(v4uni, 1))), extendedOpen(64501)),
	} {
		f.Add(msg[CommonHeaderLen:])
	}
	f.Add(openMsg(64500, addPathCap(withSR(v4uni, 3))))
	f.Add(extendedOpen(23456, []byte{bgpCap4ByteASN, 4, 0, 1, 0, 0}))
	f.Fuzz(func(t *testing.T, data []byte) {
		sameOnBothSlices(t, data, func(b []byte) peerUpResult {
			var r peerUpResult
			pu, err := ParsePeerUp(b)
			r.PeerUp = pu
			if err != nil {
				r.Err = err.Error()
			}
			o, err := parseOpen(b)
			r.Open = o
			if err != nil {
				r.OErr = err.Error()
			}
			return r
		})
	})
}

type messageResult struct {
	Header BMPCommonHeader
	Parsed any
	Err    string
	Update updateResult
}

// decodeMessage decodes one BMP message as the listener does: the common
// header, then the body by message type, and a Route Monitoring's UPDATE
// with ADD-PATH as given.
func decodeMessage(data []byte, addPath AFIMask) messageResult {
	var r messageResult
	hdr, err := ParseCommonHeader(data)
	r.Header = hdr
	if err != nil {
		r.Err = err.Error()
		return r
	}
	if hdr.Length > MaxMessageLen || int(hdr.Length) > len(data) {
		r.Err = "length"
		return r
	}
	body := data[CommonHeaderLen:hdr.Length]
	setErr := func(err error) {
		if err != nil {
			r.Err = err.Error()
		}
	}
	switch hdr.MsgType {
	case MsgTypeInitiation:
		v, err := ParseInitiation(body)
		r.Parsed = v
		setErr(err)
	case MsgTypePeerUp:
		v, err := ParsePeerUp(body)
		r.Parsed = v
		setErr(err)
	case MsgTypePeerDown:
		v, err := ParsePeerDown(body)
		r.Parsed = v
		setErr(err)
	case MsgTypeStatisticsReport:
		v, err := ParseStatsReport(body)
		r.Parsed = v
		setErr(err)
	case MsgTypeRouteMonitoring:
		rm, err := ParseRouteMonitoring(body)
		r.Parsed = rm
		setErr(err)
		if err == nil {
			// The listener's own path from here: decodeRouteMonitoring,
			// BGP header checks included.
			r.Update = toResult(decodeRouteMonitoring(rm, netip.MustParseAddr("192.0.2.1"), fuzzLocalAS, addPath))
		}
	}
	return r
}

// FuzzBMPMessage fuzzes whole BMP messages: the common header, per-peer
// header, and each message type's body, Route Monitoring through the UPDATE
// decoder.
func FuzzBMPMessage(f *testing.F) {
	peer := netip.MustParseAddr("80.81.194.180")
	p := netip.MustParsePrefix("1.1.1.0/24")
	stats := append(perPeerHeader(peer), 0, 0, 0, 2, 0, 1, 0, 4, 0, 0, 0, 9, 0, 7, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3)
	for _, msg := range [][]byte{
		initiationMsg("br1.nyc"),
		peerUpMsg(peer),
		peerUpWithOpens(peer, 0, openMsg(64500, addPathCap(withSR(v4uni, 1))), openMsg(64501, addPathCap(withSR(v4uni, 2)))),
		routeMonitoringMsg(peer, p, netip.MustParsePrefix("8.8.8.0/24")),
		routeMonitoringRD(peer, 0x0000fde8_00000064, updateBody(true, false, nil, []pathNLRI{{1, p}, {2, p}}, nil)),
		routeMonitoringWithBGPLength(peer, 5, updateBody(false, false, []pathNLRI{{0, p}}, nil, nil)),
		bmpMsg(MsgTypePeerDown, peerDownBody(peer)),
		bmpMsg(MsgTypeStatisticsReport, stats),
		bmpMsg(MsgTypeTermination, nil),
	} {
		f.Add(msg, uint8(0))
		f.Add(msg, uint8(AFIIPv4Unicast))
	}
	f.Fuzz(func(t *testing.T, data []byte, addPath uint8) {
		decode := func(b []byte) messageResult {
			return decodeMessage(b, AFIMask(addPath)&(AFIIPv4Unicast|AFIIPv6Unicast))
		}
		r := sameOnBothSlices(t, data, decode)
		checkDeterministic(t, data, r, decode)
		rm, ok := r.Parsed.(BMPRouteMonitoring)
		if !ok || len(rm.BGPUpdateData) < bgpHeaderLen {
			return
		}
		body := rm.BGPUpdateData[bgpHeaderLen:]
		if n := int(binary.BigEndian.Uint16(rm.BGPUpdateData[16:18])); n >= bgpHeaderLen && n <= len(rm.BGPUpdateData) {
			body = rm.BGPUpdateData[bgpHeaderLen:n]
		}
		checkUpdateInvariants(t, body, rm.PerPeer.Flags, r.Update)
	})
}
