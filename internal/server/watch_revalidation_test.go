package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// watchStream is one raven watch client on the API server's /api/v1/watch.
type watchStream struct {
	events chan api.RouteResponse
}

// openWatch subscribes to s's watch stream with query q. The handler
// registers the subscriber before it flushes the response headers, so once
// this returns, every later NotifyRoute reaches the subscriber.
func openWatch(t *testing.T, s *Server, q url.Values) *watchStream {
	t.Helper()
	srv := httptest.NewServer(s.apiSrv.Mux())
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), testWaitBound)
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/watch?"+q.Encode(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	ws := &watchStream{events: make(chan api.RouteResponse, 100)}
	go func() {
		defer close(ws.events)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			var rr api.RouteResponse
			if err := json.Unmarshal([]byte(line), &rr); err != nil {
				return
			}
			ws.events <- rr
		}
	}()
	return ws
}

// markerPrefix is a prefix no test route uses. A marker route notified after
// a pass is delivered after every event the pass sent, since each
// subscriber's events go through one channel in order.
var markerPrefix = netip.MustParsePrefix("233.252.0.0/24")

// until returns the events ws delivers before the marker.
func (ws *watchStream) until(t *testing.T) []api.RouteResponse {
	t.Helper()
	var got []api.RouteResponse
	for rr := range ws.events {
		if rr.Prefix == markerPrefix.String() {
			return got
		}
		got = append(got, rr)
	}
	t.Fatal("watch stream ended before the marker")
	return nil
}

// RTR-driven revalidation tells raven watch about the routes whose posture
// it changes, as BMP ingest does for the routes it receives: the lab case is
// a SLURM edit moving the only VRP for 198.51.100.0/24 from AS65000 to
// AS64511. A change that leaves posture, ROV and ASPA state as they were is
// not shown, and a watcher's posture filter applies.
func TestRTRRevalidationNotifiesWatch(t *testing.T) {
	s := newTestServer(t)
	peer := netip.MustParseAddr("10.0.0.1")
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	key := types.RouteKey{Peer: types.PeerRef{Addr: peer}, Prefix: prefix, RIBType: types.AdjRIBInPre}
	other := netip.MustParsePrefix("203.0.113.0/24") // no VRP; no delta touches it

	vOld := types.VRP{Prefix: prefix, ASN: 65000, MaxLength: 24}
	vOld25 := types.VRP{Prefix: prefix, ASN: 65000, MaxLength: 25}
	vNew := types.VRP{Prefix: prefix, ASN: 64511, MaxLength: 24}
	s.vrpStore.AddVRP(vOld)
	s.vrpStore.RebuildIndex()
	for _, p := range []netip.Prefix{prefix, other} {
		r := &types.Route{PeerAddr: peer, Prefix: p, ASPath: []uint32{65001, 65000}, RIBType: types.AdjRIBInPre}
		s.engine.ValidateRoute(r)
		s.table.Insert(r)
	}
	start := s.table.Get(key)
	if start.ROV.State != types.ROVValid {
		t.Fatalf("setup: %s ROV = %s, want Valid", prefix, start.ROV.State)
	}

	all := openWatch(t, s, nil)
	invalidOnly := openWatch(t, s, url.Values{"posture": {string(types.PostureOriginInvalid)}})

	// apply changes the VRP store, runs the pass the delta requests to the
	// end, as ingestLoop would, and sends the marker.
	apply := func(add, remove []types.VRP) {
		t.Helper()
		for _, v := range remove {
			s.vrpStore.RemoveVRP(v)
		}
		for _, v := range add {
			s.vrpStore.AddVRP(v)
		}
		s.vrpStore.RebuildIndex()
		s.RequestRevalidationDelta(&store.Delta{VRPAnnounced: add, VRPWithdrawn: remove})
		<-s.revalidateCh
		s.startRevalidation()
		for s.revalidating.Load() {
			s.stepBackground()
		}
		s.apiSrv.NotifyRoute(&types.Route{PeerAddr: peer, Prefix: markerPrefix, RIBType: types.AdjRIBInPre,
			SecurityPosture: types.PostureOriginInvalid})
	}
	expect := func(name string, ws *watchStream, want ...types.SecurityPosture) {
		t.Helper()
		got := ws.until(t)
		if len(got) != len(want) {
			t.Fatalf("%s: watch delivered %d events %+v, want %d", name, len(got), got, len(want))
		}
		for i, rr := range got {
			if rr.Prefix != prefix.String() || rr.PeerAddr != peer.String() || rr.Posture != string(want[i]) {
				t.Fatalf("%s: event %d = %s via %s posture %s, want %s via %s posture %s",
					name, i, rr.Prefix, rr.PeerAddr, rr.Posture, prefix, peer, want[i])
			}
		}
	}

	// A second VRP for the same origin: the route is replaced (it has one
	// more matching VRP) but still Valid, so nothing is shown.
	apply([]types.VRP{vOld25}, nil)
	if got := len(s.table.Get(key).ROV.MatchedVRPs); got != 2 {
		t.Fatalf("detail-only delta: route has %d matching VRPs, want 2 (the pass did not replace it)", got)
	}
	expect("detail-only delta, all", all)
	expect("detail-only delta, posture filter", invalidOnly)

	// The SLURM edit: Valid -> Invalid, one event to each watcher.
	apply([]types.VRP{vNew}, []types.VRP{vOld, vOld25})
	if r := s.table.Get(key); r.ROV.State != types.ROVInvalid || r.SecurityPosture != types.PostureOriginInvalid {
		t.Fatalf("after the edit: ROV %s posture %s, want Invalid / origin-invalid", r.ROV.State, r.SecurityPosture)
	}
	expect("Valid->Invalid, all", all, types.PostureOriginInvalid)
	expect("Valid->Invalid, posture filter", invalidOnly, types.PostureOriginInvalid)

	// Reverted: one event with the restored posture, which the
	// origin-invalid watcher does not see.
	apply([]types.VRP{vOld}, []types.VRP{vNew})
	expect("Invalid->Valid, all", all, start.SecurityPosture)
	expect("Invalid->Valid, posture filter", invalidOnly)
}

// A watcher that stops reading must not stall a pass that changes many
// routes: NotifyRoute drops what that watcher's buffer cannot take, as it
// does for ingest, rather than holding up ingestLoop.
func TestRTRRevalidationDoesNotBlockOnSlowWatcher(t *testing.T) {
	s := newTestServer(t)
	peer := netip.MustParseAddr("192.0.2.1")
	fillValidated(s, peer, sessA, 50_000) // all NotFound: no VRPs yet; ~25MB of events, past any socket buffer

	srv := httptest.NewServer(s.apiSrv.Mux())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/watch")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() // never read

	for _, v := range vrpsOther {
		s.vrpStore.AddVRP(v)
	}
	s.vrpStore.RebuildIndex()
	s.RequestRevalidationDelta(&store.Delta{VRPAnnounced: vrpsOther}) // every route turns Invalid
	<-s.revalidateCh

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.startRevalidation()
		for s.revalidating.Load() {
			s.stepBackground()
		}
	}()
	select {
	case <-done:
	case <-time.After(testWaitBound):
		t.Fatal("revalidation pass blocked on a watcher that does not read")
	}
	if got := lookup2(s, peer, 49_999).ROV.State; got != types.ROVInvalid {
		t.Fatalf("last route ROV = %s, want Invalid", got)
	}
}
