package snapshot_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Every RIB survives a round trip, with the peer type and distinguisher of a
// VRF Loc-RIB; a file naming the Adj-RIB-In pre-policy and post-policy reads
// as before; an unknown RIB is an error, not a silent pre-policy route.
func TestSnapshotRIBs(t *testing.T) {
	w, r, dir := newWriterReader(t, testVersion)
	var routes []*types.Route
	for i, rib := range types.AllRIBTypes {
		rt := syntheticRoute(i)
		rt.RIBType = rib
		routes = append(routes, rt)
	}
	loc := routes[types.LocRIB]
	loc.PeerType, loc.PeerDistinguisher, loc.PeerAddr = types.PeerTypeLocRIB, 0x0002_0000_fde8_0001, mustAddr("0.0.0.0")
	if err := w.WriteRoutes(routes); err != nil {
		t.Fatal(err)
	}
	got, err := r.ReadRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for i, rt := range got {
		if rt.RIBType != routes[i].RIBType || rt.PeerType != routes[i].PeerType ||
			rt.PeerDistinguisher != routes[i].PeerDistinguisher || rt.PeerAddr != routes[i].PeerAddr {
			t.Errorf("route %d: rib %s, peer type %d, rd %#x, peer %v; want %s, %d, %#x, %v", i,
				rt.RIBType, rt.PeerType, rt.PeerDistinguisher, rt.PeerAddr,
				routes[i].RIBType, routes[i].PeerType, routes[i].PeerDistinguisher, routes[i].PeerAddr)
		}
		// A Loc-RIB route's Peer AS is the router's own AS, the origin of
		// an empty AS_PATH; no other RIB's local AS is in the snapshot.
		want := uint32(0)
		if rt.RIBType == types.LocRIB {
			want = routes[i].PeerASN
		}
		if rt.LocalASN != want {
			t.Errorf("route %d (%s): LocalASN %d, want %d", i, rt.RIBType, rt.LocalASN, want)
		}
	}
	if routes[types.LocRIB].PeerASN == 0 {
		t.Fatal("syntheticRoute has no peer AS: the Loc-RIB LocalASN check proves nothing")
	}

	path := filepath.Join(dir, "routes.snap")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"rib_type":"loc-rib"`)) {
		t.Fatalf("routes.snap does not name RIBs as expected:\n%.300s", data)
	}
	// The older names.
	old := bytes.ReplaceAll(data, []byte(`"rib_type":"adj-rib-in-pre"`), []byte(`"rib_type":"pre-policy"`))
	old = bytes.ReplaceAll(old, []byte(`"rib_type":"adj-rib-in-post"`), []byte(`"rib_type":"post-policy"`))
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = r.ReadRoutes()
	if err != nil || got[types.AdjRIBInPre].RIBType != types.AdjRIBInPre || got[types.AdjRIBInPost].RIBType != types.AdjRIBInPost {
		t.Errorf("pre-policy/post-policy names: err %v, RIBs read %v %v", err, got[0].RIBType, got[1].RIBType)
	}
	// An unknown name.
	bad := bytes.Replace(data, []byte(`"rib_type":"loc-rib"`), []byte(`"rib_type":"loc-ribs"`), 1)
	if err := os.WriteFile(path, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadRoutes(); err == nil || !strings.Contains(err.Error(), "loc-ribs") {
		t.Errorf("unknown RIB: err %v, want an error naming it", err)
	}
}
