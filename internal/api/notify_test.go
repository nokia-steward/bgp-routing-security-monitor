package api

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// NotifyRoute runs for every ingested route. With nobody watching it must not
// build the watch response; with a watcher it delivers it as before.
func TestNotifyRoute(t *testing.T) {
	s := NewServer(routetable.New(), nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	r := &types.Route{
		PeerAddr: netip.MustParseAddr("192.0.2.1"),
		Prefix:   netip.MustParsePrefix("198.51.100.0/24"),
		NextHop:  netip.MustParseAddr("192.0.2.1"),
		ASPath:   []uint32{64500, 64501},
	}
	if n := testing.AllocsPerRun(100, func() { s.NotifyRoute(r) }); n != 0 {
		t.Errorf("NotifyRoute with no watchers allocated %v times, want 0", n)
	}

	ch := make(chan RouteResponse, 1)
	s.watchMu.Lock()
	s.watchSubs[ch] = &watcher{}
	s.watchMu.Unlock()
	s.NotifyRoute(r)
	select {
	case rr := <-ch:
		if rr.Prefix != "198.51.100.0/24" || rr.PeerAddr != "192.0.2.1" || rr.OriginASN != 64501 {
			t.Errorf("watcher got %+v", rr)
		}
	default:
		t.Error("watcher got nothing")
	}
}
