package bmp

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// peerDownBody builds a BMP Peer Down message body (per-peer header plus a
// reason byte) for an IPv4 peer.
func peerDownBody(peer netip.Addr) []byte {
	data := make([]byte, PerPeerHeaderLen+1)
	data[0] = PeerTypeGlobal
	a := peer.As4()
	copy(data[22:26], a[:])
	data[PerPeerHeaderLen] = 1 // reason: local system closed, notification sent
	return data
}

// A peer-down must reach the ingest stream even when it is full. It used to
// be sent non-blocking and silently dropped on a full channel, which left
// every route of the downed peer in the Route Table permanently.
func TestPeerDownIsNotDroppedWhenIngestIsFull(t *testing.T) {
	router := netip.MustParseAddr("198.51.100.1")
	peer := netip.MustParseAddr("192.0.2.1")

	ingest := make(chan types.IngestEvent, 1)
	ingest <- types.IngestEvent{Route: &types.Route{}} // channel is now full

	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(io.Discard, nil)))
	l.peers[PeerKey{RouterAddr: router, PeerAddr: peer}] = &Peer{Addr: peer, State: "up"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		l.processMessage(context.Background(), l.log, &bmpSession{id: 3, router: router},
			BMPCommonHeader{Version: 3, MsgType: MsgTypePeerDown}, peerDownBody(peer))
	}()

	// Make room only after the handler has had time to hit the full channel.
	time.Sleep(50 * time.Millisecond)
	<-ingest

	select {
	case ev := <-ingest:
		if ev.Withdrawal == nil || !ev.Withdrawal.WithdrawAll || ev.Withdrawal.PeerAddr != peer {
			t.Fatalf("got %+v, want a withdraw-all for %s", ev, peer)
		}
		if ev.Withdrawal.Router != router {
			t.Errorf("withdraw-all for router %s, want %s: it must not reach other routers' routes", ev.Withdrawal.Router, router)
		}
		if ev.Session != 3 {
			t.Errorf("withdraw-all session = %d, want 3 (scoped to the session that saw the peer down)", ev.Session)
		}
	case <-time.After(testWaitBound):
		t.Fatal("no withdraw-all for the downed peer — the signal was dropped")
	}
	<-done

	peers := l.GetPeers()
	if len(peers) != 1 {
		t.Fatalf("GetPeers returned %d peers, want 1", len(peers))
	}
	if peers[0].State != "down" {
		t.Errorf("peer state = %q, want down", peers[0].State)
	}
}

// Blocking on a full ingest stream must still give way to shutdown.
func TestEmitReturnsOnCancelledContext(t *testing.T) {
	ingest := make(chan types.IngestEvent) // unbuffered, nobody reading
	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l.emit(ctx, types.IngestEvent{Withdrawal: &types.Withdrawal{WithdrawAll: true}}) {
		t.Error("emit reported success with a cancelled context and no reader")
	}
}
