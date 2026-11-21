package bmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// bmpMsg frames body as a BMP v3 message of the given type.
func bmpMsg(msgType uint8, body []byte) []byte {
	b := make([]byte, CommonHeaderLen, CommonHeaderLen+len(body))
	b[0] = 3
	binary.BigEndian.PutUint32(b[1:5], uint32(CommonHeaderLen+len(body)))
	b[5] = msgType
	return append(b, body...)
}

// perPeerHeader builds a per-peer header for an IPv4 global peer.
func perPeerHeader(peer netip.Addr) []byte {
	h := make([]byte, PerPeerHeaderLen)
	h[0] = PeerTypeGlobal
	a := peer.As4()
	copy(h[22:26], a[:])
	binary.BigEndian.PutUint32(h[26:30], 64501) // peer AS
	return h
}

func initiationMsg(sysName string) []byte {
	return bmpMsg(MsgTypeInitiation, appendTLV(nil, InitTLVSysName, sysName))
}

func peerUpMsg(peer netip.Addr) []byte {
	// Local address and ports; no embedded OPENs, so LocalASN stays 0.
	return bmpMsg(MsgTypePeerUp, append(perPeerHeader(peer), make([]byte, 20)...))
}

// routeMonitoringMsg builds a Route Monitoring message carrying a BGP UPDATE
// that announces the given IPv4 /24s from peer.
func routeMonitoringMsg(peer netip.Addr, prefixes ...netip.Prefix) []byte {
	attrs := []byte{
		0x40, 1, 1, 0, // ORIGIN IGP
		0x40, 2, 6, 2, 1, 0, 0, 0xfb, 0xf5, // AS_PATH: AS_SEQUENCE [64501]
		0x40, 3, 4, 192, 0, 2, 254, // NEXT_HOP
	}
	var nlri []byte
	for _, p := range prefixes {
		a := p.Addr().As4()
		nlri = append(nlri, 24, a[0], a[1], a[2])
	}
	update := []byte{0, 0} // no withdrawn routes
	update = binary.BigEndian.AppendUint16(update, uint16(len(attrs)))
	update = append(update, attrs...)
	update = append(update, nlri...)

	bgp := bytes.Repeat([]byte{0xff}, 16)
	bgp = binary.BigEndian.AppendUint16(bgp, uint16(19+len(update)))
	bgp = append(bgp, 2) // UPDATE
	bgp = append(bgp, update...)
	return bmpMsg(MsgTypeRouteMonitoring, append(perPeerHeader(peer), bgp...))
}

// syncBuffer is a bytes.Buffer safe for a logger and a test to share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// sessionHarness accepts real TCP connections from 127.0.0.1 and hands them
// to the Listener the way Start's accept loop does.
type sessionHarness struct {
	l      *Listener
	ln     net.Listener
	ingest chan types.IngestEvent
	logs   *syncBuffer
}

func newSessionHarness(t *testing.T, ingest chan types.IngestEvent) *sessionHarness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	logs := &syncBuffer{}
	return &sessionHarness{
		l:      NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(logs, nil))),
		ln:     ln,
		ingest: ingest,
		logs:   logs,
	}
}

// connect opens a router connection and starts its session handler. done is
// closed when the handler returns.
func (h *sessionHarness) connect(ctx context.Context, t *testing.T) (client net.Conn, done <-chan struct{}) {
	t.Helper()
	client, _, done = h.connectSession(ctx, t)
	return client, done
}

func (h *sessionHarness) connectSession(ctx context.Context, t *testing.T) (client net.Conn, sess *bmpSession, done <-chan struct{}) {
	t.Helper()
	client, err := net.Dial("tcp", h.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := h.ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	sess, old := h.l.register(server)
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		h.l.handleSession(ctx, sess, old)
	}()
	return client, sess, ch
}

// testWaitBound caps how long a test waits for something to happen. It is
// not a timing assertion: it only stops a broken test from hanging, so it is
// far above anything a loaded machine under -race needs.
const testWaitBound = 60 * time.Second

func (h *sessionHarness) next(t *testing.T) types.IngestEvent {
	t.Helper()
	select {
	case ev := <-h.ingest:
		return ev
	case <-time.After(testWaitBound):
		t.Fatalf("no ingest event within %v", testWaitBound)
		return types.IngestEvent{}
	}
}

func send(t *testing.T, c net.Conn, msgs ...[]byte) {
	t.Helper()
	for _, m := range msgs {
		if _, err := c.Write(m); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWaitBound)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A router that opens a new BMP session while its old socket is still open
// supersedes the old session: the old socket is closed, the replacement is
// logged at WARN, the old session's withdraw-all is scoped to its own
// session ID, and its cleanup leaves the new session's peer and router
// state alone.
func TestNewSessionSupersedesStaleSessionFromSameRouter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Unbuffered: the stale session's final withdraw-all blocks until the
	// test reads it, which holds its cleanup back until the new session
	// has registered its peer. That is the ordering that used to delete
	// the new session's peer.
	h := newSessionHarness(t, make(chan types.IngestEvent))
	peer := netip.MustParseAddr("192.0.2.1")
	x := netip.MustParsePrefix("10.9.1.0/24")
	y := netip.MustParsePrefix("10.9.2.0/24")

	clientA, doneA := h.connect(ctx, t)
	send(t, clientA, initiationMsg("br1.nyc"), peerUpMsg(peer), routeMonitoringMsg(peer, x, y))
	var sessA uint64
	for range 2 {
		ev := h.next(t)
		if ev.Route == nil || ev.Route.PeerAddr != peer {
			t.Fatalf("got %+v from session A, want a route from %s", ev, peer)
		}
		if ev.Session == 0 || (sessA != 0 && ev.Session != sessA) {
			t.Fatalf("route session = %d, want one non-zero ID for all of session A (first was %d)", ev.Session, sessA)
		}
		sessA = ev.Session
	}

	clientB, doneB := h.connect(ctx, t)

	// The Route Table is told first, then the stale socket is closed from
	// our side.
	if ev := h.next(t); !ev.Superseded || ev.Session != sessA {
		t.Fatalf("got %+v, want the notice that session A (%d) was superseded", ev, sessA)
	}
	if err := clientA.SetReadDeadline(time.Now().Add(testWaitBound)); err != nil {
		t.Fatal(err)
	}
	if _, err := clientA.Read(make([]byte, 1)); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("stale session's socket was not closed when the new session started")
	}

	send(t, clientB, initiationMsg("br1.nyc"), peerUpMsg(peer))
	key := PeerKey{RouterAddr: netip.MustParseAddr("127.0.0.1"), PeerAddr: peer}
	var sessB uint64
	waitFor(t, "session B's peer up", func() bool {
		h.l.peerMu.RLock()
		defer h.l.peerMu.RUnlock()
		if p := h.l.peers[key]; p != nil && p.session != sessA {
			sessB = p.session
			return true
		}
		return false
	})
	if sessB <= sessA {
		t.Fatalf("session B ID = %d, want greater than session A's %d", sessB, sessA)
	}

	ev := h.next(t)
	if ev.Withdrawal == nil || !ev.Withdrawal.SessionEnd || ev.Session != sessA {
		t.Fatalf("got %+v, want session A's (%d) session-end withdraw-all", ev, sessA)
	}
	<-doneA

	if !strings.Contains(h.logs.String(), `level=WARN msg="superseding stale BMP session"`) {
		t.Errorf("no WARN for the superseded session; logs:\n%s", h.logs)
	}
	peers := h.l.GetPeers()
	if len(peers) != 1 || peers[0].State != "up" {
		t.Errorf("GetPeers = %+v after the stale session ended, want session B's peer, up", peers)
	}
	if states := h.l.GetRouterStates(); states["br1.nyc"] != 1 {
		t.Errorf("GetRouterStates = %v after the stale session ended, want br1.nyc up", states)
	}

	send(t, clientB, routeMonitoringMsg(peer, x))
	if ev := h.next(t); ev.Route == nil || ev.Route.Prefix != x || ev.Session != sessB {
		t.Fatalf("got %+v, want route %s from session B (%d)", ev, x, sessB)
	}

	clientB.Close()
	if ev := h.next(t); ev.Withdrawal == nil || !ev.Withdrawal.SessionEnd || ev.Session != sessB {
		t.Fatalf("got %+v, want session B's (%d) session-end withdraw-all", ev, sessB)
	}
	<-doneB
	if peers := h.l.GetPeers(); len(peers) != 0 {
		t.Errorf("GetPeers = %+v after the last session ended, want none", peers)
	}
}

// Once superseded, a session puts nothing more on the ingest stream from a
// message it was still processing, and does not touch peer state.
func TestRetiredSessionEmitsNothing(t *testing.T) {
	router := netip.MustParseAddr("198.51.100.1")
	peer := netip.MustParseAddr("192.0.2.1")
	ingest := make(chan types.IngestEvent, 10)
	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))

	server, client := net.Pipe()
	defer client.Close()
	sess := &bmpSession{id: 7, router: router, conn: server}
	l.retire(context.Background(), sess)
	if ev := <-ingest; !ev.Superseded || ev.Session != 7 {
		t.Fatalf("got %+v, want the notice that session 7 was superseded", ev)
	}

	l.processMessage(context.Background(), l.log, sess,
		BMPCommonHeader{Version: 3, MsgType: MsgTypePeerUp}, peerUpMsg(peer)[CommonHeaderLen:])
	l.processMessage(context.Background(), l.log, sess,
		BMPCommonHeader{Version: 3, MsgType: MsgTypeRouteMonitoring},
		routeMonitoringMsg(peer, netip.MustParsePrefix("10.9.1.0/24"))[CommonHeaderLen:])
	if l.emitFrom(context.Background(), sess, types.IngestEvent{Route: &types.Route{}}) {
		t.Error("emitFrom reported success for a retired session")
	}
	if n := len(ingest); n != 0 {
		t.Errorf("retired session emitted %d events, want 0", n)
	}
	if peers := l.GetPeers(); len(peers) != 0 {
		t.Errorf("retired session's Peer Up registered %d peers, want 0", len(peers))
	}

	// A live session's events go through, stamped with its ID.
	if !l.emitFrom(context.Background(), &bmpSession{id: 8}, types.IngestEvent{Route: &types.Route{}}) {
		t.Fatal("emitFrom failed for a live session")
	}
	if ev := <-ingest; ev.Session != 8 {
		t.Errorf("emitFrom stamped session %d, want 8", ev.Session)
	}
}

// A takeover while the old session is blocked sending on a full ingest
// stream: the blocked event is handed over before the Route Table is told
// the old session was superseded, and nothing else of the old session's but
// its session end follows the notice. (The Route Table drops anything of a
// superseded session's that does arrive after it; see the server package.)
func TestTakeoverWaitsOutBlockedSendThenMarksSessionSuperseded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newSessionHarness(t, make(chan types.IngestEvent)) // full until the test reads
	peer := netip.MustParseAddr("192.0.2.1")
	x := netip.MustParsePrefix("10.9.1.0/24")

	// Signalled with session A's send lock held, just before it sends its
	// route on a stream nobody is reading: from then on A is blocked in that
	// send until the test reads.
	aboutToSend := make(chan struct{}, 1)
	h.l.testBeforeSend = func(_ *bmpSession, ev types.IngestEvent) {
		if ev.Route != nil && ev.Route.Prefix == x {
			select {
			case aboutToSend <- struct{}{}:
			default: // session B's route later
			}
		}
	}

	clientA, sessA, doneA := h.connectSession(ctx, t)
	send(t, clientA, peerUpMsg(peer), routeMonitoringMsg(peer, x))
	select {
	case <-aboutToSend:
	case <-time.After(testWaitBound):
		t.Fatal("session A never sent its route")
	}

	clientB, sessB, doneB := h.connectSession(ctx, t)

	if ev := h.next(t); ev.Route == nil || ev.Route.Prefix != x || ev.Session != sessA.id {
		t.Fatalf("got %+v, want session A's blocked route first", ev)
	}
	if ev := h.next(t); !ev.Superseded || ev.Session != sessA.id {
		t.Fatalf("got %+v, want the notice that session A was superseded", ev)
	}
	if ev := h.next(t); ev.Withdrawal == nil || !ev.Withdrawal.SessionEnd || ev.Session != sessA.id {
		t.Fatalf("got %+v, want session A's session end", ev)
	}
	<-doneA

	send(t, clientB, peerUpMsg(peer), routeMonitoringMsg(peer, x))
	if ev := h.next(t); ev.Route == nil || ev.Route.Prefix != x || ev.Session != sessB.id {
		t.Fatalf("got %+v, want session B's route", ev)
	}
	clientB.Close()
	if ev := h.next(t); ev.Withdrawal == nil || !ev.Withdrawal.SessionEnd || ev.Session != sessB.id {
		t.Fatalf("got %+v, want session B's session end", ev)
	}
	<-doneB
}

// A session that has already sent its session end gets no superseded
// notice, which the Route Table would otherwise keep tracking forever.
func TestRetiringEndedSessionSendsNoNotice(t *testing.T) {
	ingest := make(chan types.IngestEvent, 1)
	l := NewListener("127.0.0.1:0", nil, ingest, slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))
	server, client := net.Pipe()
	defer client.Close()
	sess := &bmpSession{id: 4, conn: server, ended: true}
	l.retire(context.Background(), sess)
	if n := len(ingest); n != 0 {
		t.Errorf("retiring an ended session emitted %d events, want 0", n)
	}
}
