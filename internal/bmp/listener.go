package bmp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Listener accepts BMP connections from routers and processes messages.
type Listener struct {
	addr     string
	tlsCfg   *tls.Config // nil = plain TCP
	log      *slog.Logger
	ingestCh chan<- types.IngestEvent
	peerMu   sync.RWMutex
	peers    map[PeerKey]*Peer
	// peersGen counts changes to peers that confedIDs depend on (Peer Up,
	// Peer Down, session cleanup); confedIDs caches, per router instance,
	// the confederation identifier inferred from its peers (see confedID).
	// An entry from an older generation is stale. confedMembers records,
	// per instance, the member AS of the sessions it has sent routes with
	// confederation segments on: proof it is in a confederation. All are
	// guarded by peerMu.
	peersGen      uint64
	confedIDs     map[instanceKey]confedIDEntry
	confedMembers map[instanceKey]uint32
	routerMu      sync.RWMutex
	routers       map[netip.Addr]routerInfo
	listener      net.Listener

	// allowed lists the source prefixes BMP connections are accepted from
	// (IPv4 sources in plain form); empty accepts any.
	allowed []netip.Prefix

	lastSession atomic.Uint64 // last session ID handed out; IDs start at 1
	sessMu      sync.Mutex
	sessions    map[netip.Addr]*bmpSession // the current session per router address

	// malformedWarn rate-limits the WARN for malformed UPDATEs.
	malformedWarn warnLimiter

	// testBeforeSend, nil in production, runs in emitFrom with the
	// session's send lock held, just before the send.
	testBeforeSend func(*bmpSession, types.IngestEvent)
}

// routerInfo is what Initiation told us about a router, and which session
// told us. sysName is the metrics label (the address when Initiation gave
// no name); name is the sysName as sent, empty if none.
type routerInfo struct {
	sysName string
	name    string
	session uint64
}

// bmpSession is one accepted BMP connection.
type bmpSession struct {
	id     uint64
	router netip.Addr
	conn   net.Conn

	// mu is held for each send on the ingest stream so that retire can
	// wait out a send in progress: once retire returns, the session puts
	// nothing more on the stream but its final session-end withdrawal.
	mu      sync.Mutex
	retired bool
	ended   bool // its session-end withdrawal has been sent
}

// retire stops a superseded session from emitting any further routes or
// withdrawals, tells the Route Table so it drops anything of the session's
// still in flight, then closes the session's socket.
func (l *Listener) retire(ctx context.Context, s *bmpSession) {
	s.mu.Lock()
	// Once its session end has gone out the session has nothing left to
	// send, and the Route Table must not start tracking it.
	if !s.ended {
		l.emit(ctx, types.IngestEvent{Session: s.id, Superseded: true})
	}
	s.retired = true
	s.mu.Unlock()
	s.conn.Close()
}

func (s *bmpSession) isRetired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retired
}

// NewListener creates a BMP listener that sends parsed routes and withdrawals,
// in arrival order, to ingestCh.
// If tlsCfg is non-nil, the listener accepts TLS connections; otherwise plain TCP.
func NewListener(addr string, tlsCfg *tls.Config, ingestCh chan<- types.IngestEvent, log *slog.Logger) *Listener {
	return &Listener{
		addr:          addr,
		tlsCfg:        tlsCfg,
		log:           log.With("subsystem", "bmp"),
		ingestCh:      ingestCh,
		peers:         make(map[PeerKey]*Peer),
		confedIDs:     make(map[instanceKey]confedIDEntry),
		confedMembers: make(map[instanceKey]uint32),
		routers:       make(map[netip.Addr]routerInfo),
		sessions:      make(map[netip.Addr]*bmpSession),
	}
}

// emit sends ev on the ingest stream, blocking until there is room. It
// returns false only if ctx is cancelled first.
//
// Nothing on this stream may be dropped: a lost withdraw-all leaves every
// route of a downed peer in the Route Table for good. A full channel instead
// applies backpressure to this router's session.
func (l *Listener) emit(ctx context.Context, ev types.IngestEvent) bool {
	// select picks randomly among ready cases; check first so nothing new is
	// queued once shutdown has begun.
	if ctx.Err() != nil {
		return false
	}
	select {
	case l.ingestCh <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// emitFrom sends ev on the ingest stream on behalf of sess, stamped with its
// session ID. It returns false, sending nothing, if sess has been superseded.
func (l *Listener) emitFrom(ctx context.Context, sess *bmpSession, ev types.IngestEvent) bool {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.retired {
		return false
	}
	ev.Session = sess.id
	if l.testBeforeSend != nil {
		l.testBeforeSend(sess, ev)
	}
	return l.emit(ctx, ev)
}

// register makes a new session for conn the current one for its router
// address and returns it, along with the still-open session it replaces, if
// any. Called from the accept loop, so session IDs increase in the order
// connections were accepted.
//
// Sessions are matched by source IP alone. Routers behind one NAT address
// therefore look like a single router reconnecting, and each new session
// from any of them supersedes, and closes, the others'.
func (l *Listener) register(conn net.Conn) (sess, old *bmpSession) {
	routerAddr, _ := remoteIP(conn)
	sess = &bmpSession{id: l.lastSession.Add(1), router: routerAddr.Unmap(), conn: conn}
	l.sessMu.Lock()
	old = l.sessions[sess.router]
	l.sessions[sess.router] = sess
	l.sessMu.Unlock()
	return sess, old
}

// BuildTLSConfig assembles a server-side *tls.Config from the operator-supplied
// paths. Cert and Key are required (BMP TLS is server auth). If CA is present,
// mutual TLS is enabled and client certs are required.
func BuildTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("BMP TLS config is nil")
	}
	if cfg.Cert == "" || cfg.Key == "" {
		return nil, fmt.Errorf("BMP TLS requires both cert and key paths")
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load BMP TLS keypair: %w", err)
	}

	out := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   cfg.TLSMinVersion(),
	}

	if cfg.CA != "" {
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("read BMP TLS CA %q: %w", cfg.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse BMP TLS CA %q: no PEM certificates found", cfg.CA)
		}
		out.ClientCAs = pool
		out.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return out, nil
}

// SetAllowedRouters restricts BMP connections to sources in prefixes (see
// config.ParseAllowedRouters); nil or empty accepts any source. Call before
// Listen.
func (l *Listener) SetAllowedRouters(prefixes []netip.Prefix) {
	l.allowed = prefixes
}

// Listen binds the BMP listener and returns the address it is bound to.
// Start calls it if it has not been called.
func (l *Listener) Listen() (net.Addr, error) {
	if l.listener != nil {
		return l.listener.Addr(), nil
	}
	var err error
	transport := "tcp"
	if l.tlsCfg != nil {
		l.listener, err = tls.Listen("tcp", l.addr, l.tlsCfg)
		transport = "tls"
	} else {
		l.listener, err = net.Listen("tcp", l.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("BMP listen on %s: %w", l.addr, err)
	}
	bound := l.listener.Addr()
	l.log.Info("BMP listener started", "addr", bound.String(), "transport", transport,
		"allowed_routers", len(l.allowed))
	if len(l.allowed) == 0 {
		if tcp, ok := bound.(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
			l.log.Warn("BMP listener accepts connections from any source on a non-loopback address; "+
				"set bmp.allowed-routers to the routers' addresses", "addr", bound.String())
		}
	}
	return bound, nil
}

// permits reports whether a BMP connection from addr may proceed. An
// IPv4-mapped IPv6 source is matched as IPv4.
func (l *Listener) permits(addr netip.Addr) bool {
	if len(l.allowed) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, p := range l.allowed {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteIP returns conn's source address. From a dual-stack socket an IPv4
// source comes as IPv4-mapped IPv6; permits matches it as IPv4.
func remoteIP(conn net.Conn) (netip.Addr, bool) {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ap := tcp.AddrPort()
		return ap.Addr(), ap.Addr().IsValid()
	}
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	return ap.Addr(), err == nil
}

// admit decides, before anything is read from conn, whether it may become a
// BMP session. A rejected connection is logged, counted and closed.
func (l *Listener) admit(conn net.Conn) bool {
	if len(l.allowed) == 0 {
		return true
	}
	reason := metrics.RejectReasonNotAllowed
	if src, ok := remoteIP(conn); !ok {
		reason = metrics.RejectReasonBadRemoteAddr
	} else if l.permits(src) {
		return true
	}
	metrics.BMPRejectedConnectionsTotal.WithLabelValues(reason).Inc()
	l.log.Warn("BMP connection rejected: source not in bmp.allowed-routers",
		"remote", conn.RemoteAddr().String(), "reason", reason)
	conn.Close()
	return false
}

// Start begins listening for BMP connections. Blocks until ctx is cancelled.
func (l *Listener) Start(ctx context.Context) error {
	if _, err := l.Listen(); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		l.listener.Close()
	}()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutting down
			}
			l.log.Error("BMP accept error", "error", err)
			continue
		}
		// Before reading a byte (for TLS, before the handshake).
		if !l.admit(conn) {
			continue
		}

		sess, old := l.register(conn)
		l.log.Info("BMP session accepted", "remote", conn.RemoteAddr().String(), "session", sess.id)

		// One goroutine per BMP session (per the architecture doc)
		go l.handleSession(ctx, sess, old)
	}
}

// GetPeers returns a snapshot of all known peers.
func (l *Listener) GetPeers() []Peer {
	l.peerMu.RLock()
	defer l.peerMu.RUnlock()

	result := make([]Peer, 0, len(l.peers))
	for _, p := range l.peers {
		result = append(result, *p)
	}
	return result
}

// RouterName returns the sysName a router sent in its BMP Initiation, or ""
// if it sent none or has no session now.
func (l *Listener) RouterName(router netip.Addr) string {
	l.routerMu.RLock()
	defer l.routerMu.RUnlock()
	return l.routers[router.Unmap()].name
}

// RoutersNamed returns the routers with a session now whose Initiation
// sysName is name.
func (l *Listener) RoutersNamed(name string) []netip.Addr {
	l.routerMu.RLock()
	defer l.routerMu.RUnlock()
	var out []netip.Addr
	for addr, r := range l.routers {
		if r.name != "" && r.name == name {
			out = append(out, addr)
		}
	}
	return out
}

// GetRouterStates returns the current BMP session state for every router
// that has sent an Initiation message. Only up sessions appear (1=up);
// sessions that disconnected are removed from the map by handleSession.
func (l *Listener) GetRouterStates() map[string]int64 {
	l.routerMu.RLock()
	defer l.routerMu.RUnlock()

	result := make(map[string]int64, len(l.routers))
	for _, r := range l.routers {
		result[r.sysName] = 1
	}
	return result
}

// handleSession processes a single BMP session (one TCP connection = one
// router). old, if non-nil, is an earlier session from the same router
// address that is still open; sess supersedes it.
func (l *Listener) handleSession(ctx context.Context, sess, old *bmpSession) {
	conn := sess.conn
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	sessionLog := l.log.With("router", remoteAddr, "session", sess.id)
	sessionLog.Info("BMP session started")

	// Takeover. A router opens a new session while the old socket is still
	// open when it has given up on the old one (e.g. it judged the station
	// stuck). Retire the old one before reading anything, so all of its
	// remaining output reaches the ingest stream ahead of ours and it cannot
	// deliver late updates or withdrawals over the routes we are about to
	// send; the Route Table also drops anything of its that arrives after
	// the retirement.
	//
	// "Same router" means same source IP (see register): routers sharing
	// one NAT address would supersede each other's sessions.
	if old != nil {
		sessionLog.Warn("superseding stale BMP session", "stale_session", old.id)
		l.retire(ctx, old)
	}

	defer func() {
		sessionLog.Info("BMP session ended")
		// Withdraw every route this session still owns, from all of its
		// peers. Routes a newer session has re-announced since are that
		// session's and stay. Sent even if this session was superseded.
		// emit fails only when shutting down. Under sess.mu, so a
		// takeover's retirement notice cannot follow it.
		sess.mu.Lock()
		sess.ended = true
		l.emit(ctx, types.IngestEvent{
			Withdrawal: &types.Withdrawal{SessionEnd: true},
			Session:    sess.id,
		})
		sess.mu.Unlock()

		l.sessMu.Lock()
		if l.sessions[sess.router] == sess {
			delete(l.sessions, sess.router)
		}
		l.sessMu.Unlock()

		// Clean up this session's peers. A newer session from the same
		// router may have replaced some entries already; leave those. Their
		// raven_bmp_peer_state goes to 0: it stayed at 1 once the session
		// was gone, for every peer without a Peer Down before the end.
		l.peerMu.Lock()
		for key, p := range l.peers {
			if key.RouterAddr == sess.router && p.session == sess.id {
				delete(l.peers, key)
				setPeerState(p.SysName, key, 0)
			}
		}
		for inst := range l.confedIDs {
			if inst.router == sess.router {
				delete(l.confedIDs, inst)
			}
		}
		for inst := range l.confedMembers {
			if inst.router == sess.router {
				delete(l.confedMembers, inst)
			}
		}
		l.peersGen++
		l.peerMu.Unlock()

		// Clean up router state, unless a newer session owns it now.
		l.routerMu.Lock()
		r, ok := l.routers[sess.router]
		if ok && r.session != sess.id {
			l.routerMu.Unlock()
			return
		}
		delete(l.routers, sess.router)
		l.routerMu.Unlock()
		sysName := r.sysName
		if sysName == "" {
			sysName = remoteAddr
		}
		metrics.BMPSessionState.WithLabelValues(sysName).Set(0)
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		hdrBuf := make([]byte, CommonHeaderLen)
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			sessionLog.Error("failed to read BMP header", "error", err)
			return
		}
		hdr, err := ParseCommonHeader(hdrBuf)
		if err != nil {
			sessionLog.Error("invalid BMP header", "error", err)
			return
		}
		bodyLen := int(hdr.Length) - CommonHeaderLen
		if bodyLen < 0 || hdr.Length > MaxMessageLen {
			// The body is allocated at the length the header gives, so an
			// unchecked length let one header allocate up to 4 GB.
			sessionLog.Error("invalid BMP message length", "length", hdr.Length, "max", MaxMessageLen)
			return
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(conn, body); err != nil {
				sessionLog.Error("failed to read BMP body", "error", err)
				return
			}
		}
		l.processMessage(ctx, sessionLog, sess, hdr, body)
	}
}

// processMessage dispatches a parsed BMP message by type.
func (l *Listener) processMessage(
	ctx context.Context,
	log *slog.Logger,
	sess *bmpSession,
	hdr BMPCommonHeader,
	body []byte,
) {
	// A superseded session's router and peer state belong to its successor.
	if sess.isRetired() {
		return
	}
	routerAddr := sess.router
	switch hdr.MsgType {
	case MsgTypeInitiation:
		init, err := ParseInitiation(body)
		if err != nil {
			log.Error("failed to parse initiation", "error", err)
			return
		}
		// Store sysName for use as Prometheus label
		sysName := init.SysName
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.routerMu.Lock()
		l.routers[routerAddr] = routerInfo{sysName: sysName, name: init.SysName, session: sess.id}
		l.routerMu.Unlock()
		metrics.BMPSessionState.WithLabelValues(sysName).Set(1)
		log.Info("BMP initiation", "sysName", sysName, "sysDescr", init.SysDescr)

	case MsgTypePeerUp:
		pu, err := ParsePeerUp(body)
		if err != nil {
			log.Error("failed to parse peer up", "error", err)
			return
		}
		key := peerKey(routerAddr, pu.PerPeer)
		l.routerMu.RLock()
		sysName := l.routers[routerAddr].sysName
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		localASN := pu.LocalASN
		if pu.PerPeer.IsLocRIB() {
			localASN = pu.PerPeer.PeerASN // its OPENs are fabricated (RFC 9069 §5.1)
		}
		l.peerMu.Lock()
		l.peers[key] = &Peer{
			Router:        routerAddr,
			Distinguisher: key.Distinguisher,
			PeerType:      pu.PerPeer.PeerType,
			Addr:          pu.PerPeer.PeerAddr,
			ASN:           pu.PerPeer.PeerASN,
			LocalASN:      localASN,
			RouterID:      pu.PerPeer.PeerBGPID,
			TableName:     pu.TableName,
			SysName:       sysName,
			State:         "up",
			UpSince:       time.Now(),
			LastMsg:       time.Now(),
			session:       sess.id,
			addPath:       pu.AddPath,
		}
		l.peersGen++
		l.peerMu.Unlock()
		setPeerState(sysName, key, 1)
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "peer_up").Inc()
		if pu.PerPeer.IsLocRIB() {
			logLocRIBRegistered(log, key, pu.PerPeer, true, pu.TableName)
		}
		log.Info("BMP peer up",
			"peer", pu.PerPeer.PeerAddr,
			"peer_type", types.PeerTypeName(pu.PerPeer.PeerType),
			"asn", pu.PerPeer.PeerASN,
			"local_asn", localASN,
			"router_id", pu.PerPeer.PeerBGPID,
			"peer_distinguisher", key.Distinguisher,
			"table_name", pu.TableName,
			"add_path_in", pu.AddPath.In, "add_path_out", pu.AddPath.Out,
		)

	case MsgTypePeerDown:
		pd, err := ParsePeerDown(body)
		if err != nil {
			log.Error("failed to parse peer down", "error", err)
			return
		}
		key := peerKey(routerAddr, pd.PerPeer)
		l.routerMu.RLock()
		sysName := l.routers[routerAddr].sysName
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.peerMu.Lock()
		if p, ok := l.peers[key]; ok {
			p.State = "down"
			p.LastMsg = time.Now()
		}
		l.peersGen++
		l.peerMu.Unlock()
		setPeerState(sysName, key, 0)
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "peer_down").Inc()
		log.Info("BMP peer down", "peer", pd.PerPeer.PeerAddr,
			"peer_type", types.PeerTypeName(pd.PerPeer.PeerType), "reason", pd.Reason)
		// Implicitly withdraw everything the peer advertised, as a real BGP
		// session going down would. A Loc-RIB instance's Peer Down clears
		// its Loc-RIB only, a BGP peer's its Adj-RIBs only.
		l.emitFrom(ctx, sess, types.IngestEvent{Withdrawal: &types.Withdrawal{
			Router:            routerAddr,
			PeerDistinguisher: key.Distinguisher,
			PeerAddr:          pd.PerPeer.PeerAddr,
			RIBType:           ribTypeOf(pd.PerPeer),
			WithdrawAll:       true,
		}})

	case MsgTypeRouteMonitoring:
		l.routerMu.RLock()
		sysName := l.routers[routerAddr].sysName
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "route_monitoring").Inc()

		rm, err := ParseRouteMonitoring(body)
		if err != nil {
			log.Debug("failed to parse route monitoring", "error", err)
			return
		}
		key := peerKey(routerAddr, rm.PerPeer)
		routes, withdrawals, bad := l.parseRoutes(rm, routerAddr)
		if bad.action != actNone {
			l.reportMalformed(log, sysName, key, rm.PerPeer, bad, len(withdrawals), rm.BGPUpdateData)
		}
		if bad.action == actSessionReset {
			// The router resets the peer's session (RFC 7606); its Peer
			// Down will withdraw the rest. Until then, show that RAVEN's
			// view of this peer may be incomplete.
			l.peerMu.Lock()
			if p, ok := l.peers[key]; ok && !p.MalformedInput {
				p.MalformedInput = true
				p.MalformedReason = bad.reason
				p.MalformedAt = time.Now()
			}
			l.peerMu.Unlock()
		}
		if rm.PerPeer.IsLocRIB() && len(routes)+len(withdrawals) > 0 {
			l.registerLocRIB(log, sess, sysName, key, rm.PerPeer)
		}
		// A per-peer header timestamp of 0 means the router gave none (RFC
		// 7854 §4.2); stamp RAVEN's receive time instead.
		now := time.Now()
		for i := range routes {
			if routes[i].Timestamp.Equal(bmpNoTimestamp) {
				routes[i].Timestamp = now
			}
		}
		for i := range routes {
			if !l.emitFrom(ctx, sess, types.IngestEvent{Route: &routes[i]}) {
				return
			}
		}
		for i := range withdrawals {
			if !l.emitFrom(ctx, sess, types.IngestEvent{Withdrawal: &withdrawals[i]}) {
				return
			}
		}

		// Update peer last-message time. Its route count is the route
		// table's (routetable.Table.PeerRouteCounts), not counted here: an
		// UPDATE re-announcing a route adds nothing, and withdrawals remove.
		l.peerMu.Lock()
		if p, ok := l.peers[key]; ok {
			p.LastMsg = time.Now()
		}
		l.peerMu.Unlock()

	case MsgTypeStatisticsReport:
		_, err := ParseStatsReport(body)
		if err != nil {
			log.Debug("failed to parse stats report", "error", err)
			return
		}
		// TODO: expose as Prometheus metrics

	case MsgTypeTermination:
		log.Info("BMP termination received")
		return

	default:
		log.Debug("unknown BMP message type", "type", hdr.MsgType)
	}
}

// bmpNoTimestamp is a per-peer header timestamp of zero: none given.
var bmpNoTimestamp = time.Unix(0, 0)

// registerLocRIB records a Loc-RIB instance that sends routes or withdrawals
// with no Peer Up from this session before them, as FRR 10.2 does, or after
// its Peer Down: without it the instance was missing from the peers and its
// raven_bmp_peer_state. An End-of-RIB alone does not register it. Its routes
// are owned by the session either way, so they are withdrawn when the
// session ends.
func (l *Listener) registerLocRIB(log *slog.Logger, sess *bmpSession, sysName string, key PeerKey, pph BMPPerPeerHeader) {
	l.peerMu.Lock()
	if p, ok := l.peers[key]; ok && p.State == "up" && p.session == sess.id {
		l.peerMu.Unlock()
		return
	}
	now := time.Now()
	tableName := locRIBTableName(pph)
	l.peers[key] = &Peer{
		Router:        key.RouterAddr,
		Distinguisher: key.Distinguisher,
		PeerType:      pph.PeerType,
		Addr:          pph.PeerAddr,
		ASN:           pph.PeerASN,
		LocalASN:      pph.PeerASN,
		RouterID:      pph.PeerBGPID,
		TableName:     tableName,
		SysName:       sysName,
		State:         "up",
		UpSince:       now,
		LastMsg:       now,
		session:       sess.id,
	}
	l.peerMu.Unlock()
	setPeerState(sysName, key, 1)
	logLocRIBRegistered(log, key, pph, false, tableName)
}

// logLocRIBRegistered logs, at INFO, a Loc-RIB instance becoming a peer:
// from its Peer Up, or from routes sent without one.
func logLocRIBRegistered(log *slog.Logger, key PeerKey, pph BMPPerPeerHeader, peerUp bool, tableName string) {
	log.Info("BMP Loc-RIB registered",
		"peer_up", peerUp,
		"asn", pph.PeerASN,
		"router_id", pph.PeerBGPID,
		"peer_distinguisher", types.FormatRD(key.Distinguisher),
		"table_name", tableName,
		"filtered", pph.IsLocRIBFiltered(),
	)
}

// setPeerState sets raven_bmp_peer_state for a peer of a router whose
// sysName label is sysName.
func setPeerState(sysName string, key PeerKey, state float64) {
	metrics.BMPPeerState.WithLabelValues(sysName, key.RouterAddr.String(), key.PeerAddr.String(),
		types.FormatRD(key.Distinguisher)).Set(state)
}

// peerKey is the peer a per-peer header describes on router.
func peerKey(router netip.Addr, pph BMPPerPeerHeader) PeerKey {
	return PeerKey{RouterAddr: router, Distinguisher: pph.Distinguisher(), PeerAddr: pph.PeerAddr}
}

// parseRoutes decodes a BMP Route Monitoring message's BGP UPDATE with
// RAVEN's own decoder (decodeRouteMonitoring).
func (l *Listener) parseRoutes(rm BMPRouteMonitoring, routerAddr netip.Addr) ([]types.Route, []types.Withdrawal, malformation) {
	// Look up, from the peer's Peer Up, the monitoring router's own AS on
	// this session (recorded on each route) and where ADD-PATH is in effect
	// (the decoder must know: path identifiers change the NLRI layout). A
	// peer with no Peer Up seen is taken as without ADD-PATH.
	key := peerKey(routerAddr, rm.PerPeer)
	l.peerMu.RLock()
	var localASN uint32
	var addPath AddPathState
	if p, ok := l.peers[key]; ok {
		localASN, addPath = p.LocalASN, p.addPath
	}
	l.peerMu.RUnlock()
	// A Loc-RIB header's Peer AS is the router's own AS (RFC 9069 §4.1),
	// with or without a Peer Up: its OPENs are fabricated, and some
	// routers send no Peer Up at all.
	if rm.PerPeer.IsLocRIB() {
		localASN = rm.PerPeer.PeerASN
	}

	routes, withdrawals, bad := decodeRouteMonitoring(rm, routerAddr, localASN, addPath.For(rm.PerPeer.IsAdjRIBOut()))
	// The routes of one UPDATE share its AS_PATH. The confederation
	// identifier is the origin of an empty one (a Loc-RIB path of only the
	// router's AS counts as empty) or one with confederation segments
	// (types.Route.OriginAS).
	if len(routes) == 0 {
		return routes, withdrawals, bad
	}
	confed := routes[0].HasConfedSegment()
	if !confed && !routes[0].EmptyPath() {
		return routes, withdrawals, bad
	}
	if id := l.confedID(key, localASN, confed); id != 0 {
		for i := range routes {
			routes[i].ConfedID = id
		}
	}
	return routes, withdrawals, bad
}

// instanceKey is one BGP instance (Peer Distinguisher) on a monitored router.
type instanceKey struct {
	router        netip.Addr
	distinguisher uint64
}

// confedIDEntry is a cached confedID result, for memberAS, as of generation
// gen of the peers map.
type confedIDEntry struct {
	gen      uint64
	memberAS uint32
	id       uint32
}

// confedID returns the confederation identifier of the router instance of
// peer key, whose session to that peer has memberAS as its local AS; 0 if
// it cannot be told (inferConfedID). confed says the session just carried
// confederation segments, which proves the instance is in a confederation
// as memberAS. Without that proof, now or from an earlier UPDATE, the
// result is 0: inferConfedID would take a local AS override on a router
// outside any confederation for an identifier. The result is cached until
// the instance's peers change.
func (l *Listener) confedID(key PeerKey, memberAS uint32, confed bool) uint32 {
	if memberAS == 0 {
		return 0
	}
	inst := instanceKey{router: key.RouterAddr, distinguisher: key.Distinguisher}
	if !confed {
		// Most empty AS_PATHs are on routers outside any confederation:
		// tell that under the read lock.
		l.peerMu.RLock()
		member := l.confedMembers[inst]
		l.peerMu.RUnlock()
		if member != memberAS {
			return 0
		}
	}
	l.peerMu.Lock()
	defer l.peerMu.Unlock()
	if confed {
		l.confedMembers[inst] = memberAS
	} else if l.confedMembers[inst] != memberAS {
		return 0
	}
	if e, ok := l.confedIDs[inst]; ok && e.gen == l.peersGen && e.memberAS == memberAS {
		return e.id
	}
	id := inferConfedID(l.peers, inst, memberAS)
	l.confedIDs[inst] = confedIDEntry{gen: l.peersGen, memberAS: memberAS, id: id}
	return id
}

// inferConfedID infers, from the OPENs a router instance sent its peers,
// the instance's AS confederation identifier, given that it is in a
// confederation as member AS memberAS. Inside the confederation a router's
// OPENs carry its member AS; to a peer outside it, the confederation
// identifier (RFC 5065). So if the local ASes of the instance's up eBGP
// sessions (peer AS other than local AS) take exactly one value other than
// memberAS, that is the identifier. None (a router with no session leaving
// the confederation) or more than one (local AS overrides on some sessions)
// gives 0: unknown.
func inferConfedID(peers map[PeerKey]*Peer, inst instanceKey, memberAS uint32) uint32 {
	var id uint32
	for key, p := range peers {
		if key.RouterAddr != inst.router || key.Distinguisher != inst.distinguisher || p.State != "up" ||
			p.LocalASN == 0 || p.LocalASN == memberAS || p.ASN == p.LocalASN {
			continue
		}
		if id != 0 && id != p.LocalASN {
			return 0
		}
		id = p.LocalASN
	}
	return id
}

// BGP message type UPDATE.
const bgpMsgTypeUpdate = 2

// decodeRouteMonitoring decodes the BGP message a Route Monitoring carries.
// Anything other than an UPDATE (a KEEPALIVE, NOTIFICATION, ...) yields
// nothing. A BGP Length below the header size or past the message is a
// session-reset error (RFC 7606 §3 (b)); the bytes present are decoded
// anyway, and everything that parses is withdrawn.
func decodeRouteMonitoring(rm BMPRouteMonitoring, router netip.Addr, localASN uint32, addPath AFIMask) ([]types.Route, []types.Withdrawal, malformation) {
	bgpData := rm.BGPUpdateData
	if len(bgpData) < bgpHeaderLen || bgpData[18] != bgpMsgTypeUpdate {
		return nil, nil, malformation{}
	}
	bgpLength := int(binary.BigEndian.Uint16(bgpData[16:18]))
	if bgpLength >= bgpHeaderLen && bgpLength <= len(bgpData) {
		return parseBGPUpdate(bgpData[bgpHeaderLen:bgpLength], rm.PerPeer, router, localASN, addPath)
	}
	// A Length below the header size used to be sliced as given, which
	// panicked the session's goroutine and with it the whole process.
	routes, withdrawals, _ := parseBGPUpdate(bgpData[bgpHeaderLen:], rm.PerPeer, router, localASN, addPath)
	return nil, append(withdrawals, asWithdrawals(routes)...), malformation{
		action: actSessionReset,
		reason: metrics.MalformedReasonUpdateLength,
		detail: fmt.Sprintf("BGP message length %d with %d bytes present", bgpLength, len(bgpData)),
	}
}

// reachable is an announced NLRI entry and its next hop.
type reachable struct {
	n       nlri
	nextHop netip.Addr
}

// parseBGPUpdate decodes a BGP UPDATE message body: IPv4 withdrawals and
// NLRI, and IPv4 and IPv6 unicast NLRI in MP_REACH_NLRI / MP_UNREACH_NLRI
// (RFC 4760). addPath lists the address families whose NLRI carry ADD-PATH
// path identifiers (RFC 7911 §3).
//
// A malformed UPDATE is handled as RFC 7606 tells the monitored router to
// handle it, so that RAVEN's table holds what the router's does:
//
//   - attribute discard: the attribute is dropped and the UPDATE processed
//     without it;
//   - treat-as-withdraw: every prefix the UPDATE announces is returned as a
//     withdrawal instead of a route;
//   - session reset: the router resets the peer's session. RAVEN cannot do
//     that, and closing the BMP session would drop every peer on the
//     router, so every prefix that can still be parsed is withdrawn; the
//     caller marks the peer, and the router's Peer Down clears the rest.
//
// The malformation returned says which applied and why. Withdrawals that
// parse are returned however malformed the rest of the UPDATE is.
func parseBGPUpdate(data []byte, pph BMPPerPeerHeader, router netip.Addr, localASN uint32, addPath AFIMask) ([]types.Route, []types.Withdrawal, malformation) {
	var m malformation
	if len(data) < 4 {
		m.add(actSessionReset, metrics.MalformedReasonUpdateLength,
			fmt.Sprintf("%d-byte UPDATE, too short for its length fields", len(data)))
		return nil, nil, m
	}
	ribType := ribTypeOf(pph)

	// Withdrawn Routes Length, then the IPv4 withdrawn prefixes. A length
	// running past the message used to be sliced as given, which panicked
	// the session's goroutine and with it the whole process. Past the
	// message, the field cannot be delimited and nothing can be withdrawn.
	withdrawnLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+withdrawnLen+2 > len(data) {
		m.add(actSessionReset, metrics.MalformedReasonUpdateLength,
			fmt.Sprintf("withdrawn routes length %d overflows a %d-byte UPDATE", withdrawnLen, len(data)))
		return nil, nil, m
	}
	var withdrawals []types.Withdrawal
	v4Withdrawn, ok := parseNLRI(data[2:2+withdrawnLen], 4, addPath&AFIIPv4Unicast != 0)
	if !ok {
		m.add(actSessionReset, metrics.MalformedReasonNLRI, "withdrawn routes field syntactically incorrect")
	}
	for _, n := range v4Withdrawn {
		withdrawals = append(withdrawals, makeWithdrawal(n, pph, router, ribType))
	}

	offset := 2 + withdrawnLen
	pathAttrLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	pathAttrEnd := offset + pathAttrLen
	if pathAttrEnd > len(data) {
		// Neither the attributes nor the NLRI can be delimited; the
		// withdrawals parsed above still apply. Dropping the whole UPDATE,
		// as RAVEN used to, left the withdrawn routes in the table.
		m.add(actSessionReset, metrics.MalformedReasonUpdateLength,
			fmt.Sprintf("path attributes length %d overflows a %d-byte UPDATE", pathAttrLen, len(data)))
		return nil, withdrawals, m
	}

	// iBGP: LOCAL_PREF, ORIGINATOR_ID and CLUSTER_LIST errors are
	// treat-as-withdraw only from an internal peer (RFC 7606 §7.5, §7.9,
	// §7.10). Unknown local AS counts as external.
	internal := localASN != 0 && localASN == pph.PeerASN
	attrs := parsePathAttributes(data[offset:pathAttrEnd], pph.IsAS2(), internal, &m)

	// The NLRI field is located by the Total Path Attribute Length even when
	// an attribute inside overran (RFC 7606 §4).
	nlriField := data[pathAttrEnd:]
	var reach []reachable
	v4, ok := parseNLRI(nlriField, 4, addPath&AFIIPv4Unicast != 0)
	if !ok {
		m.add(actSessionReset, metrics.MalformedReasonNLRI, "NLRI field syntactically incorrect")
	}
	for _, n := range v4 {
		reach = append(reach, reachable{n: n, nextHop: attrs.nextHop})
	}

	// NLRI carried in MP_REACH_NLRI / MP_UNREACH_NLRI (RFC 4760): IPv4 and
	// IPv6 unicast. Any other address family is counted, not decoded. More
	// than one of either is a session reset; each is parsed so that all
	// their prefixes are withdrawn.
	for _, a := range attrs.mpReach {
		mp := parseMPReachNLRI(a, addPath, &m)
		if !mp.supported {
			countUnsupportedNLRI(mp.afi, mp.safi)
		}
		for _, n := range mp.nlri {
			reach = append(reach, reachable{n: n, nextHop: mp.nextHop})
		}
	}
	for _, a := range attrs.mpUnreach {
		mp := parseMPUnreachNLRI(a, addPath, &m)
		if !mp.supported {
			countUnsupportedNLRI(mp.afi, mp.safi)
		}
		for _, n := range mp.nlri {
			withdrawals = append(withdrawals, makeWithdrawal(n, pph, router, ribType))
		}
	}

	announces := len(nlriField) > 0 || len(attrs.mpReach) > 0
	if announces {
		// RFC 7606 §3 (d): well-known mandatory attributes. NEXT_HOP is
		// required only for NLRI in the NLRI field (RFC 4760 §3); an
		// UPDATE carrying only withdrawals needs none of them.
		var missing []string
		if !attrs.seen[attrOrigin] {
			missing = append(missing, "ORIGIN")
		}
		if !attrs.seen[attrASPath] {
			missing = append(missing, "AS_PATH")
		}
		if len(nlriField) > 0 && !attrs.seen[attrNextHop] {
			missing = append(missing, "NEXT_HOP")
		}
		if len(missing) > 0 {
			m.add(actTreatAsWithdraw, metrics.MalformedReasonMissingMandatory,
				fmt.Sprintf("missing %s", strings.Join(missing, ", ")))
		}
	} else if m.action == actTreatAsWithdraw {
		// RFC 7606 §5.2: an attribute error in an UPDATE that announces
		// nothing leaves no confidence that its NLRI were all found, so it
		// is a session reset.
		m.action = actSessionReset
		m.detail += "; the UPDATE announces no NLRI (RFC 7606 §5.2)"
	}

	if m.action >= actTreatAsWithdraw {
		for _, r := range reach {
			withdrawals = append(withdrawals, makeWithdrawal(r.n, pph, router, ribType))
		}
		return nil, withdrawals, m
	}
	var routes []types.Route
	for _, r := range reach {
		routes = append(routes, makeRoute(r.n, r.nextHop, pph, router, attrs, ribType, localASN))
	}
	return routes, withdrawals, m
}

// ribTypeOf is the RIB a Route Monitoring message reports: the Loc-RIB for
// a Loc-RIB instance (RFC 9069), otherwise by the L flag (RFC 7854) and the
// O flag (RFC 8671) Adj-RIB-In or Adj-RIB-Out, pre- or post-policy.
func ribTypeOf(pph BMPPerPeerHeader) types.RIBType {
	switch {
	case pph.IsLocRIB():
		return types.LocRIB
	case pph.IsAdjRIBOut() && pph.IsPostPolicy():
		return types.AdjRIBOutPost
	case pph.IsAdjRIBOut():
		return types.AdjRIBOutPre
	case pph.IsPostPolicy():
		return types.AdjRIBInPost
	}
	return types.AdjRIBInPre
}

func countUnsupportedNLRI(afi uint16, safi uint8) {
	metrics.BMPUnsupportedNLRITotal.WithLabelValues(strconv.Itoa(int(afi)), strconv.Itoa(int(safi))).Inc()
}

// makeRoute constructs a types.Route from an NLRI entry, next hop, and
// extracted path attributes.
func makeRoute(n nlri, nextHop netip.Addr, pph BMPPerPeerHeader, router netip.Addr, attrs pathAttrs, ribType types.RIBType, localASN uint32) types.Route {
	return types.Route{
		Timestamp:         pph.Timestamp,
		Router:            router,
		PeerDistinguisher: pph.Distinguisher(),
		PeerType:          pph.PeerType,
		PeerAddr:          pph.PeerAddr,
		PeerASN:           pph.PeerASN,
		PathID:            n.pathID,
		LocalASN:          localASN,
		RouterID:          pph.PeerBGPID,
		Prefix:            n.prefix,
		ASPath:            attrs.asPath,
		ASPathRaw:         attrs.asPathRaw,
		Origin:            types.OriginType(attrs.origin),
		NextHop:           nextHop,
		Communities:       attrs.communities,
		LargeCommunities:  attrs.largeCommunities,
		RIBType:           ribType,
	}
}

// makeWithdrawal constructs a types.Withdrawal for an NLRI entry.
func makeWithdrawal(n nlri, pph BMPPerPeerHeader, router netip.Addr, ribType types.RIBType) types.Withdrawal {
	return types.Withdrawal{
		Router:            router,
		PeerDistinguisher: pph.Distinguisher(),
		PeerAddr:          pph.PeerAddr,
		Prefix:            n.prefix,
		PathID:            n.pathID,
		RIBType:           ribType,
	}
}

// nlri is one NLRI entry: a prefix and, with ADD-PATH, its path identifier.
type nlri struct {
	prefix netip.Prefix
	pathID uint32
}

// parseNLRI iterates length-prefixed NLRI entries. addrLen is 4 for IPv4 NLRI
// or 16 for IPv6 NLRI; it bounds how many bytes are read into the address slot.
// With addPath each entry starts with a 4-byte path identifier (RFC 7911 §3).
//
// ok is false if the field is syntactically incorrect (RFC 7606 §5.3): a
// prefix length beyond the address family's, or an entry running past the
// field. The entries before the error are returned.
func parseNLRI(data []byte, addrLen int, addPath bool) ([]nlri, bool) {
	var out []nlri
	off := 0
	maxBits := addrLen * 8
	for off < len(data) {
		var pathID uint32
		if addPath {
			if off+4 >= len(data) { // the path identifier and a length octet
				return out, false
			}
			pathID = binary.BigEndian.Uint32(data[off : off+4])
			off += 4
		}
		pLen := int(data[off])
		off++
		if pLen > maxBits {
			return out, false
		}
		pBytes := (pLen + 7) / 8
		if off+pBytes > len(data) {
			return out, false
		}
		buf := make([]byte, addrLen)
		copy(buf, data[off:off+pBytes])
		off += pBytes
		addr, _ := netip.AddrFromSlice(buf)
		out = append(out, nlri{prefix: netip.PrefixFrom(addr.Unmap(), pLen), pathID: pathID})
	}
	return out, true
}

// mpNLRI is a decoded MP_REACH_NLRI or MP_UNREACH_NLRI attribute.
type mpNLRI struct {
	afi       uint16
	safi      uint8
	supported bool       // an address family RAVEN decodes (IPv4 or IPv6 unicast)
	nextHop   netip.Addr // MP_REACH only
	nlri      []nlri
}

// mpFamily returns the NLRI address length and ADD-PATH bit for a supported
// (afi, safi): IPv4 or IPv6 unicast.
func mpFamily(afi uint16, safi uint8) (addrLen int, bit AFIMask, ok bool) {
	switch {
	case afi == 1 && safi == 1:
		return 4, AFIIPv4Unicast, true
	case afi == 2 && safi == 1:
		return 16, AFIIPv6Unicast, true
	}
	return 0, 0, false
}

// parseMPReachNLRI parses an MP_REACH_NLRI attribute payload (RFC 4760 §3).
// Layout:
//
//	AFI(2) | SAFI(1) | NH Len(1) | NH(variable) | Reserved(1) | NLRI(variable)
//
// IPv4 and IPv6 unicast are decoded, each with its own ADD-PATH setting. The
// next hop is IPv4 (4 bytes, IPv4 NLRI only) or IPv6 (16 bytes global, or 32
// with a link-local RAVEN drops); an IPv6 next hop for IPv4 NLRI is RFC 8950.
// Other address families come back unsupported.
//
// Malformations are session resets (RFC 7606 §5.3, §7.11), recorded in m:
// an attribute under 5 bytes, a next hop of another length or running past
// the attribute, or incorrect NLRI. The NLRI that parse are still returned,
// to be withdrawn.
func parseMPReachNLRI(data []byte, addPath AFIMask, m *malformation) mpNLRI {
	if len(data) < 5 {
		m.add(actSessionReset, metrics.MalformedReasonMPReach, fmt.Sprintf("MP_REACH_NLRI length %d, under 5", len(data)))
		return mpNLRI{supported: true}
	}
	mp := mpNLRI{afi: binary.BigEndian.Uint16(data[0:2]), safi: data[2]}
	addrLen, bit, ok := mpFamily(mp.afi, mp.safi)
	if !ok {
		return mp
	}
	mp.supported = true
	nhLen := int(data[3])
	if 4+nhLen+1 > len(data) {
		m.add(actSessionReset, metrics.MalformedReasonMPReachNextHop,
			fmt.Sprintf("MP_REACH_NLRI next hop length %d runs past the %d-byte attribute", nhLen, len(data)))
		return mp
	}
	switch {
	case nhLen == 4 && mp.afi == 1:
		mp.nextHop = netip.AddrFrom4([4]byte(data[4:8]))
	case nhLen == 16 || nhLen == 32:
		mp.nextHop = netip.AddrFrom16([16]byte(data[4:20]))
	default:
		m.add(actSessionReset, metrics.MalformedReasonMPReachNextHop,
			fmt.Sprintf("MP_REACH_NLRI next hop length %d for AFI %d SAFI %d", nhLen, mp.afi, mp.safi))
	}
	mp.nlri, ok = parseNLRI(data[4+nhLen+1:], addrLen, addPath&bit != 0) // skip the reserved byte
	if !ok {
		m.add(actSessionReset, metrics.MalformedReasonNLRI, "MP_REACH_NLRI NLRI syntactically incorrect")
	}
	return mp
}

// parseMPUnreachNLRI parses an MP_UNREACH_NLRI attribute payload (RFC 4760 §4).
// Layout:
//
//	AFI(2) | SAFI(1) | Withdrawn NLRI(variable)
//
// IPv4 and IPv6 unicast are decoded; other address families come back
// unsupported. An attribute under 3 bytes or incorrect NLRI is a session
// reset (RFC 7606 §5.3), recorded in m; the NLRI that parse are returned.
func parseMPUnreachNLRI(data []byte, addPath AFIMask, m *malformation) mpNLRI {
	if len(data) < 3 {
		m.add(actSessionReset, metrics.MalformedReasonMPUnreach, fmt.Sprintf("MP_UNREACH_NLRI length %d, under 3", len(data)))
		return mpNLRI{supported: true}
	}
	mp := mpNLRI{afi: binary.BigEndian.Uint16(data[0:2]), safi: data[2]}
	addrLen, bit, ok := mpFamily(mp.afi, mp.safi)
	if !ok {
		return mp
	}
	mp.supported = true
	mp.nlri, ok = parseNLRI(data[3:], addrLen, addPath&bit != 0)
	if !ok {
		m.add(actSessionReset, metrics.MalformedReasonNLRI, "MP_UNREACH_NLRI NLRI syntactically incorrect")
	}
	return mp
}

// pathAttrs collects the path-attribute fields RAVEN cares about, plus the raw
// MP_REACH/MP_UNREACH bodies for downstream multiprotocol NLRI parsing.
type pathAttrs struct {
	asPath           []uint32
	asPathRaw        []types.ASSegment
	origin           uint8
	nextHop          netip.Addr // IPv4 NEXT_HOP only; MP next hops live in MP_REACH
	communities      []types.Community
	largeCommunities []types.LargeCommunity
	// MP_REACH_NLRI (attr type 14) and MP_UNREACH_NLRI (15) bodies: one
	// each in a well-formed UPDATE, every instance in a malformed one.
	mpReach   [][]byte
	mpUnreach [][]byte
	seen      [256]bool // attribute types present
}

// BGP path attribute type codes RAVEN reads.
const (
	attrOrigin           = 1
	attrASPath           = 2
	attrNextHop          = 3
	attrMED              = 4
	attrLocalPref        = 5
	attrCommunities      = 8
	attrOriginatorID     = 9
	attrClusterList      = 10
	attrMPReach          = 14
	attrMPUnreach        = 15
	attrAS4Path          = 17 // RFC 6793
	attrAS4Aggregator    = 18 // RFC 6793
	attrLargeCommunities = 32
)

// asTrans is AS_TRANS (RFC 6793): the 2-octet stand-in for a 4-octet AS.
const asTrans = 23456

// parsePathAttributes walks the path attributes and extracts the fields
// RAVEN cares about: AS_PATH, ORIGIN, NEXT_HOP, COMMUNITIES, MP_REACH_NLRI,
// MP_UNREACH_NLRI, LARGE_COMMUNITIES and AS4_PATH.
//
// as2 is the per-peer header's A flag (RFC 7854 §4.2): the peer session uses
// 2-octet AS numbers, so AS_PATH holds 2-octet ASNs (4-octet ones as
// AS_TRANS) and AS4_PATH, if present, carries the 4-octet path to merge
// (RFC 6793 §4.2.3). Without it AS_PATH holds 4-octet ASNs and AS4_PATH is
// ignored, as a 4-octet speaker must. internal is an iBGP peer.
//
// Errors are recorded in m with the approach RFC 7606 gives them: a
// malformed or wrongly flagged ORIGIN, AS_PATH, NEXT_HOP, MULTI_EXIT_DISC,
// COMMUNITIES or LARGE_COMMUNITIES (and from an internal peer LOCAL_PREF,
// ORIGINATOR_ID or CLUSTER_LIST), or an attribute running past the others,
// is treat-as-withdraw; a malformed AS4_PATH or AS4_AGGREGATOR is
// discarded, leaving AS_PATH alone (RFC 6793 §6); of a repeated attribute
// the first is kept, except that a repeated MP_REACH_NLRI or
// MP_UNREACH_NLRI is a session reset (§3 (g)).
func parsePathAttributes(data []byte, as2, internal bool, m *malformation) pathAttrs {
	var out pathAttrs
	var as4Path []types.ASSegment
	withdraw := func(reason, detail string) { m.add(actTreatAsWithdraw, reason, detail) }
	badFlags := func(name string, flags byte) {
		withdraw(metrics.MalformedReasonAttrFlags, fmt.Sprintf("%s flags 0x%02x", name, flags))
	}
	offset := 0
	for offset < len(data) {
		// Flags, type and a 1-byte length, or 2 bytes with Extended Length.
		hdrLen := 3
		if data[offset]&attrFlagExtLen != 0 {
			hdrLen = 4
		}
		if offset+hdrLen > len(data) {
			withdraw(metrics.MalformedReasonAttrLength,
				fmt.Sprintf("%d bytes left after the last attribute, too few for another", len(data)-offset))
			break
		}
		flags := data[offset]
		attrType := data[offset+1]
		attrLen := int(data[offset+2])
		if hdrLen == 4 {
			attrLen = int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		}
		offset += hdrLen
		if offset+attrLen > len(data) {
			withdraw(metrics.MalformedReasonAttrLength,
				fmt.Sprintf("attribute type %d length %d runs past the path attributes", attrType, attrLen))
			break
		}
		attrData := data[offset : offset+attrLen]
		offset += attrLen

		if out.seen[attrType] {
			switch attrType {
			case attrMPReach:
				m.add(actSessionReset, metrics.MalformedReasonDuplicateMP, "MP_REACH_NLRI more than once")
				out.mpReach = append(out.mpReach, attrData)
			case attrMPUnreach:
				m.add(actSessionReset, metrics.MalformedReasonDuplicateMP, "MP_UNREACH_NLRI more than once")
				out.mpUnreach = append(out.mpUnreach, attrData)
			default:
				m.add(actAttributeDiscard, metrics.MalformedReasonDuplicateAttr,
					fmt.Sprintf("attribute type %d more than once; the first kept", attrType))
			}
			continue
		}
		out.seen[attrType] = true

		switch attrType {
		case attrOrigin:
			switch {
			case !flagsAre(flags, false, true):
				badFlags("ORIGIN", flags)
			case len(attrData) != 1 || attrData[0] > uint8(types.OriginIncomplete):
				withdraw(metrics.MalformedReasonOrigin, fmt.Sprintf("ORIGIN % x", attrData))
			default:
				out.origin = attrData[0]
			}

		case attrASPath:
			asnLen := 4
			if as2 {
				asnLen = 2
			}
			segs, ok := parseASPath(attrData, asnLen)
			switch {
			case !flagsAre(flags, false, true):
				badFlags("AS_PATH", flags)
			case !ok:
				withdraw(metrics.MalformedReasonASPath,
					fmt.Sprintf("AS_PATH malformed after %d good segments", len(segs)))
			}
			out.asPathRaw = segs

		case attrAS4Path:
			if !as2 {
				continue
			}
			segs, ok := parseASPath(attrData, 4)
			switch {
			case !flagsAre(flags, true, true):
				m.add(actAttributeDiscard, metrics.MalformedReasonAS4Path, fmt.Sprintf("AS4_PATH flags 0x%02x", flags))
			case !ok:
				m.add(actAttributeDiscard, metrics.MalformedReasonAS4Path,
					fmt.Sprintf("AS4_PATH malformed after %d good segments", len(segs)))
			default:
				as4Path = segs
			}

		case attrAS4Aggregator:
			// Not used by RAVEN; checked only to count its discard.
			if as2 && (!flagsAre(flags, true, true) || len(attrData) != 8) {
				m.add(actAttributeDiscard, metrics.MalformedReasonAS4Aggregator,
					fmt.Sprintf("AS4_AGGREGATOR flags 0x%02x length %d", flags, len(attrData)))
			}

		case attrNextHop:
			switch {
			case !flagsAre(flags, false, true):
				badFlags("NEXT_HOP", flags)
			case len(attrData) != 4:
				withdraw(metrics.MalformedReasonNextHop, fmt.Sprintf("NEXT_HOP length %d", len(attrData)))
			default:
				out.nextHop = netip.AddrFrom4([4]byte(attrData))
			}

		case attrMED:
			switch {
			case !flagsAre(flags, true, false):
				badFlags("MULTI_EXIT_DISC", flags)
			case len(attrData) != 4:
				withdraw(metrics.MalformedReasonMED, fmt.Sprintf("MULTI_EXIT_DISC length %d", len(attrData)))
			}

		case attrLocalPref:
			// From an external peer it is discarded whatever it holds.
			switch {
			case !internal:
			case !flagsAre(flags, false, true):
				badFlags("LOCAL_PREF", flags)
			case len(attrData) != 4:
				withdraw(metrics.MalformedReasonLocalPref, fmt.Sprintf("LOCAL_PREF length %d", len(attrData)))
			}

		case attrOriginatorID:
			switch {
			case !internal:
			case !flagsAre(flags, true, false):
				badFlags("ORIGINATOR_ID", flags)
			case len(attrData) != 4:
				withdraw(metrics.MalformedReasonOriginatorID, fmt.Sprintf("ORIGINATOR_ID length %d", len(attrData)))
			}

		case attrClusterList:
			switch {
			case !internal:
			case !flagsAre(flags, true, false):
				badFlags("CLUSTER_LIST", flags)
			case len(attrData) == 0 || len(attrData)%4 != 0:
				withdraw(metrics.MalformedReasonClusterList, fmt.Sprintf("CLUSTER_LIST length %d", len(attrData)))
			}

		case attrCommunities:
			switch {
			case !flagsAre(flags, true, true):
				badFlags("COMMUNITIES", flags)
			case len(attrData) == 0 || len(attrData)%4 != 0:
				withdraw(metrics.MalformedReasonCommunities, fmt.Sprintf("COMMUNITIES length %d", len(attrData)))
			default:
				for i := 0; i+4 <= len(attrData); i += 4 {
					out.communities = append(out.communities, types.Community{
						High: binary.BigEndian.Uint16(attrData[i : i+2]),
						Low:  binary.BigEndian.Uint16(attrData[i+2 : i+4]),
					})
				}
			}

		case attrLargeCommunities:
			switch {
			case !flagsAre(flags, true, true):
				badFlags("LARGE_COMMUNITY", flags)
			case len(attrData) == 0 || len(attrData)%12 != 0:
				withdraw(metrics.MalformedReasonLargeCommunities,
					fmt.Sprintf("LARGE_COMMUNITY length %d", len(attrData)))
			default:
				for i := 0; i+12 <= len(attrData); i += 12 {
					out.largeCommunities = append(out.largeCommunities, types.LargeCommunity{
						GlobalAdmin: binary.BigEndian.Uint32(attrData[i : i+4]),
						LocalData1:  binary.BigEndian.Uint32(attrData[i+4 : i+8]),
						LocalData2:  binary.BigEndian.Uint32(attrData[i+8 : i+12]),
					})
				}
			}

		case attrMPReach:
			if !flagsAre(flags, true, false) {
				m.add(actSessionReset, metrics.MalformedReasonMPReach, fmt.Sprintf("MP_REACH_NLRI flags 0x%02x", flags))
			}
			out.mpReach = append(out.mpReach, attrData)

		case attrMPUnreach:
			if !flagsAre(flags, true, false) {
				m.add(actSessionReset, metrics.MalformedReasonMPUnreach, fmt.Sprintf("MP_UNREACH_NLRI flags 0x%02x", flags))
			}
			out.mpUnreach = append(out.mpUnreach, attrData)
		}
	}

	if as4Path != nil {
		out.asPathRaw = mergeAS4Path(out.asPathRaw, as4Path)
	}
	out.asPath = flattenASPath(out.asPathRaw)
	return out
}

// parseASPath parses AS_PATH (or AS4_PATH) attribute data with asnLen-byte
// AS numbers (2 or 4) into its segments. ok is false if the path is
// malformed (RFC 7606 §7.2): an unknown segment type, a segment of length
// zero or running past the attribute, or a single byte left over. The
// segments before the error are returned.
func parseASPath(data []byte, asnLen int) (raw []types.ASSegment, ok bool) {
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			return raw, false
		}
		segType := types.ASSegmentType(data[offset])
		segLen := int(data[offset+1])
		offset += 2
		if segType < types.ASSegmentSet || segType > types.ASSegmentConfedSet ||
			segLen == 0 || offset+segLen*asnLen > len(data) {
			return raw, false
		}
		seg := types.ASSegment{Type: segType, ASNs: make([]uint32, segLen)}
		for i := 0; i < segLen; i++ {
			if asnLen == 2 {
				seg.ASNs[i] = uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
			} else {
				seg.ASNs[i] = binary.BigEndian.Uint32(data[offset : offset+4])
			}
			offset += asnLen
		}
		raw = append(raw, seg)
	}
	return raw, true
}

// flattenASPath lists the path's AS numbers in order. AS_SET members are
// included (expanded); so are confederation segments.
func flattenASPath(segs []types.ASSegment) []uint32 {
	var flat []uint32
	for _, s := range segs {
		flat = append(flat, s.ASNs...)
	}
	return flat
}

// asPathCount is the number of AS numbers in a path as RFC 6793 §4.2.3
// counts them (RFC 4271 §9.1.2.2): each AS_SEQUENCE member counts one, an
// AS_SET counts one, confederation segments count none.
func asPathCount(segs []types.ASSegment) int {
	n := 0
	for _, s := range segs {
		switch s.Type {
		case types.ASSegmentSequence:
			n += len(s.ASNs)
		case types.ASSegmentSet:
			n++
		}
	}
	return n
}

// mergeAS4Path reconstructs the AS path from AS_PATH and AS4_PATH received
// over a 2-octet session (RFC 6793 §4.2.3). If AS_PATH has fewer AS numbers
// than AS4_PATH, AS4_PATH is ignored. Otherwise the result is the leading
// part of AS_PATH, as many AS numbers and segments as make up the
// difference, followed by AS4_PATH, so it has as many AS numbers as AS_PATH:
// the AS_TRANS stand-ins in AS_PATH's tail are replaced by the real 4-octet
// ASNs. Confederation segments in AS4_PATH, which a speaker must not send
// there, are dropped.
func mergeAS4Path(asPath, as4Path []types.ASSegment) []types.ASSegment {
	var as4 []types.ASSegment
	for _, s := range as4Path {
		if s.Type == types.ASSegmentSequence || s.Type == types.ASSegmentSet {
			as4 = append(as4, s)
		}
	}
	need := asPathCount(asPath) - asPathCount(as4)
	if need < 0 {
		return asPath
	}
	var out []types.ASSegment
	for _, s := range asPath {
		if need == 0 {
			break
		}
		switch s.Type {
		case types.ASSegmentSequence:
			k := min(need, len(s.ASNs))
			out = append(out, types.ASSegment{Type: s.Type, ASNs: s.ASNs[:k:k]})
			need -= k
		case types.ASSegmentSet:
			out = append(out, s)
			need--
		default: // confederation segments count none; keep them in place
			out = append(out, s)
		}
	}
	return append(out, as4...)
}
