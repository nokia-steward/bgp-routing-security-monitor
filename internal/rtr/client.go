package rtr

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// RTR PDU types (RFC 8210)
const (
	PDUSerialNotify  uint8 = 0
	PDUSerialQuery   uint8 = 1
	PDUResetQuery    uint8 = 2
	PDUCacheResponse uint8 = 3
	PDUIPv4Prefix    uint8 = 4
	PDUIPv6Prefix    uint8 = 6
	PDUEndOfData     uint8 = 7
	PDUCacheReset    uint8 = 8
	PDUErrorReport   uint8 = 10
	PDUASPA          uint8 = 11 // RTR v2 (draft-ietf-sidrops-8210bis)
)

// RTR header is 8 bytes: version(1) + type(1) + sessionID(2) + length(4)
const rtrHeaderLen = 8

// Error Report codes (RFC 8210 §12). In an Error Report the header's
// session ID field carries the code.
const (
	errCodeNoDataAvailable     uint16 = 2
	errCodeUnsupportedProtoVer uint16 = 4
)

// End of Data timing (RFC 8210 §6): defaults when the cache sends none
// (version 0) and the allowed ranges, in seconds.
const (
	defaultRefresh = 3600
	defaultRetry   = 600
	defaultExpire  = 7200
)

var (
	refreshRange = [2]uint32{1, 86400}
	retryRange   = [2]uint32{1, 7200}
	expireRange  = [2]uint32{600, 172800}
)

// errCacheNotReady marks a session the cache ended with Error Report code 2
// (No Data Available): it is still building its data set, typically just
// after it started. Retry later at the same protocol version.
var errCacheNotReady = errors.New("cache has no data available yet")

// errVersionUpgrade ends a downgraded session after a re-probe found that the
// cache now supports the configured version.
var errVersionUpgrade = errors.New("cache now supports a higher RTR protocol version")

// errVersionDowngrade ends a session the cache turned down during version
// negotiation (Error Report code 4 before any Cache Response). The client
// reconnects at once, at the lower version negotiatedVersion now holds.
var errVersionDowngrade = errors.New("cache does not support this RTR protocol version")

// errNoResponse ends a session whose query went unanswered for the Retry
// Interval.
var errNoResponse = errors.New("no response from cache within the retry interval")

// errorReportError ends a session the cache ended with an Error Report. It
// wraps errCacheNotReady (code 2) or errVersionDowngrade where those apply.
type errorReportError struct {
	code uint16
	err  error
}

func (e *errorReportError) Error() string { return e.err.Error() }
func (e *errorReportError) Unwrap() error { return e.err }

// defaultVersionReprobe is how often a downgraded client re-probes the cache
// at the configured version unless SetVersionReprobeInterval says otherwise.
const defaultVersionReprobe = time.Hour

// probeTimeout bounds a version re-probe's connection and first reply.
const probeTimeout = 30 * time.Second

// rtrKeepAlive detects a dead cache or path within about two minutes (60s
// idle, then 4 probes 15s apart) whether or not a query is outstanding.
// Without it a session idle between polls could sit on a dead connection
// until the next poll's Retry Interval ran out.
var rtrKeepAlive = net.KeepAliveConfig{
	Enable:   true,
	Idle:     60 * time.Second,
	Interval: 15 * time.Second,
	Count:    4,
}

// Client maintains an RTR session with a single RPKI validator cache.
type Client struct {
	address         string
	transport       string // "tcp" (default) or "tls"
	tlsCfg          *tls.Config
	vrpStore        *store.VRPStore
	aspaStore       *store.ASPAStore
	log             *slog.Logger
	retryMin        time.Duration
	retryMax        time.Duration
	hasReset        bool
	fullSyncPending bool  // true between Reset Query send and EndOfData receive
	configVersion   uint8 // configured starting version; reset to this on each session
	protoVersion    uint8 // RTR protocol version (0, 1, or 2)
	// sessionVersion is protoVersion as of the last session established,
	// for ProtocolVersion; 0 before the first.
	sessionVersion atomic.Uint32
	onUpdate       func(*store.Delta)
	onSync         func()
	readyOnce      sync.Once
	ready          chan struct{}

	// negotiatedVersion is the version the next session opens at. It
	// starts at configVersion and is lowered only when the cache rejects a
	// version with Error Report code 4 (Unsupported Protocol Version),
	// answers at a lower one, or drops the connection before answering the
	// first query (see dropTrial). Never when pinned.
	negotiatedVersion uint8

	// pinned holds every session at configVersion: no fallback of any kind
	// and no re-probe (SetVersionPinned).
	pinned bool

	// A cache that does not speak a version may close or reset the
	// connection instead of sending Error Report code 4. The first session
	// that ends that way, before any response to its first query, lowers the
	// version by one for a single trial session (dropTrial, from
	// dropTrialFrom). If the trial also gets no response, the client goes
	// back to dropTrialFrom with its normal backoff, and does not lower the
	// version on a drop again (dropRetryUsed) until some session gets a
	// response. Owned by the goroutine running Start.
	dropTrial     bool
	dropTrialFrom uint8
	dropRetryUsed bool
	// sessionResponded is whether the current session received any PDU;
	// sessionDialed whether it connected at all.
	sessionResponded bool
	sessionDialed    bool

	// State of the cache's data as of the last End of Data. Owned by the
	// goroutine running Start.
	sessionID   uint16
	serial      uint32
	haveSerial  bool
	refresh     uint32 // seconds (see unit)
	retry       uint32
	expire      uint32
	expireTimer *time.Timer // fires Expire after the last End of Data
	// expireOverride, if not 0, replaces the cache's Expire Interval
	// (rtr.expire-interval, clamped by ExpireOverride).
	expireOverride uint32
	expired        bool
	sessionSynced  bool // the current session has completed a sync

	// unit is what one second of an End of Data interval lasts. Only tests
	// shorten it.
	unit time.Duration

	// Version re-probing after a downgrade: how often, and when the cache
	// last turned the configured version down.
	reprobeInterval time.Duration
	downgradedAt    time.Time

	// connHook, if set, sees each session's connection. Tests only.
	connHook func(net.Conn)

	// Telemetry (optional). A nil recorder is a safe no-op.
	tel           *telemetry.Recorder
	syncStart     time.Time // when the current sync's query was sent
	lastSyncTime  time.Time // EndOfData time of the previous completed sync
	vrpAnnounced  int       // per-sync counters, reset on each Cache Response
	vrpWithdrawn  int
	aspaAnnounced int
	aspaWithdrawn int

	// delta records how the current sync changes the stores; reset on
	// each Cache Response and handed to onUpdate at End of Data.
	delta *store.DeltaRecorder
}

// NewClient creates an RTR client that syncs VRPs into the given store.
// transport selects the wire encoding: "tcp" (default, plaintext) or "tls".
// tlsCfg is consulted only when transport == "tls"; it may be nil, in which
// case the system root CA pool is used and no client certificate is presented.
func NewClient(address string, transport string, tlsCfg *config.TLSConfig, vrpStore *store.VRPStore, aspaStore *store.ASPAStore, configVersion uint8, log *slog.Logger) (*Client, error) {
	if transport == "" {
		transport = "tcp"
	}
	logger := log.With("subsystem", "rtr", "cache", address)

	c := &Client{
		address:       address,
		transport:     transport,
		vrpStore:      vrpStore,
		aspaStore:     aspaStore,
		log:           logger,
		retryMin:      5 * time.Second,
		retryMax:      60 * time.Second,
		configVersion: configVersion,
		protoVersion:  configVersion,
		ready:         make(chan struct{}),

		negotiatedVersion: configVersion,
		refresh:           defaultRefresh,
		retry:             defaultRetry,
		expire:            defaultExpire,
		unit:              time.Second,
		reprobeInterval:   defaultVersionReprobe,
	}

	if transport == "tls" {
		built, err := buildTLSConfig(tlsCfg, logger)
		if err != nil {
			return nil, err
		}
		c.tlsCfg = built
	}

	return c, nil
}

// buildTLSConfig assembles a *tls.Config from the user-supplied paths.
// A nil cfg or empty CA falls back to the system root pool.
func buildTLSConfig(cfg *config.TLSConfig, log *slog.Logger) (*tls.Config, error) {
	out := &tls.Config{MinVersion: cfg.TLSMinVersion()}

	if cfg == nil || cfg.CA == "" {
		log.Warn("RTR TLS configured without a custom CA; using system root pool")
	} else {
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("read RTR TLS CA %q: %w", cfg.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse RTR TLS CA %q: no PEM certificates found", cfg.CA)
		}
		out.RootCAs = pool
	}

	if cfg != nil && cfg.Cert != "" && cfg.Key != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("load RTR TLS client cert: %w", err)
		}
		out.Certificates = []tls.Certificate{cert}
	}

	return out, nil
}

// Ready returns a channel that is closed after the first successful RTR sync.
func (c *Client) Ready() <-chan struct{} {
	return c.ready
}

// recorder returns the current sync's delta recorder. Data arriving without
// a Cache Response first starts a Full one: nothing says what it patched.
func (c *Client) recorder() *store.DeltaRecorder {
	if c.delta == nil {
		c.delta = store.NewDeltaRecorder(true)
	}
	return c.delta
}

// SetOnUpdate sets a callback invoked after a sync that changed the VRP or
// ASPA data: a full sync, a new serial, or any records applied. A poll that
// finds the cache's serial unchanged does not call it. fn receives what the
// sync changed; a Full delta means the stores were rebuilt.
func (c *Client) SetOnUpdate(fn func(*store.Delta)) {
	c.onUpdate = fn
}

// ProtocolVersion returns the RTR protocol version of the cache's current (or
// last) session: 2 means its data includes ASPA. 0 before any session. Safe
// from any goroutine; from the OnSync callback it is the synced session's.
func (c *Client) ProtocolVersion() uint8 { return uint8(c.sessionVersion.Load()) }

// SetOnSync sets a callback invoked after every completed sync (End of
// Data), whether or not the data changed. For a sync that changed the data
// it runs after the update callback.
func (c *Client) SetOnSync(fn func()) {
	c.onSync = fn
}

// SetVersionPinned, with pinned true, holds every session at the configured
// version: a cache that rejects it (Error Report code 4), drops the
// connection or answers at another version is retried at the same version
// with the normal backoff, never at a lower one. Call before Start.
func (c *Client) SetVersionPinned(pinned bool) { c.pinned = pinned }

// SetVersionReprobeInterval sets how often, after a cache has made the client
// downgrade, it checks whether the cache now supports the configured version
// (default one hour). Zero or less keeps the default.
func (c *Client) SetVersionReprobeInterval(d time.Duration) {
	if d > 0 {
		c.reprobeInterval = d
	}
}

// ExpireOverride returns the Expire Interval, in seconds, that a configured
// rtr.expire-interval sets: the value clamped to RFC 8210's range (600 to
// 172800 seconds, §6), and whether it had to be clamped. Zero or less is
// unset: 0, and each cache's own interval applies.
func ExpireOverride(seconds int) (effective uint32, clamped bool) {
	if seconds <= 0 {
		return 0, false
	}
	v := uint32(min(seconds, int(expireRange[1])))
	if v < expireRange[0] {
		v = expireRange[0]
	}
	return v, int(v) != seconds
}

// SetExpireOverride makes seconds (from ExpireOverride) the Expire Interval
// in place of the one each End of Data carries; 0 keeps the cache's.
func (c *Client) SetExpireOverride(seconds uint32) {
	c.expireOverride = seconds
	if seconds != 0 {
		c.expire = seconds
	}
}

// ExpireInterval returns the Expire Interval in effect, in seconds: the
// override if one is set, else the last End of Data's (the default before
// the first).
func (c *Client) ExpireInterval() uint32 { return c.expire }

// SetTelemetry attaches a telemetry recorder. Passing nil (or never calling
// this) disables telemetry; all recording calls become no-ops.
func (c *Client) SetTelemetry(rec *telemetry.Recorder) {
	c.tel = rec
}

// Start connects to the RTR cache and maintains the session.
// Reconnects with exponential backoff on failure. Blocks until ctx is cancelled.
func (c *Client) Start(ctx context.Context) {
	retryDelay := c.retryMin
	metrics.RTRDataExpired.WithLabelValues(c.address).Set(0)
	defer func() {
		if c.expireTimer != nil {
			c.expireTimer.Stop()
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		c.sessionSynced, c.sessionResponded, c.sessionDialed = false, false, false
		err := c.runSession(ctx)
		if ctx.Err() != nil {
			return
		}
		if c.sessionSynced {
			retryDelay = c.retryMin
		}
		retryNow := c.negotiateAfterSession(err)

		switch {
		case errors.Is(err, errVersionUpgrade):
			c.log.Info("RTR reconnecting to upgrade protocol version", "protocol_version", c.negotiatedVersion)
			retryDelay = 0
		case retryNow:
			// A negotiation step, not a failure: try the lower version now.
			c.log.Info("RTR reconnecting at a lower protocol version", "error", err,
				"protocol_version", c.negotiatedVersion)
			retryDelay = 0
		case errors.Is(err, errCacheNotReady):
			c.log.Info("RTR cache not ready, reconnecting", "error", err, "retry_in", retryDelay,
				"protocol_version", c.negotiatedVersion)
		default:
			c.log.Error("RTR session failed, reconnecting", "error", err, "retry_in", retryDelay)
		}

		// Keep watching for expiry while disconnected: a cache that is
		// unreachable is exactly when the data goes stale.
		wait := time.NewTimer(retryDelay)
	backoff:
		for {
			select {
			case <-wait.C:
				break backoff
			case <-timerC(c.expireTimer):
				c.expireTimer = nil
				c.markExpired()
			case <-ctx.Done():
				wait.Stop()
				return
			}
		}
		retryDelay = min(max(retryDelay*2, c.retryMin), c.retryMax)
	}
}

// negotiateAfterSession updates the version the next session opens at from
// how this one ended, and reports whether the next should start at once (a
// negotiation step) rather than after the backoff.
func (c *Client) negotiateAfterSession(err error) (retryNow bool) {
	if c.sessionResponded {
		// The cache answered at this version, whatever it said: drops
		// before a response may lower the version again later.
		c.dropTrial, c.dropRetryUsed = false, false
	}
	switch {
	case errors.Is(err, errVersionDowngrade):
		return true
	case c.sessionResponded || c.pinned || !c.sessionDialed:
		return false
	}

	// The session connected and ended with no response to its first query.
	if c.dropTrial {
		// The lower version did no better: the drop was not about the
		// version. Back to the version that was in use, at the normal
		// backoff.
		c.dropTrial = false
		c.log.Warn("RTR session at the lower protocol version also ended without a response; going back",
			"protocol_version", c.protoVersion, "next_version", c.dropTrialFrom, "error", err)
		c.negotiatedVersion = c.dropTrialFrom
		return false
	}
	reason, _ := disconnectReason(context.Background(), err)
	if (reason != telemetry.DisconnectReasonEOF && reason != telemetry.DisconnectReasonReset) ||
		c.dropRetryUsed || c.protoVersion == 0 {
		return false
	}
	next := c.protoVersion - 1
	c.log.Warn("cache closed the connection before answering; retrying once at a lower RTR protocol version",
		"protocol_version", c.protoVersion, "next_version", next, "disconnect_reason", reason)
	c.tel.Record(telemetry.SessionEvent{
		Cache:            c.address,
		EventType:        telemetry.EventVersionDowngrade,
		ProtoVersion:     c.protoVersion,
		NextProtoVersion: &next,
		DowngradeReason:  telemetry.DowngradeReasonSessionDropped,
		DisconnectReason: string(reason),
	})
	c.dropTrial, c.dropTrialFrom, c.dropRetryUsed = true, c.protoVersion, true
	c.negotiatedVersion = next
	return true
}

// recordDisconnect records the end of a session that connected.
func (c *Client) recordDisconnect(ctx context.Context, err error) {
	reason, code := disconnectReason(ctx, err)
	ev := telemetry.SessionEvent{
		Cache:            c.address,
		EventType:        telemetry.EventDisconnected,
		DisconnectReason: string(reason),
		ErrorCode:        code,
		ProtoVersion:     c.protoVersion,
	}
	if err != nil && reason != telemetry.DisconnectReasonShutdown {
		ev.ErrorText = err.Error()
	}
	c.tel.Record(ev)
}

// disconnectReason classifies how a session ended: err is what runSession
// returned, ctx its context. code is the Error
// Report's, for DisconnectReasonErrorReport.
func disconnectReason(ctx context.Context, err error) (telemetry.DisconnectReason, *uint16) {
	var report *errorReportError
	var netErr net.Error
	switch {
	case ctx.Err() != nil || err == nil:
		return telemetry.DisconnectReasonShutdown, nil
	case errors.Is(err, errVersionUpgrade):
		return telemetry.DisconnectReasonVersionUpgrade, nil
	case errors.As(err, &report):
		code := report.code
		return telemetry.DisconnectReasonErrorReport, &code
	case errors.Is(err, errNoResponse), errors.Is(err, syscall.ETIMEDOUT),
		errors.As(err, &netErr) && netErr.Timeout():
		return telemetry.DisconnectReasonTimeout, nil
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return telemetry.DisconnectReasonEOF, nil
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return telemetry.DisconnectReasonReset, nil
	default:
		return telemetry.DisconnectReasonError, nil
	}
}

// dialer returns the dialer for RTR connections, with TCP keepalive on. TLS
// connections use it for their underlying TCP connection too.
func (c *Client) dialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAliveConfig: rtrKeepAlive}
}

// dial connects to the cache over the configured transport. It also returns
// the underlying TCP connection, if there is one.
func (c *Client) dial(ctx context.Context) (net.Conn, *net.TCPConn, error) {
	switch c.transport {
	case "tls":
		// tls.DialWithDialer ignores DialContext's deadline, so we bound the
		// handshake via the dialer's own Timeout.
		tconn, err := tls.DialWithDialer(c.dialer(), "tcp", c.address, c.tlsCfg)
		if err != nil {
			return nil, nil, fmt.Errorf("connect (tls): %w", err)
		}
		// Reach through tls.Conn to the underlying TCP socket so we can apply
		// the same buffer tunings used on plaintext sessions.
		tc, _ := tconn.NetConn().(*net.TCPConn)
		return tconn, tc, nil
	default:
		pc, err := c.dialer().DialContext(ctx, "tcp", c.address)
		if err != nil {
			return nil, nil, fmt.Errorf("connect: %w", err)
		}
		tc, _ := pc.(*net.TCPConn)
		return pc, tc, nil
	}
}

// probeResult is what a version re-probe found.
type probeResult int

const (
	probeInconclusive probeResult = iota // no answer, or one that says nothing about the version
	probeSupported                       // the cache answered at the version
	probeUnsupported                     // Error Report code 4
)

// probeVersion opens a separate, short connection and sends a Reset Query at
// version, to learn whether the cache now supports it without disturbing the
// running session. It reads only the first reply.
func (c *Client) probeVersion(ctx context.Context, version uint8) (probeResult, string) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, _, err := c.dial(ctx)
	if err != nil {
		return probeInconclusive, err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	if err := c.sendResetQuery(conn, version); err != nil {
		return probeInconclusive, err.Error()
	}
	v, pduType, code, payload, err := c.readPDU(bufio.NewReader(conn))
	switch {
	case err != nil:
		return probeInconclusive, err.Error()
	case pduType == PDUCacheResponse && v == version:
		return probeSupported, ""
	case pduType == PDUErrorReport && code == errCodeUnsupportedProtoVer:
		return probeUnsupported, c.parseErrorReport(payload)
	case pduType == PDUErrorReport:
		return probeInconclusive, fmt.Sprintf("error report code %d: %s", code, c.parseErrorReport(payload))
	default:
		return probeInconclusive, fmt.Sprintf("unexpected PDU type %d at version %d", pduType, v)
	}
}

// pduResult is one PDU, or the read error that ended the session.
type pduResult struct {
	version   uint8
	pduType   uint8
	sessionID uint16
	payload   []byte
	err       error
}

// readLoop reads PDUs into out until a read fails or stop is closed. It runs
// on its own goroutine so the session loop can wait on PDUs and its timers
// at once.
func (c *Client) readLoop(r *bufio.Reader, out chan<- pduResult, stop <-chan struct{}) {
	for {
		var res pduResult
		res.version, res.pduType, res.sessionID, res.payload, res.err = c.readPDU(r)
		select {
		case out <- res:
		case <-stop:
			return
		}
		if res.err != nil {
			return
		}
	}
}

// runSession handles a single RTR connection lifecycle.
//
// After the initial Reset Query it keeps the data current two ways: it sends
// a Serial Query when the cache sends a Serial Notify, and, since a cache
// need not notify, whenever the Refresh Interval from the last End of Data
// passes without one (RFC 8210 §6). A query that gets no response within
// the Retry Interval fails the session.
//
// Every session that connects ends with a disconnected telemetry event
// saying why.
func (c *Client) runSession(ctx context.Context) (err error) {
	c.protoVersion = c.negotiatedVersion

	conn, tcpRaw, err := c.dial(ctx)
	if err != nil {
		return err
	}
	c.sessionDialed = true
	defer conn.Close()
	defer func() { c.recordDisconnect(ctx, err) }()
	if c.connHook != nil {
		c.connHook(conn)
	}

	// Tune TCP buffers to handle large VRP table dumps
	if tcpRaw != nil && c.transport != "tls" {
		tcpRaw.SetNoDelay(true)
		tcpRaw.SetReadBuffer(4 * 1024 * 1024)
		tcpRaw.SetWriteBuffer(1 * 1024 * 1024)
	}

	c.log.Info("RTR connected", "transport", c.transport, "protocol_version", c.protoVersion)
	c.tel.Record(telemetry.SessionEvent{
		Cache:        c.address,
		EventType:    telemetry.EventConnected,
		ProtoVersion: c.protoVersion,
	})
	metrics.RTRSessionState.WithLabelValues(c.address).Set(1)
	defer metrics.RTRSessionState.WithLabelValues(c.address).Set(0)
	metrics.RTRVRPCount.WithLabelValues(c.address).Set(float64(c.vrpStore.Count()))
	metrics.RTRASPACount.WithLabelValues(c.address).Set(float64(c.aspaStore.Count()))

	// Timers: refresh fires the next poll and is armed only after an End of
	// Data; response bounds the wait for an answer to the outstanding query
	// and is non-nil exactly while one is outstanding.
	//
	// reprobe, on a session below the configured version, fires the next
	// version re-probe; probed delivers its result.
	var refresh, response, reprobe *time.Timer
	probed := make(chan probeResult, 1)
	var probeDetail string
	defer func() {
		for _, t := range []*time.Timer{refresh, response, reprobe} {
			if t != nil {
				t.Stop()
			}
		}
	}()
	query := func(send func() error) error {
		if refresh != nil {
			refresh.Stop()
			refresh = nil
		}
		c.syncStart = time.Now()
		if err := send(); err != nil {
			return err
		}
		response = time.NewTimer(c.interval(c.retry))
		return nil
	}

	// Send Reset Query to get the full VRP set
	c.fullSyncPending = true
	if err := query(func() error { return c.sendResetQuery(conn, c.protoVersion) }); err != nil {
		return fmt.Errorf("send reset query: %w", err)
	}

	// Buffered reader — critical for draining large VRP table dumps
	reader := bufio.NewReaderSize(conn, 4*1024*1024) // 4MB read buffer
	pdus := make(chan pduResult)
	stop := make(chan struct{})
	defer close(stop) // runs before conn.Close, which unblocks the reader
	go c.readLoop(reader, pdus, stop)

	established := false
	var notifiedSerial uint32
	notifyPending := false // a Serial Notify arrived while a query was outstanding

	for {
		var res pduResult
		select {
		case <-ctx.Done():
			return nil
		case <-timerC(c.expireTimer):
			c.expireTimer = nil
			c.markExpired()
			continue
		case <-timerC(refresh):
			refresh = nil
			c.log.Debug("refresh interval elapsed, polling cache", "serial", c.serial)
			if err := query(func() error { return c.sendSerialQuery(conn, c.sessionID, c.serial) }); err != nil {
				return fmt.Errorf("send serial query: %w", err)
			}
			continue
		case <-timerC(response):
			return fmt.Errorf("%w (%s)", errNoResponse, c.interval(c.retry))
		case <-timerC(reprobe):
			reprobe = nil
			c.log.Info("re-probing RTR protocol version", "version", c.configVersion,
				"current_version", c.protoVersion)
			go func() {
				r, detail := c.probeVersion(ctx, c.configVersion)
				probeDetail = detail
				probed <- r
			}()
			continue
		case r := <-probed:
			switch r {
			case probeSupported:
				c.log.Info("cache now supports the configured RTR protocol version; upgrading",
					"version", c.configVersion, "current_version", c.protoVersion)
				c.negotiatedVersion = c.configVersion
				c.downgradedAt = time.Time{}
				return errVersionUpgrade
			case probeUnsupported:
				c.downgradedAt = time.Now()
				c.log.Warn("cache still does not support the configured RTR protocol version; staying downgraded",
					"version", c.configVersion, "current_version", c.protoVersion,
					"next_reprobe_in", c.reprobeInterval, "error_text", probeDetail)
			default:
				c.log.Warn("RTR protocol version re-probe inconclusive; staying downgraded",
					"version", c.configVersion, "current_version", c.protoVersion,
					"next_reprobe_in", c.reprobeInterval, "detail", probeDetail)
			}
			reprobe = time.NewTimer(c.reprobeInterval)
			continue
		case res = <-pdus:
		}
		if res.err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read PDU: %w", res.err)
		}
		c.sessionResponded = true
		// The cache is answering; a large dump may take a while to arrive.
		if response != nil {
			response.Reset(c.interval(c.retry))
		}
		pduType, sessionID, payload := res.pduType, res.sessionID, res.payload

		switch pduType {
		case PDUCacheResponse:
			c.log.Debug("cache response", "session_id", sessionID)
			if !established {
				if c.pinned && res.version != c.protoVersion {
					c.log.Error("cache answered at another RTR protocol version than the pinned one",
						"protocol_version", c.protoVersion, "answered_version", res.version)
					return fmt.Errorf("cache answered at RTR protocol version %d, pinned to %d", res.version, c.protoVersion)
				}
				established = true
				c.sessionEstablished(res.version)
				if c.protoVersion < c.configVersion {
					if c.downgradedAt.IsZero() {
						c.downgradedAt = time.Now()
					}
					reprobe = time.NewTimer(max(0, time.Until(c.downgradedAt.Add(c.reprobeInterval))))
				}
			}
			// Reset per-sync counters at the start of each cache response so
			// the EndOfData telemetry reflects only this sync's deltas.
			c.vrpAnnounced, c.vrpWithdrawn = 0, 0
			c.aspaAnnounced, c.aspaWithdrawn = 0, 0
			// A full sync rebuilds the stores (and sessionEstablished may
			// have cleared ASPA): only a full revalidation follows it.
			c.delta = store.NewDeltaRecorder(c.fullSyncPending)
			// If we're servicing a Reset Query, clear the stores so the
			// incoming full snapshot replaces rather than appends. Without
			// this, every reconnect doubles the VRP store size.
			if c.fullSyncPending {
				c.vrpStore.Clear()
				c.aspaStore.Clear()
			}

		case PDUIPv4Prefix:
			vrp, withdraw, err := c.parseIPv4Prefix(payload)
			if err != nil {
				c.log.Error("bad IPv4 prefix PDU", "error", err)
				continue
			}
			if withdraw {
				c.vrpStore.RemoveVRP(vrp)
				c.vrpWithdrawn++
			} else {
				c.vrpStore.AddVRP(vrp)
				c.vrpAnnounced++
			}
			c.recorder().VRP(vrp, withdraw)

		case PDUIPv6Prefix:
			vrp, withdraw, err := c.parseIPv6Prefix(payload)
			if err != nil {
				c.log.Error("bad IPv6 prefix PDU", "error", err)
				continue
			}
			if withdraw {
				c.vrpStore.RemoveVRP(vrp)
				c.vrpWithdrawn++
			} else {
				c.vrpStore.AddVRP(vrp)
				c.vrpAnnounced++
			}
			c.recorder().VRP(vrp, withdraw)

		case PDUASPA:
			customerASN, providerASNs, withdraw, err := c.parseASPAPDU(sessionID, payload)
			if err != nil {
				c.log.Error("bad ASPA PDU", "error", err)
				continue
			}
			changed := false
			if withdraw {
				for _, p := range providerASNs {
					changed = c.aspaStore.RemoveProvider(customerASN, p) || changed
				}
				c.aspaWithdrawn++
			} else {
				for _, p := range providerASNs {
					changed = c.aspaStore.AddProvider(customerASN, p) || changed
				}
				c.aspaAnnounced++
			}
			if changed {
				c.recorder().ASPA(customerASN)
			}

		case PDUEndOfData:
			eod, err := c.parseEndOfData(res.version, payload)
			if err != nil {
				c.log.Error("bad end-of-data PDU", "error", err)
				continue
			}
			if response != nil {
				response.Stop()
				response = nil
			}
			c.endOfData(sessionID, eod)
			c.sessionSynced = true
			c.hasReset = true

			// A notify for a serial this sync did not reach: ask again now.
			if notifyPending && notifiedSerial != c.serial {
				notifyPending = false
				if err := query(func() error { return c.sendSerialQuery(conn, c.sessionID, c.serial) }); err != nil {
					return fmt.Errorf("send serial query: %w", err)
				}
				continue
			}
			notifyPending = false
			refresh = time.NewTimer(c.interval(c.refresh))

		case PDUSerialNotify:
			if len(payload) < 4 {
				continue
			}
			serial := binary.BigEndian.Uint32(payload[0:4])
			c.log.Debug("serial notify", "serial", serial)
			if response != nil {
				// A query is already outstanding; its End of Data may or
				// may not reach this serial.
				notifiedSerial, notifyPending = serial, true
				continue
			}
			if !c.haveSerial || serial == c.serial {
				continue
			}
			if err := query(func() error { return c.sendSerialQuery(conn, c.sessionID, c.serial) }); err != nil {
				return fmt.Errorf("send serial query: %w", err)
			}

		case PDUCacheReset:
			c.log.Warn("cache reset received, performing full sync")
			c.tel.Record(telemetry.SessionEvent{
				Cache:        c.address,
				EventType:    telemetry.EventReset,
				ResetReason:  telemetry.ResetReasonCacheResetPDU,
				ProtoVersion: c.protoVersion,
			})
			c.fullSyncPending = true
			if err := query(func() error { return c.sendResetQuery(conn, c.protoVersion) }); err != nil {
				return fmt.Errorf("send reset query after cache reset: %w", err)
			}

		case PDUErrorReport:
			return c.errorReport(res.version, sessionID, payload, established)

		default:
			c.log.Debug("unknown RTR PDU type", "type", pduType)
		}
	}
}

// sessionEstablished records the protocol version the cache answered at,
// which the rest of the session (and the next) uses.
func (c *Client) sessionEstablished(version uint8) {
	if version < c.protoVersion {
		// The cache answered at a version below the one asked for.
		c.protoVersion = version
		c.negotiatedVersion = version
	}
	c.sessionVersion.Store(uint32(c.protoVersion))
	c.log.Info("RTR session established", "transport", c.transport, "protocol_version", c.protoVersion,
		"configured_version", c.configVersion, "pinned", c.pinned)
	metrics.RTRProtocolVersion.WithLabelValues(c.address).Set(float64(c.protoVersion))
	if c.protoVersion < 2 {
		// ASPA records exist only from version 2. Drop any left from an
		// earlier version 2 session rather than validate against them
		// indefinitely.
		c.aspaStore.Clear()
		metrics.RTRASPACount.WithLabelValues(c.address).Set(0)
		c.log.Warn("RTR session below protocol version 2: ASPA validation is unavailable",
			"protocol_version", c.protoVersion)
	}
}

// endOfData completes a sync: it records the cache's serial and timing,
// updates metrics and telemetry, re-arms the expiry timer and, if the data
// changed, notifies the update callback.
func (c *Client) endOfData(sessionID uint16, eod endOfData) {
	serialChanged := !c.haveSerial || eod.serial != c.serial
	applied := c.vrpAnnounced + c.vrpWithdrawn + c.aspaAnnounced + c.aspaWithdrawn
	dataChanged := c.fullSyncPending || serialChanged || applied > 0
	delta := c.recorder()
	if c.fullSyncPending || (c.haveSerial && sessionID != c.sessionID) {
		delta.MarkFull()
	}
	c.delta = nil
	c.sessionID, c.serial, c.haveSerial = sessionID, eod.serial, true
	c.refresh, c.retry, c.expire = eod.refresh, eod.retry, eod.expire
	if c.expireOverride != 0 {
		c.expire = c.expireOverride
	}

	c.vrpStore.SetSerial(eod.serial, sessionID)
	if dataChanged {
		c.vrpStore.RebuildIndex()
	}

	// Emit sync telemetry before clearing fullSyncPending, which
	// distinguishes a full (Reset Query) from an incremental sync.
	now := time.Now()
	syncType := telemetry.SyncTypeIncremental
	if c.fullSyncPending {
		syncType = telemetry.SyncTypeFull
	}
	ev := telemetry.SessionEvent{
		Timestamp:     now,
		Cache:         c.address,
		EventType:     telemetry.EventSync,
		Serial:        eod.serial,
		SerialChanged: &serialChanged,
		VRPTotal:      int(c.vrpStore.Count()),
		VRPAnnounced:  c.vrpAnnounced,
		VRPWithdrawn:  c.vrpWithdrawn,
		ASPATotal:     c.aspaStore.Count(),
		ASPAAnnounced: c.aspaAnnounced,
		ASPAWithdrawn: c.aspaWithdrawn,
		SyncDuration:  now.Sub(c.syncStart),
		SyncType:      syncType,
		ProtoVersion:  c.protoVersion,
	}
	if !c.lastSyncTime.IsZero() {
		ev.IntervalSince = now.Sub(c.lastSyncTime)
	}
	c.tel.Record(ev)
	c.lastSyncTime = now
	c.fullSyncPending = false

	metrics.RTRVRPCount.WithLabelValues(c.address).Set(float64(c.vrpStore.Count()))
	metrics.RTRASPACount.WithLabelValues(c.address).Set(float64(c.aspaStore.Count()))
	metrics.RTRLastSync.WithLabelValues(c.address).Set(float64(now.Unix()))
	if serialChanged {
		metrics.RTRLastSerialChange.WithLabelValues(c.address).Set(float64(now.Unix()))
	}

	if c.expired {
		c.log.Info("RTR data current again", "serial", eod.serial)
	}
	c.expired = false
	metrics.RTRDataExpired.WithLabelValues(c.address).Set(0)
	if c.expireTimer != nil {
		c.expireTimer.Stop()
	}
	c.expireTimer = time.NewTimer(c.interval(c.expire))

	c.log.Info("RTR sync complete",
		"vrp_count", c.vrpStore.Count(),
		"aspa_count", c.aspaStore.Count(),
		"serial", eod.serial,
		"serial_changed", serialChanged,
		"session_id", sessionID,
		"refresh", eod.refresh, "retry", eod.retry, "expire", eod.expire,
		"expire_effective", c.expire,
	)
	// Update before sync: whoever sees the sync recorded can rely on the
	// update (in raven serve, the revalidation request) having been made.
	if dataChanged && c.onUpdate != nil {
		c.onUpdate(delta.Delta())
	}
	if c.onSync != nil {
		c.onSync()
	}
	c.readyOnce.Do(func() { close(c.ready) })
}

// markExpired flags the cache's data as expired: no sync has completed within
// its Expire Interval. The data is kept; validation goes on using it.
func (c *Client) markExpired() {
	if c.expired {
		return
	}
	c.expired = true
	metrics.RTRDataExpired.WithLabelValues(c.address).Set(1)
	c.log.Error("RTR data expired: no sync with the cache completed within its expire interval; still validating with the last data received",
		"expire_interval", c.interval(c.expire), "last_sync", c.lastSyncTime, "serial", c.serial)
}

// errorReport handles an Error Report from the cache, which ends the session,
// and returns the error to end it with. established says whether the
// session had received a Cache Response before it.
//
// Code 4 (Unsupported Protocol Version) before the session is established
// is version negotiation: the client steps down one version, or straight to
// the cache's own version when its Error Report carries a lower one, and
// records an informational version_downgrade event, not an error. Code 4 on
// an established session, at version 0 or at a pinned version is a fault
// and recorded as an error. Code 2 (No Data Available) never changes the
// version.
func (c *Client) errorReport(version uint8, code uint16, payload []byte, established bool) error {
	errMsg := c.parseErrorReport(payload)
	canFallBack := code == errCodeUnsupportedProtoVer && !c.pinned && c.protoVersion > 0
	var next uint8
	if canFallBack {
		next = c.protoVersion - 1
		if version < c.protoVersion {
			next = version // the cache's own version, from its Error Report
		}
	}
	negotiating := canFallBack && !established

	ev := telemetry.SessionEvent{
		Cache:        c.address,
		EventType:    telemetry.EventError,
		ErrorText:    errMsg,
		ErrorCode:    &code,
		ProtoVersion: c.protoVersion,
	}
	switch {
	case code == errCodeNoDataAvailable:
		ev.EventType = telemetry.EventCacheNotReady
	case negotiating:
		ev.EventType = telemetry.EventVersionDowngrade
		ev.NextProtoVersion = &next
		ev.DowngradeReason = telemetry.DowngradeReasonUnsupportedVersion
	}
	c.tel.Record(ev)

	wrap := func(err error) error { return &errorReportError{code: code, err: err} }
	switch {
	case code == errCodeNoDataAvailable:
		// Not a version problem: the cache is still building its data
		// (Routinator sends "Running initial validation" at startup).
		// Retry later, at the same version.
		return wrap(fmt.Errorf("%w (%s)", errCacheNotReady, errMsg))

	case code == errCodeUnsupportedProtoVer && c.pinned:
		c.log.Error("cache rejected the pinned RTR protocol version; retrying at the same version",
			"protocol_version", c.protoVersion, "error_text", errMsg)
		return wrap(fmt.Errorf("cache does not support the pinned RTR protocol version %d: %s", c.protoVersion, errMsg))

	case code == errCodeUnsupportedProtoVer && c.protoVersion == 0:
		c.log.Error("cache rejected RTR protocol version 0", "error_text", errMsg)
		return wrap(fmt.Errorf("cache does not support RTR protocol version 0: %s", errMsg))

	case code == errCodeUnsupportedProtoVer:
		c.log.Warn("cache does not support this RTR protocol version, downgrading",
			"protocol_version", c.protoVersion, "next_version", next, "error_text", errMsg,
			"established", established, "reprobe_in", c.reprobeInterval)
		c.negotiatedVersion = next
		c.downgradedAt = time.Now()
		err := fmt.Errorf("cache does not support RTR protocol version %d (retrying at %d): %s", c.protoVersion, next, errMsg)
		if negotiating {
			err = fmt.Errorf("%w: %w", errVersionDowngrade, err)
		}
		return wrap(err)

	default:
		c.log.Error("RTR error report from cache", "code", code, "error_text", errMsg)
		return wrap(fmt.Errorf("cache sent error report (code %d): %s", code, errMsg))
	}
}

// interval converts an End of Data interval to a duration.
func (c *Client) interval(seconds uint32) time.Duration {
	return time.Duration(seconds) * c.unit
}

// timerC returns t's channel, or nil (never ready) for no timer.
func timerC(t *time.Timer) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

// readPDU reads a single RTR PDU from the connection.
func (c *Client) readPDU(r *bufio.Reader) (version, pduType uint8, sessionID uint16, payload []byte, err error) {
	hdr := make([]byte, rtrHeaderLen)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, 0, 0, nil, err
	}
	version = hdr[0]
	pduType = hdr[1]
	sessionID = binary.BigEndian.Uint16(hdr[2:4])
	length := binary.BigEndian.Uint32(hdr[4:8])
	if length < rtrHeaderLen {
		return version, pduType, sessionID, nil, fmt.Errorf("PDU length %d < header size", length)
	}
	payloadLen := int(length) - rtrHeaderLen
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err = io.ReadFull(r, payload); err != nil {
			return version, pduType, sessionID, nil, err
		}
	}
	return version, pduType, sessionID, payload, nil
}

// parseASPAPDU parses an ASPA PDU (type 11) from RTR v2.
// Format per draft-ietf-sidrops-8210bis:
//
//	Flags (1) | AFI Flags (1) | Customer ASN (4) | Provider AS Count (2) | Provider ASNs (4 each)
func (c *Client) parseASPAPDU(sessionID uint16, data []byte) (customerASN uint32, providerASNs []uint32, withdraw bool, err error) {
	flags := uint8(sessionID >> 8)
	withdraw = flags&0x01 == 0

	if len(data) < 4 {
		return 0, nil, false, fmt.Errorf("ASPA PDU too short: %d", len(data))
	}
	customerASN = binary.BigEndian.Uint32(data[0:4])

	// No explicit provider count — derive from remaining payload length
	remaining := len(data) - 4
	if remaining%4 != 0 {
		return 0, nil, false, fmt.Errorf("ASPA PDU malformed: %d extra bytes after customerASN", remaining)
	}
	providerCount := remaining / 4
	providerASNs = make([]uint32, providerCount)
	for i := 0; i < providerCount; i++ {
		providerASNs[i] = binary.BigEndian.Uint32(data[4+i*4 : 8+i*4])
	}
	return customerASN, providerASNs, withdraw, nil
}

// sendResetQuery sends an RTR Reset Query PDU at the given version.
func (c *Client) sendResetQuery(conn net.Conn, version uint8) error {
	pdu := make([]byte, 8)
	pdu[0] = version
	pdu[1] = PDUResetQuery
	// session_id = 0
	binary.BigEndian.PutUint32(pdu[4:8], 8) // length = 8
	_, err := conn.Write(pdu)
	return err
}

// sendSerialQuery sends an RTR Serial Query PDU.
func (c *Client) sendSerialQuery(conn net.Conn, sessionID uint16, serial uint32) error {
	pdu := make([]byte, 12)
	pdu[0] = c.protoVersion
	pdu[1] = PDUSerialQuery
	binary.BigEndian.PutUint16(pdu[2:4], sessionID)
	binary.BigEndian.PutUint32(pdu[4:8], 12) // length = 12
	binary.BigEndian.PutUint32(pdu[8:12], serial)
	_, err := conn.Write(pdu)
	return err
}

// parseIPv4Prefix parses an IPv4 Prefix PDU payload.
// Returns the VRP and whether this is a withdrawal (flags bit 0 = 0).
func (c *Client) parseIPv4Prefix(data []byte) (types.VRP, bool, error) {
	// IPv4 Prefix PDU payload (after header):
	// flags(1) + prefixLen(1) + maxLen(1) + zero(1) + prefix(4) + ASN(4)
	if len(data) < 12 {
		return types.VRP{}, false, fmt.Errorf("IPv4 prefix PDU too short: %d", len(data))
	}

	flags := data[0]
	prefixLen := int(data[1])
	maxLen := data[2]
	// data[3] is zero/reserved

	addr, ok := netip.AddrFromSlice(data[4:8])
	if !ok {
		return types.VRP{}, false, fmt.Errorf("invalid IPv4 address")
	}
	prefix := netip.PrefixFrom(addr, prefixLen)
	asn := binary.BigEndian.Uint32(data[8:12])

	withdraw := flags&0x01 == 0 // flags bit 0: 1=announce, 0=withdraw

	return types.VRP{
		Prefix:    prefix,
		ASN:       asn,
		MaxLength: maxLen,
	}, withdraw, nil
}

// parseIPv6Prefix parses an IPv6 Prefix PDU payload.
func (c *Client) parseIPv6Prefix(data []byte) (types.VRP, bool, error) {
	// IPv6 Prefix PDU payload (after header):
	// flags(1) + prefixLen(1) + maxLen(1) + zero(1) + prefix(16) + ASN(4)
	if len(data) < 24 {
		return types.VRP{}, false, fmt.Errorf("IPv6 prefix PDU too short: %d", len(data))
	}

	flags := data[0]
	prefixLen := int(data[1])
	maxLen := data[2]

	addr, ok := netip.AddrFromSlice(data[4:20])
	if !ok {
		return types.VRP{}, false, fmt.Errorf("invalid IPv6 address")
	}
	prefix := netip.PrefixFrom(addr, prefixLen)
	asn := binary.BigEndian.Uint32(data[20:24])

	withdraw := flags&0x01 == 0

	return types.VRP{
		Prefix:    prefix,
		ASN:       asn,
		MaxLength: maxLen,
	}, withdraw, nil
}

// endOfData is an End of Data PDU's serial and timing parameters, in seconds.
type endOfData struct {
	serial                 uint32
	refresh, retry, expire uint32
}

// parseEndOfData parses an End of Data PDU payload. Version 0 carries only
// the serial; versions 1 and 2 add the Refresh, Retry and Expire Intervals
// (RFC 8210 §5.8). Absent intervals (version 0) take the RFC defaults; an
// out-of-range interval is clamped to the nearest bound of its §6 range, so
// a Refresh Interval of 0 ("refresh now") becomes 1 second, not the default.
func (c *Client) parseEndOfData(version uint8, data []byte) (endOfData, error) {
	if len(data) < 4 {
		return endOfData{}, fmt.Errorf("end-of-data PDU too short: %d", len(data))
	}
	eod := endOfData{
		serial:  binary.BigEndian.Uint32(data[0:4]),
		refresh: defaultRefresh,
		retry:   defaultRetry,
		expire:  defaultExpire,
	}
	if version == 0 || len(data) < 16 {
		return eod, nil
	}
	field := func(name string, v uint32, valid [2]uint32) uint32 {
		clamped := min(max(v, valid[0]), valid[1])
		if clamped != v {
			c.log.Warn("cache sent an out-of-range End of Data interval; clamped",
				"interval", name, "value", v, "clamped", clamped)
		}
		return clamped
	}
	eod.refresh = field("refresh", binary.BigEndian.Uint32(data[4:8]), refreshRange)
	eod.retry = field("retry", binary.BigEndian.Uint32(data[8:12]), retryRange)
	eod.expire = field("expire", binary.BigEndian.Uint32(data[12:16]), expireRange)
	return eod, nil
}

// parseErrorReport extracts the error text from an RTR Error Report PDU.
func (c *Client) parseErrorReport(data []byte) string {
	// Error Report payload:
	// Length of Encapsulated PDU (4 bytes)
	// Encapsulated PDU (variable)
	// Length of Error Text (4 bytes)
	// Error Text (variable)
	if len(data) < 4 {
		return "(empty error report)"
	}

	encapLen := binary.BigEndian.Uint32(data[0:4])
	offset := 4 + int(encapLen)

	if offset+4 > len(data) {
		return "(no error text)"
	}

	textLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset+int(textLen) > len(data) {
		return "(error text truncated)"
	}

	return string(data[offset : offset+int(textLen)])
}
