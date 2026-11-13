package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/aspa/recommender"
	"github.com/nokia/bgp-routing-security-monitor/internal/bmp"
	"github.com/nokia/bgp-routing-security-monitor/internal/buildinfo"
	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/events"
	"github.com/nokia/bgp-routing-security-monitor/internal/external"
	"github.com/nokia/bgp-routing-security-monitor/internal/external/ripestat"
	"github.com/nokia/bgp-routing-security-monitor/internal/flowspec"
	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	otelexporter "github.com/nokia/bgp-routing-security-monitor/internal/otel"
	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/snapshot"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation/aspa"
	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version is the RAVEN build version embedded in snapshots for compatibility
// checking. Set at build time via -ldflags "-X ...server.Version=v1.2.3".
var Version = "dev"

// APIListen is the address the JSON API server binds to: api.listen, or
// config.DefaultAPIListen (loopback only) when unset.
func APIListen(cfg *config.Config) string {
	if cfg.API.Listen != "" {
		return cfg.API.Listen
	}
	return config.DefaultAPIListen
}

// otelShutdownTimeout bounds the OTel exporter's final flush on shutdown.
const otelShutdownTimeout = 5 * time.Second

// Server is the top-level RAVEN daemon that owns all subsystems.
type Server struct {
	cfg         *config.Config
	log         *slog.Logger
	table       *routetable.Table
	bmpListen   *bmp.Listener
	vrpStore    *store.VRPStore
	aspaStore   *store.ASPAStore
	engine      *validation.Engine
	eventEngine *events.Engine
	ingestCh    chan types.IngestEvent
	demoMode    bool
	apiSrv      *api.Server
	rtrReady    chan struct{}
	// heldRestored are routes restored from a snapshot that wait for the
	// first RTR sync to be inserted (restoreSnapshots). Set before ingestLoop
	// starts and owned by it after.
	heldRestored []*types.Route

	// fsManagers holds the active flowspec lifecycle managers.
	fsManagers []*flowspec.Manager

	// rtrMu guards rtrStates and rtrLastSync for StateReader.
	rtrMu       sync.RWMutex
	rtrStates   map[string]int64 // cache address → 1 connected, 0 disconnected
	rtrLastSync map[string]int64 // cache address → unix seconds of last sync
	rtrASPA     map[string]bool  // cache address → its last sync was at RTR version 2 (has ASPA)

	// Owned by ingestLoop.
	removals []*pendingRemoval
	// retired holds BMP sessions a newer session from the same router has
	// superseded and that have not ended yet, with the number of their
	// late events dropped so far.
	retired map[uint64]int
	// removalsPending mirrors len(removals) for tests.
	removalsPending atomic.Int64

	// revalidateCh carries RTR updates' requests to revalidate the table.
	// It holds one request at most: a request made while one is already
	// queued adds nothing.
	revalidateCh chan struct{}
	// pendingDelta merges the RTR deltas not yet taken by a pass; nil when
	// there are none. Guarded by deltaMu: RTR goroutines add to it.
	deltaMu      sync.Mutex
	pendingDelta *store.Delta
	// pendingUpdates are the RTR updates whose deltas pendingDelta merges,
	// for the pass's events (cache and serial). Guarded by deltaMu.
	pendingUpdates []rtrUpdate
	// rtrBatch collects the event-engine side of the revalidation pass in
	// progress (see publishChange); nil without an event engine. Owned by
	// ingestLoop.
	rtrBatch *events.RTRBatch
	// Owned by ingestLoop: the revalidation pass in progress, and whether
	// another was requested after it started and must follow it.
	revalidation    *validation.Revalidation
	revalidateAgain bool
	revalidateStart time.Time
	// For tests: whether a pass is in progress, and how many have finished.
	revalidating       atomic.Bool
	revalidationPasses atomic.Int64

	// evictCh carries the stale-eviction timer's request to ingestLoop.
	evictCh chan struct{}

	// Test hooks, nil in production. Both run on ingestLoop's goroutine:
	// testAfterEvent after an event has been applied, testAfterChunk after
	// each chunk of background work. They let a test act and observe at
	// exact points in the loop instead of racing it.
	testAfterEvent func(types.IngestEvent)
	testAfterChunk func()
	// testEmitted, if set, sees each event emitted to the event engine.
	testEmitted func(events.Event)

	// listening is closed once Run has bound its listeners; bmpAddr and
	// apiAddr are then their addresses (apiAddr nil if the API failed to
	// bind).
	listening chan struct{}
	bmpAddr   net.Addr
	apiAddr   net.Addr
}

// emitEvent hands ev to the event engine.
func (s *Server) emitEvent(ev events.Event) {
	if s.testEmitted != nil {
		s.testEmitted(ev)
	}
	s.eventEngine.Emit(ev)
}

// Background work (withdraw-alls and stale eviction, then revalidation
// passes) is applied a chunk at a time so it never holds up ingest: chunks run back to back while
// no event is waiting, and while events are waiting, one chunk runs per
// backgroundEvery events, so the work still finishes under sustained load, at
// one route per event applied. Removing or revalidating a route costs about
// what ingesting one does, so that at most halves ingest throughput while it
// lasts. No event waits on more than one chunk.
const (
	removalChunk    = 256
	revalidateChunk = 256
	backgroundEvery = 256
)

// pendingRemoval is a peer-down or session-end withdraw-all that ingestLoop
// is still applying.
type pendingRemoval struct {
	rm      *routetable.Removal
	session uint64
	peer    types.PeerRef // zero for a session end
	locRIB  bool          // a Loc-RIB instance's withdraw-all
	stale   bool          // stale eviction rather than a withdraw-all
	removed int
	started time.Time
}

// New creates a new RAVEN server from the given config.
func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	ingestCh := make(chan types.IngestEvent, 100_000)
	vrpStore := store.NewVRPStore()
	aspaStore := store.NewASPAStore() // ADD
	table := routetable.New()
	if cfg.Validation.ASPADefaultProcedure == "auto" {
		log.Warn("aspa-default-procedure auto has no BGP Role source yet; routes from peers not in aspa-peers fall back to upstream")
	}
	aspaSel := aspa.NewSelector(cfg.Validation.ASPADefaultProcedure, cfg.Validation.ASPAPeers)
	engine := validation.NewEngine(vrpStore, aspaStore, aspaSel, table, log)
	// No ASPA verification until an RTR cache syncs at version 2 (see
	// noteASPASource), or at all if it is disabled.
	if cfg.Validation.ASPA {
		engine.SetASPAUnavailable(validation.ASPAReasonNoData)
	} else {
		engine.SetASPAUnavailable(validation.ASPAReasonDisabled)
	}

	allowed, err := config.ParseAllowedRouters(cfg.BMP.AllowedRouters)
	if err != nil {
		return nil, err
	}

	var bmpTLS *tls.Config
	if cfg.BMP.TLS != nil {
		built, err := bmp.BuildTLSConfig(cfg.BMP.TLS)
		if err != nil {
			return nil, fmt.Errorf("BMP TLS: %w", err)
		}
		bmpTLS = built
	}

	srv := &Server{
		cfg:          cfg,
		log:          log,
		table:        table,
		bmpListen:    bmp.NewListener(cfg.BMP.Listen, bmpTLS, ingestCh, log),
		vrpStore:     vrpStore,
		aspaStore:    aspaStore, // ADD
		engine:       engine,
		ingestCh:     ingestCh,
		rtrReady:     make(chan struct{}),
		rtrStates:    make(map[string]int64),
		rtrLastSync:  make(map[string]int64),
		rtrASPA:      make(map[string]bool),
		retired:      make(map[uint64]int),
		revalidateCh: make(chan struct{}, 1),
		evictCh:      make(chan struct{}, 1),
		listening:    make(chan struct{}),
	}

	// Existing API server
	srv.bmpListen.SetAllowedRouters(allowed)
	srv.apiSrv = api.NewServer(table, srv.bmpListen, vrpStore, log, buildinfo.Version)

	// Phase 2b: what-if + recommender
	sim := whatif.NewSimulator(table)
	rec := recommender.NewRecommender(table, aspaStore)
	whatifHandler := api.NewWhatIfHandler(sim, rec, aspaStore)
	whatifHandler.RegisterRoutes(srv.apiSrv.Mux())

	// Audit endpoint
	auditHandler := api.NewAuditHandler(table)
	auditHandler.RegisterRoutes(srv.apiSrv.Mux())

	return srv, nil
}

// SetDemoMode enables demo mode with test VRPs instead of live RTR.
func (s *Server) SetDemoMode(enabled bool) {
	s.demoMode = enabled
}

// Run starts all subsystems and blocks until interrupted.
func (s *Server) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return s.RunContext(ctx)
}

// RunContext starts all subsystems and blocks until ctx is done (or the BMP
// listener fails), then shuts down as Run does on a signal.
func (s *Server) RunContext(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// Build event engine before starting any goroutines so that ingestLoop
	// sees a non-nil s.eventEngine from the start.
	if len(s.cfg.Events.Rules) > 0 {
		var opts []events.Option

		// External global-visibility correlation is opt-in and defaults to
		// disabled. When off, no provider is injected and a rule that asks
		// for a global-correlate action fails the build with a clear
		// message rather than silently doing nothing.
		if rs := s.cfg.External.RIPEstat; rs.Enabled {
			client, err := ripestat.New(ripestat.Config{
				BaseURL:         rs.BaseURL,
				Timeout:         rs.Timeout,
				CacheTTL:        rs.CacheTTL,
				RateLimitPerMin: rs.RateLimitPerMin,
			})
			if err != nil {
				return fmt.Errorf("external.ripestat: %w", err)
			}
			external.InitMetrics(client.Name())
			opts = append(opts, events.WithGlobalVisibility(client, rs.CacheTTL))
			s.log.Info("external global-visibility correlation enabled",
				"source", client.Name(),
				"base_url", rs.BaseURL,
				"cache_ttl", rs.CacheTTL,
				"rate_limit_per_min", rs.RateLimitPerMin,
			)
		}

		eng, mgrs, err := events.BuildEngine(s.cfg.Events, s.log, opts...)
		if err != nil {
			return fmt.Errorf("event engine: %w", err)
		}
		s.log.Info("event engine built", "rules", len(s.cfg.Events.Rules),
			"rtr_bulk_threshold", s.cfg.Events.RTRBulkThreshold)
		s.eventEngine = eng
		s.fsManagers = mgrs
	}

	// Flowspec API endpoint — registered here so managers are available.
	fsHandler := api.NewFlowspecHandler(s.fsManagers)
	fsHandler.RegisterRoutes(s.apiSrv.Mux())

	// Warm-start restore, before BMP/RTR sessions open.
	s.restoreSnapshots()

	var wg sync.WaitGroup

	if err := s.bindListeners(ctx, &wg); err != nil {
		return err
	}

	// Route ingestion pipeline
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ingestLoop(ctx)
	}()

	// BMP listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.bmpListen.Start(ctx); err != nil {
			s.log.Error("BMP listener failed", "error", err)
			cancel()
		}
	}()

	// RTR clients or demo mode
	if s.demoMode {
		rtr.LoadTestVRPs(s.vrpStore, s.log)
		close(s.rtrReady)
	} else {
		s.log.Info("starting RTR clients", "count", len(s.cfg.RTR.Caches))
		expireOverride := logExpireInterval(s.log, s.cfg.RTR.ExpireInterval)
		for _, cache := range s.cfg.RTR.Caches {
			wg.Add(1)
			go func() {
				defer wg.Done()
				addr := cache.Address
				client, err := s.newRTRClient(cache, expireOverride)
				if err != nil {
					s.log.Error("failed to build RTR client", "cache", addr, "error", err)
					return
				}
				s.wireRTRClient(client, addr)
				// Signal server when first RTR sync completes
				go func() {
					<-client.Ready()
					select {
					case <-s.rtrReady:
						// already closed
					default:
						close(s.rtrReady)
					}
				}()
				s.rtrMu.Lock()
				s.rtrStates[addr] = 0
				s.rtrMu.Unlock()
				client.Start(ctx)
				// Mark disconnected when Start returns (session ended).
				s.rtrMu.Lock()
				s.rtrStates[addr] = 0
				s.rtrMu.Unlock()
			}()
		}
	}

	// ── Stale eviction — fires once after stale_eviction_timeout ───────────
	if s.cfg.Persistence.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-time.After(s.cfg.Persistence.StaleEvictionTimeout):
				s.RequestStaleEviction()
			case <-ctx.Done():
			}
		}()
	}

	// OTel metrics exporter — non-fatal if collector is unreachable.
	if s.cfg.Outputs.OTel.Enabled {
		otelCfg := otelexporter.OTelConfig{
			Enabled:            true,
			Endpoint:           s.cfg.Outputs.OTel.Endpoint,
			Protocol:           s.cfg.Outputs.OTel.Protocol,
			Interval:           s.cfg.Outputs.OTel.Interval,
			Headers:            s.cfg.Outputs.OTel.Headers,
			Insecure:           s.cfg.Outputs.OTel.Insecure,
			ResourceAttributes: s.cfg.Outputs.OTel.ResourceAttributes,
		}
		otelExp, otelErr := otelexporter.NewExporter(ctx, otelCfg)
		if otelErr != nil {
			s.log.Error("failed to start OTel exporter", "err", otelErr)
		} else if otelExp != nil {
			otelExp.SetReader(s)
			// Bounded: the final export retries with backoff, and against an
			// unreachable collector that alone could stall shutdown for about
			// a minute.
			defer func() {
				sctx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
				defer cancel()
				if err := otelExp.Shutdown(sctx); err != nil {
					s.log.Warn("OTel exporter shutdown", "err", err)
				}
			}()
			s.log.Info("OTel exporter started",
				"endpoint", s.cfg.Outputs.OTel.Endpoint,
				"protocol", s.cfg.Outputs.OTel.Protocol,
				"interval", s.cfg.Outputs.OTel.Interval,
			)
		}
	}

	// Periodically update route table metrics
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.updateRouteMetrics()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Event engine (Phase 3 active response)
	if s.eventEngine != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.eventEngine.Run(ctx, nil)
		}()
	}

	// Flowspec manager reapers — one goroutine per flowspec action config block.
	for _, mgr := range s.fsManagers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.Run(ctx)
		}()
	}

	s.log.Info("RAVEN started",
		"bmp_listen", s.cfg.BMP.Listen,
		"rtr_caches", len(s.cfg.RTR.Caches),
		"rov_enabled", s.cfg.Validation.ROV,
	)

	<-ctx.Done()
	shutdownStart := time.Now()
	s.log.Info("shutting down...")
	wg.Wait()
	s.log.Info("all subsystems stopped", "elapsed", time.Since(shutdownStart).Round(time.Millisecond))

	// ── Snapshot on shutdown (after all sessions drained) ──────────────────
	if s.cfg.Persistence.Enabled {
		writer, wErr := snapshot.NewWriter(s.cfg.Persistence.SnapshotDir, Version)
		if wErr != nil {
			s.log.Error("failed to create snapshot writer", "err", wErr)
		} else {
			snapStart := time.Now()
			routes := s.table.Snapshot()
			// Routes still held for want of an RTR sync are kept too.
			routes = append(routes, s.heldRestored...)
			if err := writer.WriteRoutes(routes); err != nil {
				s.log.Error("failed to write route snapshot", "err", err)
			} else {
				s.log.Info("wrote route snapshot", "routes", len(routes),
					"elapsed", time.Since(snapStart).Round(time.Millisecond))
			}

			vrps := s.vrpStore.Snapshot()
			aspas := s.aspaStore.Snapshot()
			serial := s.vrpStore.Serial()
			if err := writer.WriteRPKI(vrps, aspas, serial); err != nil {
				s.log.Error("failed to write RPKI snapshot", "err", err)
			} else {
				s.log.Info("wrote RPKI snapshot", "vrps", len(vrps), "aspas", len(aspas))
			}
		}
	}

	s.log.Info("RAVEN stopped")
	return nil
}

// GetTable returns the route table.
func (s *Server) GetTable() *routetable.Table {
	return s.table
}

// FlowspecManagers returns the active flowspec lifecycle managers.
func (s *Server) FlowspecManagers() []*flowspec.Manager {
	return s.fsManagers
}

// GetBMPListener returns the BMP listener.
func (s *Server) GetBMPListener() *bmp.Listener {
	return s.bmpListen
}

// ingestLoop applies BMP routes and withdrawals to the Route Table in the
// order they arrived. It waits for the first RTR sync so the VRP store is
// populated before any route is annotated; withdrawals wait too, so they can
// never overtake the routes they withdraw.
func (s *Server) ingestLoop(ctx context.Context) {
	s.log.Info("route ingest pipeline started")
	// Wait for first RTR sync before annotating routes.
	// This ensures VRP store is populated before any ROV happens.
	s.log.Info("waiting for RTR sync before annotating routes...")
	select {
	case <-s.rtrReady:
		s.log.Info("RTR ready — starting route annotation")
		s.releaseRestored()
	case <-ctx.Done():
		return
	}

	var count uint64
	stop := func() { s.log.Info("route ingest pipeline stopped", "total_ingested", count) }
	sinceChunk := 0 // events applied since the last background chunk

	for {
		var ev types.IngestEvent
		if !s.backgroundPending() {
			select {
			case ev = <-s.ingestCh:
			case <-s.revalidateCh:
				s.startRevalidation()
				continue
			case <-s.evictCh:
				s.startStaleEviction()
				continue
			case <-ctx.Done():
				stop()
				return
			}
		} else {
			// Background work in progress: events first; a chunk of it
			// whenever none is waiting (see backgroundEvery).
			select {
			case ev = <-s.ingestCh:
			case <-s.revalidateCh:
				s.startRevalidation()
				continue
			case <-s.evictCh:
				s.startStaleEviction()
				continue
			case <-ctx.Done():
				stop()
				return
			default:
				s.stepBackground()
				sinceChunk = 0
				continue
			}
		}
		// Don't start new work once shutdown has begun: select picks
		// randomly among ready cases.
		if ctx.Err() != nil {
			stop()
			return
		}
		if s.acceptEvent(ev) {
			switch {
			case ev.Route != nil:
				count++
				s.ingestRoute(*ev.Route, ev.Session, count)
			case ev.Withdrawal != nil:
				s.ingestWithdrawal(*ev.Withdrawal, ev.Session)
			}
			if s.testAfterEvent != nil {
				s.testAfterEvent(ev)
			}
		}
		if sinceChunk++; sinceChunk >= backgroundEvery {
			s.stepBackground()
			sinceChunk = 0
		}
	}
}

// wireRTRClient connects an RTR client's callbacks to the server. Every
// completed sync records the cache as synced; only a sync that changed the
// VRP or ASPA data requests a revalidation pass, so a refresh poll that finds
// the cache's serial unchanged costs no pass over the table.
//
// Every session end counts in raven_rtr_disconnects_total with its reason,
// and marks the cache disconnected for StateReader (the OTel
// raven.rtr.session.state gauge) at once: it used to stay connected until
// the client stopped.
func (s *Server) wireRTRClient(client *rtr.Client, addr string) {
	client.SetOnUpdate(func(d *store.Delta) {
		s.requestRTRUpdate(rtrUpdate{cache: addr, serial: client.Serial()}, d)
	})
	for _, reason := range telemetry.DisconnectReasons {
		metrics.RTRDisconnectsTotal.WithLabelValues(addr, string(reason))
	}
	client.SetOnDisconnect(func(reason telemetry.DisconnectReason) {
		s.rtrMu.Lock()
		s.rtrStates[addr] = 0
		s.rtrMu.Unlock()
		metrics.RTRDisconnectsTotal.WithLabelValues(addr, string(reason)).Inc()
	})
	client.SetOnSync(func() {
		// Last-sync time for StateReader/OTel.
		s.rtrMu.Lock()
		s.rtrLastSync[addr] = time.Now().Unix()
		s.rtrStates[addr] = 1
		s.rtrMu.Unlock()
		s.noteASPASource(addr, client.ProtocolVersion() >= 2)
	})
}

// noteASPASource records whether cache addr's last sync was at RTR version 2,
// with ASPA data. ASPA is verified while any cache's was; otherwise every
// route's ASPA is Unknown (validation.ASPAReasonNoData). A change either way
// revalidates the whole table: a first version 2 sync turns ASPA on for
// routes validated without it, a cache falling back to version 1 (whose
// session clears the ASPA data) turns it off. With validation.aspa false
// nothing changes.
func (s *Server) noteASPASource(addr string, v2 bool) {
	if !s.cfg.Validation.ASPA {
		return
	}
	s.rtrMu.Lock()
	s.rtrASPA[addr] = v2
	reason := validation.ASPAReasonNoData
	for _, ok := range s.rtrASPA {
		if ok {
			reason = ""
			break
		}
	}
	s.rtrMu.Unlock()
	if !s.engine.SetASPAUnavailable(reason) {
		return
	}
	if reason == "" {
		s.log.Info("ASPA verification on: an RTR cache synced at protocol version 2", "cache", addr)
	} else {
		s.log.Warn("ASPA verification off: no RTR cache has synced at protocol version 2", "cache", addr)
	}
	s.RequestRevalidation()
}

// RequestRevalidation asks ingestLoop to revalidate every route against the
// current VRP and ASPA stores. Called after each RTR update; safe from any
// goroutine, and never blocks.
//
// Revalidation runs in ingestLoop because that is the Route Table's only
// writer. Run from the RTR goroutine, it re-inserted routes ingest had since
// withdrawn or replaced, giving a newer session's route back to an older
// session or bringing a withdrawn one back, and it changed routes in place
// while API and metrics readers were reading them.
func (s *Server) RequestRevalidation() {
	s.RequestRevalidationDelta(store.FullDelta())
}

// RequestRevalidationDelta asks ingestLoop to revalidate the routes an RTR
// delta can affect (all of them, for a Full delta). Deltas requested before a
// pass takes them are merged. Safe from any goroutine, and never blocks.
func (s *Server) RequestRevalidationDelta(d *store.Delta) {
	s.requestRTRUpdate(rtrUpdate{}, d)
}

// requestRTRUpdate is RequestRevalidationDelta for an RTR update from a
// known cache and serial, which the pass's events report.
func (s *Server) requestRTRUpdate(u rtrUpdate, d *store.Delta) {
	if d == nil {
		d = store.FullDelta()
	}
	if d.Empty() {
		return
	}
	s.deltaMu.Lock()
	if s.pendingDelta == nil {
		s.pendingDelta = &store.Delta{}
	}
	s.pendingDelta.Merge(d)
	s.pendingUpdates = append(s.pendingUpdates, u)
	s.deltaMu.Unlock()
	select {
	case s.revalidateCh <- struct{}{}:
	default: // one is already queued; it will see this update's data too
	}
}

// RequestStaleEviction asks ingestLoop to remove the routes restored from a
// snapshot that no live BMP session has confirmed. Safe from any goroutine,
// and never blocks. Eviction used to run on the timer's goroutine, as a
// second writer of the table.
func (s *Server) RequestStaleEviction() {
	select {
	case s.evictCh <- struct{}{}:
	default:
	}
}

func (s *Server) startStaleEviction() {
	s.queueRemoval(&pendingRemoval{rm: s.table.DetachUnowned(), stale: true})
}

// startRevalidation starts a revalidation pass for the deltas requested so
// far, or, if one is already in progress, schedules one more after it: routes
// the current pass has already checked were checked against the old data. Any
// number of requests during a pass make one follow-up pass, for their merged
// deltas. With no delta pending (its request's pass already took it) there is
// nothing to do.
func (s *Server) startRevalidation() {
	if s.revalidation != nil {
		s.revalidateAgain = true
		return
	}
	s.deltaMu.Lock()
	d, updates := s.pendingDelta, s.pendingUpdates
	s.pendingDelta, s.pendingUpdates = nil, nil
	s.deltaMu.Unlock()
	if d == nil {
		s.revalidating.Store(false)
		return
	}
	s.revalidateStart = time.Now()
	s.startRTRBatch(updates)
	s.revalidation = s.engine.NewDeltaRevalidation(d)
	s.revalidation.OnChange = s.notifyRevalidated
	s.revalidating.Store(true)
}

// notifyRevalidated publishes a route an RTR-driven revalidation pass
// replaced (see publishChange), as ingest does for a BMP route, if its
// posture, ROV state or ASPA state changed. A pass also replaces a route
// whose results changed only in detail (another matching VRP, a new reason);
// that is not a change watchers or rules are shown. Nothing here blocks: a
// watcher whose buffer is full misses the event, and event-engine events
// wait in the pass's batch, so a pass that changes many routes cannot hold
// up ingestLoop.
func (s *Server) notifyRevalidated(old, updated *types.Route) {
	if old.SecurityPosture == updated.SecurityPosture &&
		old.ROV.State == updated.ROV.State && old.ASPA.State == updated.ASPA.State {
		return
	}
	s.publishChange(old, updated, metrics.SourceRTR)
}

func (s *Server) backgroundPending() bool {
	return len(s.removals) > 0 || s.revalidation != nil
}

// stepBackground runs the next chunk of background work. Withdraw-alls go
// first: there is no point revalidating routes about to be removed.
func (s *Server) stepBackground() {
	switch {
	case len(s.removals) > 0:
		s.stepRemovals()
	case s.revalidation != nil:
		s.stepRevalidation()
	default:
		return
	}
	if s.testAfterChunk != nil {
		s.testAfterChunk()
	}
}

func (s *Server) stepRevalidation() {
	rv := s.revalidation
	if !rv.Step(revalidateChunk) {
		return
	}
	took := time.Since(s.revalidateStart)
	mode := metrics.RevalidationModeIncremental
	if rv.Full {
		mode = metrics.RevalidationModeFull
	}
	attrs := []any{"mode", mode, "candidates", rv.Candidates, "checked", rv.Checked,
		"changed", rv.Changed, "skipped_superseded", rv.Skipped, "took", took}
	if rv.ASPAScanned > 0 {
		attrs = append(attrs, "aspa_scanned", rv.ASPAScanned, "aspa_scan_took", rv.ASPAScanTime)
	}
	s.log.Info("re-validation complete", attrs...)
	metrics.RevalidationDuration.WithLabelValues(mode).Observe(took.Seconds())
	metrics.RevalidationRoutesTotal.WithLabelValues(mode, metrics.RevalidationResultChecked).Add(float64(rv.Checked))
	metrics.RevalidationRoutesTotal.WithLabelValues(mode, metrics.RevalidationResultChanged).Add(float64(rv.Changed))
	s.flushRTRBatch()
	s.revalidation = nil
	s.revalidationPasses.Add(1)
	if s.revalidateAgain {
		s.revalidateAgain = false
		s.startRevalidation()
		return
	}
	s.revalidating.Store(false)
}

// acceptEvent tracks superseded BMP sessions and reports whether ev should be
// applied. The listener stops a superseded session from sending, but an
// event it had already handed over may still arrive behind the newer
// session's announcements; applied, it would take a route back from the
// newer session, and the superseded session's session end would then remove
// it. Dropping it loses nothing: the session end removes every route the
// superseded session still owns.
func (s *Server) acceptEvent(ev types.IngestEvent) bool {
	if ev.Superseded {
		s.retired[ev.Session] = 0
		return false
	}
	dropped, ok := s.retired[ev.Session]
	if !ok {
		return ev.Route != nil || ev.Withdrawal != nil
	}
	if ev.Withdrawal != nil && ev.Withdrawal.SessionEnd {
		delete(s.retired, ev.Session)
		if dropped > 0 {
			s.log.Info("dropped late events from superseded BMP session",
				"session", ev.Session, "events", dropped)
		}
		return true
	}
	s.retired[ev.Session] = dropped + 1
	return false
}

// stepRemovals removes the next chunk of the oldest withdraw-all in
// progress, if any.
func (s *Server) stepRemovals() {
	if len(s.removals) == 0 {
		return
	}
	p := s.removals[0]
	n, done := p.rm.Step(removalChunk)
	p.removed += n
	if done {
		s.removals[0] = nil
		s.removals = s.removals[1:]
		s.removalsPending.Store(int64(len(s.removals)))
		switch {
		case p.stale:
			s.log.Info("evicted unconfirmed stale routes", "count", p.removed, "took", time.Since(p.started))
		case p.peer.Addr.IsValid():
			s.log.Info("withdrew all routes from BMP peer", "peer", p.peer.Addr.String(),
				"router", p.peer.Router.String(), "peer_distinguisher", p.peer.Distinguisher,
				"loc_rib", p.locRIB, "session", p.session, "routes", p.removed, "took", time.Since(p.started))
		default:
			s.log.Info("withdrew all routes of ended BMP session",
				"session", p.session, "routes", p.removed, "took", time.Since(p.started))
		}
	}
}

// ingestRoute validates one BMP route from BMP session session and inserts
// it into the Route Table. The latest announcement wins: it replaces any
// existing route for the key, and the session takes ownership of it.
// count is the running number of routes ingested, for progress logging.
func (s *Server) ingestRoute(r types.Route, session, count uint64) {
	r.OwnerSession = session

	// The route as the table holds it, to tell what the announcement
	// changes. A Stale one (a snapshot artefact) counts as not there: the
	// live announcement is a new route.
	old := s.table.Get(r.Key())
	if old != nil && old.Stale {
		old = nil
	}

	// Run ROV validation before inserting
	if s.cfg.Validation.ROV {
		s.engine.ValidateRoute(&r)
	}

	s.table.Insert(&r)

	// Watch, metrics and the event engine see the change, if it is one: a
	// re-announcement that changes nothing is not.
	if old == nil || !sameRoute(old, &r) {
		s.publishChange(old, &r, metrics.SourceBMP)
	}

	// Log first few routes so the user sees it working
	if count <= 20 {
		s.log.Info("route received",
			"prefix", r.Prefix.String(),
			"peer", r.PeerAddr.String(),
			"origin_asn", r.OriginASN(),
			"rov", r.ROV.State.String(),
			"posture", r.SecurityPosture,
		)
	}
	if count%10000 == 0 {
		s.log.Info("routes ingested", "count", count, "table_size", s.table.Count())
	}
}

// ingestWithdrawal applies a withdrawal from BMP session session: one
// withdrawn route, every route of a peer that went down, or every route of a
// session that ended. Withdraw-alls only remove routes the session owns, so a
// stale session closing cannot remove what a newer session re-announced.
func (s *Server) ingestWithdrawal(w types.Withdrawal, session uint64) {
	// A withdraw-all is detached from the owner index here, in stream
	// order, so routes announced after it are not taken with it; its
	// routes are then removed a chunk at a time by stepRemovals.
	switch {
	case w.SessionEnd:
		s.queueRemoval(&pendingRemoval{rm: s.table.DetachSession(session), session: session})
		return
	case w.WithdrawAll:
		s.queueRemoval(&pendingRemoval{rm: s.table.DetachPeer(w.Peer(), session, w.RIBType), session: session,
			peer: w.Peer(), locRIB: w.RIBType == types.LocRIB})
		return
	}
	// Capture route before removal so the event carries prefix/posture context.
	key := w.Key()
	var withdrawn *types.Route
	if s.eventEngine != nil {
		withdrawn = s.table.Get(key)
	}
	if !s.table.WithdrawFromSession(key, session) {
		return // nothing to withdraw, or a newer session owns the route
	}
	if s.eventEngine != nil && withdrawn != nil && withdrawn.OwnerSession <= session && !key.RIBType.IsAdjRIBOut() {
		s.emitEvent(events.Event{
			ID:         events.NewID(),
			Timestamp:  time.Now(),
			Type:       events.EventTypeRouteWithdraw,
			Route:      withdrawn,
			OldPosture: withdrawn.SecurityPosture,
			RouterID:   w.Router.String(), // the monitored router; it was the peer's address
			Source:     events.SourceBMP,
		})
	}
}

func (s *Server) queueRemoval(p *pendingRemoval) {
	p.started = time.Now()
	s.removals = append(s.removals, p)
	s.removalsPending.Store(int64(len(s.removals)))
}

// metricRIBs are the RIBs raven_routes_total counts, each with its own rib
// label (metrics.RouteRIBs): the inbound RIBs and the Loc-RIB.
var metricRIBs = []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost, types.LocRIB}

// routeCountKey is a route count's RIB, posture and address family.
type routeCountKey struct {
	rib     types.RIBType
	posture string
	afi     string
}

// routeCounts counts the table's routes by RIB, posture and address family,
// in one pass that copies no route. A route without a posture counts as
// unverified.
func (s *Server) routeCounts() map[routeCountKey]int64 {
	counts := make(map[routeCountKey]int64)
	sc := s.table.NewScan()
	for batch := sc.Next(4096); len(batch) > 0; batch = sc.Next(4096) {
		for _, r := range batch {
			posture := string(r.SecurityPosture)
			if posture == "" {
				posture = string(types.PostureUnverified)
			}
			afi := "ipv4"
			if r.Prefix.Addr().Is6() {
				afi = "ipv6"
			}
			counts[routeCountKey{r.RIBType, posture, afi}]++
		}
	}
	return counts
}

// updateRouteMetrics refreshes Prometheus gauges for route counts.
//
// Every known label set is set, to 0 when it has no route: Reset() would
// remove the series, and Grafana lastNotNull panels would keep showing
// their last value.
func (s *Server) updateRouteMetrics() {
	counts := s.routeCounts()
	var size types.RIBCounts
	for _, posture := range metrics.Postures {
		for _, afi := range metrics.AFIs {
			for _, rib := range metricRIBs {
				n := counts[routeCountKey{rib, posture, afi}]
				metrics.RoutesTotal.WithLabelValues(posture, afi, rib.String()).Set(float64(n))
				size[rib] += uint64(n)
			}
			metrics.AdjRIBOutRoutesTotal.WithLabelValues(posture, afi).Set(
				float64(counts[routeCountKey{types.AdjRIBOutPre, posture, afi}]))
		}
	}
	for _, rib := range metricRIBs {
		metrics.RouteTableSize.WithLabelValues(rib.String()).Set(float64(size[rib]))
	}
}

// restoreSnapshots warm-starts the route table and the RPKI stores from the
// persistence snapshots, if persistence is enabled. Any snapshot it cannot
// use (unreadable, another RAVEN version, an older route format) is skipped
// with a warning: that part starts cold.
func (s *Server) restoreSnapshots() {
	if !s.cfg.Persistence.Enabled {
		return
	}
	reader := snapshot.NewReader(s.cfg.Persistence.SnapshotDir, Version)

	// RPKI first: the restored routes' ROV reasons are computed from it.
	vrpsRestored := false
	if vrps, aspas, serial, err := reader.ReadRPKI(); err != nil {
		if !errors.Is(err, snapshot.ErrVersionMismatch) {
			s.log.Warn("failed to read RPKI snapshot", "err", err)
		} else {
			s.log.Warn("RPKI snapshot version mismatch, starting cold")
		}
	} else if vrps != nil {
		s.vrpStore.Restore(vrps)
		s.aspaStore.Restore(aspas)
		vrpsRestored = len(vrps) > 0
		s.log.Info("restored RPKI snapshot",
			"vrps", len(vrps), "aspas", len(aspas), "serial", serial)
	}

	if routes, err := reader.ReadRoutes(); err != nil {
		if errors.Is(err, snapshot.ErrFormatMismatch) {
			// Not migrated: an old-format route key cannot say which
			// router or instance a route was from.
			s.log.Warn("route snapshot is in an older format, starting the route table cold", "err", err)
		} else if !errors.Is(err, snapshot.ErrVersionMismatch) {
			s.log.Warn("failed to read route snapshot", "err", err)
		} else {
			s.log.Warn("route snapshot version mismatch, starting cold")
		}
	} else if routes != nil {
		if !vrpsRestored {
			// No VRPs to compute the routes' ROV reasons from: hold them
			// until the first RTR sync (releaseRestored), so no query
			// sees a restored route without its reason.
			s.heldRestored = routes
			s.log.Info("restored route snapshot without VRPs; routes held until the first RTR sync",
				"routes", len(routes))
			return
		}
		s.insertRestored(routes)
		s.log.Info("restored route snapshot", "routes", len(routes))
	}
}

// insertRestored puts routes restored from a snapshot in the table, each
// with its ROV reason computed from the VRP store (#61): a snapshot keeps
// only the ROV state.
func (s *Server) insertRestored(routes []*types.Route) {
	mismatched := 0
	for _, r := range routes {
		if !s.engine.RestoreROVReason(r) {
			mismatched++
		}
	}
	if mismatched > 0 {
		s.log.Info("restored routes whose ROV state the current VRPs no longer give; the next revalidation updates them",
			"routes", mismatched)
	}
	s.table.Restore(routes)
}

// releaseRestored inserts the routes restoreSnapshots held for want of VRPs.
// ingestLoop calls it once the first RTR sync has filled the VRP store,
// before it applies any BMP event or revalidation.
func (s *Server) releaseRestored() {
	if s.heldRestored == nil {
		return
	}
	routes := s.heldRestored
	s.insertRestored(routes)
	s.heldRestored = nil
	s.log.Info("restored route snapshot", "routes", len(routes))
}

// bindListeners binds the BMP, API, metrics and pprof listeners, starts
// serving all but BMP (Run's BMP goroutine accepts on the bound listener),
// and logs one line with every bound address.
func (s *Server) bindListeners(ctx context.Context, wg *sync.WaitGroup) error {
	// Bind every listener before serving any, so one line can say where
	// each one is. A BMP bind failure is fatal; the others are logged and
	// the daemon runs without them, as before.
	bmpAddr, err := s.bmpListen.Listen()
	if err != nil {
		return err
	}
	s.bmpAddr = bmpAddr
	defer close(s.listening)
	listeners := []any{"bmp", bmpAddr.String()}
	if ln, err := net.Listen("tcp", APIListen(s.cfg)); err != nil {
		s.log.Error("API server failed", "addr", APIListen(s.cfg), "error", err)
	} else {
		s.apiAddr = ln.Addr()
		listeners = append(listeners, "api", ln.Addr().String())
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.apiSrv.Serve(ctx, ln); err != nil {
				s.log.Error("API server failed", "error", err)
			}
		}()
	}
	if p := s.cfg.Outputs.Prometheus; p != nil {
		if ln, err := net.Listen("tcp", p.Listen); err != nil {
			s.log.Error("Prometheus server error", "addr", p.Listen, "error", err)
		} else {
			listeners = append(listeners, "metrics", ln.Addr().String())
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.runPrometheus(ctx, ln)
			}()
		}
	}
	// pprof profiling endpoint — opt-in via debug.pprof.listen, off by default.
	if a := s.startPprof(ctx, wg); a != nil {
		listeners = append(listeners, "pprof", a.String())
	}
	s.log.Info("listeners bound", listeners...)
	return nil
}

// runPrometheus serves the Prometheus metrics endpoint on ln.
func (s *Server) runPrometheus(ctx context.Context, ln net.Listener) {
	path := s.cfg.Outputs.Prometheus.Path

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	s.log.Info("Prometheus metrics endpoint started", "addr", ln.Addr().String(), "path", path)
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		s.log.Error("Prometheus server error", "error", err)
	}
}

// logExpireInterval logs, once at startup, the RTR Expire Interval in
// effect, and returns the override for each client: rtr.expire-interval
// clamped to RFC 8210's range (a WARN if it had to be), or 0 when unset, in
// which case each cache's End of Data interval applies.
func logExpireInterval(log *slog.Logger, configured int) uint32 {
	eff, clamped := rtr.ExpireOverride(configured)
	switch {
	case eff == 0:
		log.Info("RTR expire interval: each cache's own (End of Data)", "expire_interval", "cache")
	case clamped:
		log.Warn("rtr.expire-interval outside RFC 8210's 600-172800 s; clamped",
			"configured", configured, "expire_interval", eff)
	default:
		log.Info("RTR expire interval: rtr.expire-interval overrides each cache's",
			"expire_interval", eff)
	}
	return eff
}

// newRTRClient builds the RTR client for a configured cache: transport, the
// configured protocol version, the version re-probe interval, and
// expireOverride (from logExpireInterval; 0 keeps the cache's Expire
// Interval).
func (s *Server) newRTRClient(cache config.RTRCacheConfig, expireOverride uint32) (*rtr.Client, error) {
	transport := cache.Transport
	if transport == "" {
		transport = "tcp"
	}
	var configVersion uint8
	switch s.cfg.RTR.RTRVersion {
	case "0":
		configVersion = 0
	case "1":
		configVersion = 1
	default: // "2", "auto", ""
		configVersion = 2
	}
	client, err := rtr.NewClient(cache.Address, transport, cache.TLS, s.vrpStore, s.aspaStore, configVersion, s.log)
	if err != nil {
		return nil, err
	}
	client.SetVersionReprobeInterval(s.cfg.RTR.VersionReprobeInterval)
	client.SetExpireOverride(expireOverride)
	return client, nil
}
