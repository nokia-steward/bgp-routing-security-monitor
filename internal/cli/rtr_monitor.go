package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/server"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// rtrMonitorProtoVersion is the RTR protocol version the monitor starts with
// when --rtr-version is auto (the default). v2 exercises ASPA PDUs (which
// telemetry records); the client falls back to v1, then v0, if the cache
// rejects it.
const rtrMonitorProtoVersion uint8 = 2

// parseMonitorRTRVersion reads --rtr-version: "auto" (or empty) negotiates
// from version 2 down; 0, 1 or 2 pins the session to that version.
func parseMonitorRTRVersion(s string) (version uint8, pinned bool, err error) {
	switch s {
	case "", "auto":
		return rtrMonitorProtoVersion, false, nil
	case "0", "1", "2":
		return s[0] - '0', true, nil
	default:
		return 0, false, fmt.Errorf("invalid --rtr-version %q: must be auto, 0, 1 or 2", s)
	}
}

// newMonitorClient builds the monitor's RTR client for cache, at the version
// --rtr-version (rtrVersion) asks for, recording telemetry to rec.
func newMonitorClient(cache, transport, rtrVersion string, rec *telemetry.Recorder, log *slog.Logger) (*rtr.Client, error) {
	// Minimal in-memory stores: NewClient requires them. This command
	// performs no validation; with several caches the comparison reads
	// them.
	return newMonitorClientStores(cache, transport, rtrVersion, store.NewVRPStore(), store.NewASPAStore(), rec, log)
}

// newMonitorClientStores is newMonitorClient filling the given stores.
func newMonitorClientStores(cache, transport, rtrVersion string, vrps *store.VRPStore, aspas *store.ASPAStore,
	rec *telemetry.Recorder, log *slog.Logger) (*rtr.Client, error) {
	version, pinned, err := parseMonitorRTRVersion(rtrVersion)
	if err != nil {
		return nil, err
	}
	// tlsCfg is nil: NewClient only consults it when transport == "tls",
	// and a nil config falls back to the system root CA pool.
	client, err := rtr.NewClient(cache, transport, nil, vrps, aspas, version, log)
	if err != nil {
		return nil, fmt.Errorf("create RTR client: %w", err)
	}
	client.SetVersionPinned(pinned)
	client.SetTelemetry(rec)
	return client, nil
}

// consumeRTREvents feeds every telemetry event from rec to the detector until
// rec is closed: each anomaly is written as an NDJSON record on the same
// sink and counted in Prometheus, and observed is called for each sync the
// baseline took in. cmp, the comparison of several caches (nil with one),
// is told of every sync and the anomaly it raised.
func consumeRTREvents(rec *telemetry.Recorder, detector *telemetry.Detector, cmp *telemetry.CrossCache, observed func(), log *slog.Logger) {
	for ev := range rec.Events() {
		if handleRTREvent(rec, detector, cmp, ev, log) && observed != nil {
			observed()
		}
	}
}

// handleRTREvent is consumeRTREvents for one event: the detector's anomaly,
// the comparison, and the data tracker's stale, stale_resolved and
// data_regressed records with their structural anomalies. It reports
// whether the event was a sync the detector's baseline took in.
func handleRTREvent(rec *telemetry.Recorder, detector *telemetry.Detector, cmp *telemetry.CrossCache,
	ev telemetry.SessionEvent, log *slog.Logger) bool {
	anomaly, ok := observeRTREvent(detector, ev, log)
	if anomaly != nil {
		recordAnomaly(rec, anomaly)
	}
	if ev.EventType == telemetry.EventConnected || ev.EventType == telemetry.EventDisconnected {
		detector.Data().Observe(ev) // the cache's connection state
	}
	if ev.EventType != telemetry.EventSync {
		return ok
	}
	if cmp != nil {
		cmp.ObserveSync(ev, anomaly)
	}
	recordDataEvents(rec, detector.Data(), detector.Data().Observe(ev), ev.Timestamp, log)
	return ok
}

// dataTickEvery is how often rtr monitor evaluates each cache's data age
// between syncs (DataTracker.Tick), as raven serve does.
const dataTickEvery = 15 * time.Second

// tickData evaluates every cache's data age at now: a cache goes stale when
// its data outlasts its threshold, not at its next sync, and one that stops
// syncing goes stale too.
func tickData(rec *telemetry.Recorder, t *telemetry.DataTracker, now time.Time, log *slog.Logger) {
	recordDataEvents(rec, t, t.Tick(now), now, log)
}

// runDataTicks calls tickData every dataTickEvery until ctx is done.
func runDataTicks(ctx context.Context, rec *telemetry.Recorder, t *telemetry.DataTracker, log *slog.Logger) {
	tick := time.NewTicker(dataTickEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			tickData(rec, t, now, log)
		}
	}
}

// recordDataEvents writes the data tracker's records with their structural
// anomalies, logs and counts them, and sets every cache's data gauges as of
// now.
func recordDataEvents(rec *telemetry.Recorder, t *telemetry.DataTracker, des []telemetry.DataEvent, now time.Time, log *slog.Logger) {
	for _, de := range des {
		rec.RecordData(de)
		logDataEvent(log, de)
		if de.Kind == telemetry.DataRegressed {
			metrics.RTRDataRegressions.WithLabelValues(de.Cache).Inc()
		}
		if a := de.Anomaly(); a != nil {
			recordAnomaly(rec, a)
		}
	}
	for _, cache := range t.Caches() {
		if st, ok := t.Status(cache, now); ok {
			metrics.SetRTRData(cache, st.Age, st.CacheState)
		}
	}
}

// recordAnomaly writes an anomaly record and counts it in Prometheus.
func recordAnomaly(rec *telemetry.Recorder, a *telemetry.AnomalyEvent) {
	rec.RecordAnomaly(a)
	metrics.RTRAnomalyTotal.WithLabelValues(a.Cache, a.Severity).Inc()
	metrics.RTRAnomalyLastTimestamp.WithLabelValues(a.Cache).Set(float64(a.Timestamp.Unix()))
}

// logDataEvent logs a stale episode starting or ending, or a return to
// earlier data.
func logDataEvent(log *slog.Logger, de telemetry.DataEvent) {
	switch de.Kind {
	case telemetry.DataStale:
		log.Warn("RTR cache data stale: syncing, but its data has not changed for longer than its threshold",
			"cache", de.Cache, "serial", de.Serial, "last_change", de.LastChange, "gap", de.Gap,
			"threshold", de.ExpectedGap, "threshold_source", de.ThresholdSource, "syncs_without_change", de.SyncsWithoutChange,
			"scope", de.Scope, "cache_state", de.CacheState)
	case telemetry.DataStaleResolved:
		log.Info("RTR cache data changing again", "cache", de.Cache, "resolution", de.Resolution, "stale_for", de.Duration, "unchanged_for", de.Gap,
			"serial_before", de.SerialBefore, "serial_after", de.SerialAfter)
	case telemetry.DataRegressed:
		log.Warn("RTR cache returned to earlier data", "cache", de.Cache, "last_current", de.LastCurrent, "ago", de.Ago,
			"first_current", de.FirstCurrent, "serial_before", de.SerialBefore, "serial_after", de.SerialAfter,
			"sync_type", de.SyncType)
	}
}

// monitorSet is rtr monitor's RTR clients, one per --cache, each with its
// own stores, and with several caches their comparison.
type monitorSet struct {
	clients []*rtr.Client
	cmp     *telemetry.CrossCache // nil with one cache
}

// newMonitorSet builds a client for each of caches, recording telemetry to
// rec. With more than one cache it wires each client's stores and callbacks
// to a comparison writing to rec; settle, if above 0, overrides its settle
// window.
func newMonitorSet(caches []string, transport, rtrVersion string, settle time.Duration, rec *telemetry.Recorder,
	log *slog.Logger) (*monitorSet, error) {
	if len(caches) == 0 {
		return nil, fmt.Errorf("no --cache given")
	}
	ms := &monitorSet{}
	if len(caches) > 1 {
		ms.cmp = telemetry.NewCrossCache(rec, settle, func(cache, kind string, n int) {
			metrics.RTRDivergentItems.WithLabelValues(cache, kind).Set(float64(n))
		}, log)
		ms.cmp.OnCompared(func(cache string, compared bool) {
			v := 0.0
			if compared {
				v = 1
			}
			metrics.RTRCompared.WithLabelValues(cache).Set(v)
		})
	}
	for _, cache := range caches {
		vrps, aspas := store.NewVRPStore(), store.NewASPAStore()
		client, err := newMonitorClientStores(cache, transport, rtrVersion, vrps, aspas, rec, log)
		if err != nil {
			return nil, err
		}
		if ms.cmp != nil {
			member, err := ms.cmp.Add(cache, vrps, aspas)
			if err != nil {
				return nil, fmt.Errorf("--cache: %w", err)
			}
			client.SetOnUpdate(func(d *store.Delta) { member.Update(d, client.Serial()) })
			client.SetOnSync(func() { member.Synced(client.ProtocolVersion()) })
			client.SetOnDisconnect(func(telemetry.DisconnectReason) { member.Disconnected() })
			for _, kind := range telemetry.DivergenceKinds {
				metrics.RTRDivergentItems.WithLabelValues(cache, kind).Set(0)
			}
			metrics.RTRCompared.WithLabelValues(cache).Set(0)
		}
		ms.clients = append(ms.clients, client)
	}
	return ms, nil
}

// start runs every client until ctx is cancelled. The returned channel is
// closed once all of them have returned.
func (ms *monitorSet) start(ctx context.Context) <-chan struct{} {
	var wg sync.WaitGroup
	for _, c := range ms.clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Start(ctx)
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}

// rtrMonitorShutdownGrace bounds how long we wait for the RTR client goroutine
// to unwind after a signal before closing the recorder. It is deliberately
// longer than the client's rtrReadTimeout (65s): a parked read unblocks within
// that window and returns cleanly on a cancelled context, so the goroutine
// always exits before this grace fires. The bound only guards against an
// unforeseen hang. See the shutdown note in RunE.
const rtrMonitorShutdownGrace = 70 * time.Second

// rtrMonitorSaveEvery is how many sync events elapse between periodic saves of
// the anomaly baseline snapshot. At the baseline's ~15 min/sync this is roughly
// every 5 hours, bounding worst-case data loss on an ungraceful crash to a
// handful of samples against a 500-sample window.
const rtrMonitorSaveEvery = 20

// newRTRMonitorCmd builds "raven rtr monitor": a standalone RTR session
// observer that streams telemetry events to an NDJSON file. It needs no
// config file — every setting comes from flags.
func newRTRMonitorCmd() *cobra.Command {
	var (
		caches          []string
		compareSettle   time.Duration
		logFile         string
		transport       string
		prometheus      string
		anomalySnapshot string
		rtrVersion      string
		staleThreshold  time.Duration
	)

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Observe RTR cache sessions and log telemetry to NDJSON",
		Long: `monitor connects to one or more RPKI-to-Router (RTR) caches (--cache, repeated),
records session lifecycle and sync events as NDJSON, and (optionally) exposes
Prometheus metrics. It keeps an in-memory VRP/ASPA set per cache; no
validation or BMP ingestion happens here.

It reports a cache whose data (not serial) stops changing for longer than its
learned threshold (stale, once per episode, and stale_resolved), and one that
returns to data it served earlier (data_regressed).

With several caches it also compares their data after every sync, and reports
a cache that persistently disagrees with the others (divergence) and a large
change that reached every cache at once (upstream_change).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := initLogger()

			if transport != "tcp" && transport != "tls" {
				return fmt.Errorf("invalid --transport %q: must be \"tcp\" or \"tls\"", transport)
			}
			if _, _, err := parseMonitorRTRVersion(rtrVersion); err != nil {
				return err
			}
			if staleThreshold < 0 {
				return fmt.Errorf("invalid --stale-threshold %s: must not be negative", staleThreshold)
			}
			if compareSettle < 0 {
				return fmt.Errorf("invalid --compare-settle %s: must not be negative", compareSettle)
			}

			// Open the NDJSON sink for append, creating it if absent.
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				return fmt.Errorf("open log file %q: %w", logFile, err)
			}

			rec := telemetry.NewRecorder(f, 64, log)

			// Anomaly detector: warm-started from a persisted baseline when one
			// exists. A missing or unreadable baseline degrades to a cold start;
			// it must never block monitor startup.
			snapshotPath := expandHome(anomalySnapshot)
			detector := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
			if err := telemetry.EnsureAnomalySnapshotDir(snapshotPath); err != nil {
				log.Warn("could not create anomaly snapshot directory", "path", snapshotPath, "error", err)
			}
			switch err := detector.Load(snapshotPath); {
			case err == nil:
				log.Info("loaded anomaly baseline", "path", snapshotPath)
			case os.IsNotExist(err):
				log.Info(fmt.Sprintf("no anomaly baseline found at %s, starting cold", snapshotPath))
			default:
				log.Warn("could not load anomaly baseline, starting cold", "path", snapshotPath, "error", err)
			}

			set, err := newMonitorSet(caches, transport, rtrVersion, compareSettle, rec, log)
			if err != nil {
				f.Close()
				return err
			}
			for _, cache := range caches {
				initAnomalyMetrics(cache)
			}
			configureDataTracker(detector.Data(), staleThreshold, set.cmp)
			seedDataGaps(detector.Data(), logFile, caches, log)

			// Consume the telemetry event channel: feed sync/structural events to
			// the detector, emit any resulting anomaly as an NDJSON record on the
			// same sink, and update Prometheus counters. A local counter drives
			// periodic baseline saves. This goroutine exits when rec.Close()
			// closes the channel at shutdown; consumerDone signals that exit so
			// the final save does not race an in-flight ObserveSync.
			consumerDone := make(chan struct{})
			go func() {
				defer close(consumerDone)
				syncsSinceSave := 0
				consumeRTREvents(rec, detector, set.cmp, func() {
					syncsSinceSave++
					if syncsSinceSave >= rtrMonitorSaveEvery {
						syncsSinceSave = 0
						if err := detector.Save(snapshotPath); err != nil {
							log.Warn("periodic anomaly baseline save failed", "path", snapshotPath, "error", err)
						}
					}
				}, log)
			}()

			// SIGHUP too: a closed terminal or tmux session must not
			// skip the shutdown records and the final snapshot (#82).
			ctx, stop := signal.NotifyContext(context.Background(), server.ShutdownSignals...)
			defer stop()

			if prometheus != "" {
				startRTRMonitorMetrics(ctx, prometheus, log)
			}

			done := set.start(ctx)

			// Data age between syncs. Stopped, like the clients, before the
			// recorder closes and the log file with it.
			ticksDone := make(chan struct{})
			go func() {
				defer close(ticksDone)
				runDataTicks(ctx, rec, detector.Data(), log)
			}()

			if len(caches) == 1 {
				log.Info("RTR monitor started", "cache", caches[0], "transport", transport, "rtr_version", rtrVersion, "log_file", logFile)
			} else {
				log.Info("RTR monitor started", "caches", caches, "transport", transport, "rtr_version", rtrVersion,
					"log_file", logFile, "compare_settle", compareSettle)
			}

			<-ctx.Done()
			log.Info("shutting down RTR monitor")

			// Wait for the client goroutine to stop before closing the recorder:
			// Recorder.Record must not run after Close. The wait is bounded
			// because the client's read loop can park in a blocking socket read
			// (no read deadline) that ctx cancellation cannot interrupt until
			// the cache sends more bytes. On the rare timeout path the process
			// exits immediately anyway.
			select {
			case <-done:
			case <-time.After(rtrMonitorShutdownGrace):
				log.Warn("RTR client did not stop within grace period", "grace", rtrMonitorShutdownGrace)
			}

			<-ticksDone
			rec.Close()

			// The consumer goroutine drains any buffered events and exits once
			// the channel is closed. Wait for it before the final save so the
			// snapshot reflects every observed sync and no ObserveSync is in
			// flight concurrently.
			<-consumerDone
			if err := detector.Save(snapshotPath); err != nil {
				log.Warn("final anomaly baseline save failed", "path", snapshotPath, "error", err)
			}

			if err := f.Close(); err != nil {
				return fmt.Errorf("close log file: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&caches, "cache", []string{"localhost:3323"},
		"RTR cache address; repeat to monitor and compare several caches in one process")
	cmd.Flags().DurationVar(&compareSettle, "compare-settle", 0,
		"with several caches: how long a difference between them must last to be reported (0: twice the slowest cache's median refresh interval, at least 10m; 30m until intervals are known)")
	cmd.Flags().StringVar(&logFile, "log-file", "rtr-telemetry.ndjson", "path to NDJSON telemetry output file")
	cmd.Flags().StringVar(&transport, "transport", "tcp", "RTR transport: tcp or tls")
	cmd.Flags().StringVar(&prometheus, "prometheus", "", "Prometheus listen address (e.g. :9595); empty disables metrics")
	cmd.Flags().StringVar(&rtrVersion, "rtr-version", "auto",
		"RTR protocol version: auto negotiates from 2 down to what the cache supports; 0, 1 or 2 pins the session to that version, with no fallback")
	cmd.Flags().DurationVar(&staleThreshold, "stale-threshold", 0,
		"how long a cache's data may go without changing before it is reported stale (0: learned per cache, max(4 x median gap, 3 x p90 gap, 30m) between data changes; 4h until 20 gaps are known, at most 4h until 100)")
	cmd.Flags().StringVar(&anomalySnapshot, "anomaly-snapshot", "~/.raven/anomaly-baseline.json", "path to the adaptive anomaly-detector baseline snapshot (JSON)")

	return cmd
}

// expandHome expands a leading "~/" in path using the current user's home
// directory, mirroring the helper in internal/snapshot so path flags behave
// consistently across the project. On any lookup error the path is returned
// unchanged.
// initAnomalyMetrics exports raven_rtr_anomaly_total for cache at 0 for every
// severity, so a scrape shows 0 before the first anomaly rather than nothing.
func initAnomalyMetrics(cache string) {
	for _, sev := range telemetry.AnomalySeverities {
		metrics.RTRAnomalyTotal.WithLabelValues(cache, sev)
	}
	metrics.RTRDataRegressions.WithLabelValues(cache)
}

// configureDataTracker applies --stale-threshold (0 learns) and, with several
// caches compared, reports the scope of stale data against them.
func configureDataTracker(t *telemetry.DataTracker, threshold time.Duration, cmp *telemetry.CrossCache) {
	t.SetThreshold(threshold)
	if cmp != nil {
		t.SetGroup(cmp.Compared)
	}
}

// seedDataGaps fills in, before the first live sync, the gap history of
// each cache the anomaly snapshot had none for (one from before data_gaps,
// or no snapshot) from the sync records already in logFile (#80), and logs
// how many gaps it seeded per cache. Without it such a cache learns from
// scratch, and its first gaps can be mostly stalls. A missing or unreadable
// log seeds nothing; it never blocks startup.
func seedDataGaps(t *telemetry.DataTracker, logFile string, caches []string, log *slog.Logger) {
	f, err := os.Open(logFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("could not read the log file for gaps between data changes", "log_file", logFile, "error", err)
		}
		return
	}
	defer f.Close()
	seeded, skipped, err := t.SeedGaps(f, caches)
	if err != nil {
		log.Warn("could not seed gaps between data changes from the log file", "log_file", logFile, "error", err)
		return
	}
	if skipped > 0 {
		log.Warn("skipped unreadable lines of the log file while seeding gaps between data changes",
			"log_file", logFile, "lines", skipped)
	}
	for _, cache := range caches {
		n, ok := seeded[cache]
		if !ok {
			continue
		}
		thr, src, _ := t.Threshold(cache)
		log.Info("seeded gaps between data changes from the log file", "cache", cache, "gaps", n,
			"threshold", thr, "threshold_source", src, "log_file", logFile)
	}
}

// observeRTREvent feeds one telemetry event to the detector and returns the
// anomaly it raises, if any, and whether it was a sync the detector's
// baseline took in.
func observeRTREvent(d *telemetry.Detector, ev telemetry.SessionEvent, log *slog.Logger) (*telemetry.AnomalyEvent, bool) {
	switch ev.EventType {
	case telemetry.EventSync:
		// Full syncs (Reset Query table dumps) report near the entire
		// VRP/ASPA table as "announced", which is not comparable to the
		// incremental deltas the baseline is built from. Feeding them to the
		// detector would both trip a false positive (the first sync after
		// connect is always full) and poison the rolling windows. Skip
		// statistical evaluation entirely and leave the windows untouched;
		// the sync is still recorded to NDJSON by the recorder for operator
		// visibility.
		if ev.SyncType == telemetry.SyncTypeFull {
			log.Info("full RTR resync, not evaluated by anomaly detector",
				"cache", ev.Cache, "vrp_total", ev.VRPTotal, "aspa_total", ev.ASPATotal)
			return nil, false
		}
		return d.ObserveSyncTotals(ev.Cache, ev.Timestamp, telemetry.SyncMetrics(ev), telemetry.TotalsOf(ev)), true
	case telemetry.EventReset:
		return d.ObserveStructural(ev.Cache, "cache_reset", ev.Timestamp), false
	case telemetry.EventCacheNotReady:
		// Error Report code 2: the cache is still building its data (e.g.
		// Routinator at startup). Recorded to NDJSON by the recorder; not an
		// anomaly, and the baseline is untouched.
		code := uint16(0)
		if ev.ErrorCode != nil {
			code = *ev.ErrorCode
		}
		log.Info("RTR cache not ready yet, not an anomaly",
			"cache", ev.Cache, "error_code", code, "error_text", ev.ErrorText)
		return nil, false
	case telemetry.EventVersionDowngrade:
		// A step of version negotiation (Error Report code 4, or a dropped
		// connection, before the session answered anything): expected
		// against a cache that speaks an older version. Not an anomaly.
		next := -1
		if ev.NextProtoVersion != nil {
			next = int(*ev.NextProtoVersion)
		}
		log.Info("RTR version negotiation step, not an anomaly", "cache", ev.Cache,
			"proto_version", ev.ProtoVersion, "next_proto_version", next, "reason", ev.DowngradeReason)
		return nil, false
	case telemetry.EventError:
		if ev.ErrorOrigin == telemetry.ErrorOriginClient {
			// An error RAVEN found in what the cache sent (e.g. code 7,
			// duplicate announcements): the session goes on, but the cache
			// broke the protocol, which is anomalous by definition.
			return d.ObserveStructural(ev.Cache, "protocol_error", ev.Timestamp), false
		}
		return d.ObserveError(ev.Cache, ev.ErrorCode, ev.Timestamp), false
	}
	return nil, false
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

// startRTRMonitorMetrics serves Prometheus metrics on addr until ctx is
// cancelled. Mirrors the server package's runPrometheus handler wiring.
func startRTRMonitorMetrics(ctx context.Context, addr string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	go func() {
		log.Info("Prometheus metrics endpoint started", "addr", addr, "path", "/metrics")
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("Prometheus server error", "error", err)
		}
	}()
}
