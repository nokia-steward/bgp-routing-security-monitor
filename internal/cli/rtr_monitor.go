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
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
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
	version, pinned, err := parseMonitorRTRVersion(rtrVersion)
	if err != nil {
		return nil, err
	}
	// Minimal in-memory stores: NewClient requires them, but this command
	// performs no validation, so they are never queried. tlsCfg is nil:
	// NewClient only consults it when transport == "tls", and a nil config
	// falls back to the system root CA pool.
	client, err := rtr.NewClient(cache, transport, nil, store.NewVRPStore(), store.NewASPAStore(), version, log)
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
// baseline took in.
func consumeRTREvents(rec *telemetry.Recorder, detector *telemetry.Detector, observed func(), log *slog.Logger) {
	for ev := range rec.Events() {
		anomaly, ok := observeRTREvent(detector, ev, log)
		if ok && observed != nil {
			observed()
		}
		if anomaly != nil {
			rec.RecordAnomaly(anomaly)
			metrics.RTRAnomalyTotal.WithLabelValues(anomaly.Cache, anomaly.Severity).Inc()
			metrics.RTRAnomalyLastTimestamp.WithLabelValues(anomaly.Cache).Set(float64(anomaly.Timestamp.Unix()))
		}
	}
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
		cache           string
		logFile         string
		transport       string
		prometheus      string
		anomalySnapshot string
		rtrVersion      string
	)

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Observe an RTR cache session and log telemetry to NDJSON",
		Long: `monitor connects to a single RPKI-to-Router (RTR) cache, records session
lifecycle and sync events as NDJSON, and (optionally) exposes Prometheus
metrics. It maintains in-memory VRP/ASPA stores solely to drive the RTR
client; no validation or BMP ingestion happens here.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := initLogger()

			if transport != "tcp" && transport != "tls" {
				return fmt.Errorf("invalid --transport %q: must be \"tcp\" or \"tls\"", transport)
			}
			if _, _, err := parseMonitorRTRVersion(rtrVersion); err != nil {
				return err
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

			client, err := newMonitorClient(cache, transport, rtrVersion, rec, log)
			if err != nil {
				f.Close()
				return err
			}
			initAnomalyMetrics(cache)

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
				consumeRTREvents(rec, detector, func() {
					syncsSinceSave++
					if syncsSinceSave >= rtrMonitorSaveEvery {
						syncsSinceSave = 0
						if err := detector.Save(snapshotPath); err != nil {
							log.Warn("periodic anomaly baseline save failed", "path", snapshotPath, "error", err)
						}
					}
				}, log)
			}()

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			if prometheus != "" {
				startRTRMonitorMetrics(ctx, prometheus, log)
			}

			done := make(chan struct{})
			go func() {
				client.Start(ctx)
				close(done)
			}()

			log.Info("RTR monitor started", "cache", cache, "transport", transport, "rtr_version", rtrVersion, "log_file", logFile)

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

	cmd.Flags().StringVar(&cache, "cache", "localhost:3323", "RTR cache address")
	cmd.Flags().StringVar(&logFile, "log-file", "rtr-telemetry.ndjson", "path to NDJSON telemetry output file")
	cmd.Flags().StringVar(&transport, "transport", "tcp", "RTR transport: tcp or tls")
	cmd.Flags().StringVar(&prometheus, "prometheus", "", "Prometheus listen address (e.g. :9595); empty disables metrics")
	cmd.Flags().StringVar(&rtrVersion, "rtr-version", "auto",
		"RTR protocol version: auto negotiates from 2 down to what the cache supports; 0, 1 or 2 pins the session to that version, with no fallback")
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
