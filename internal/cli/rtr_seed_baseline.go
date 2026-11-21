package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// newRTRSeedBaselineCmd builds "raven rtr seed-baseline": it replays a recorded
// NDJSON telemetry file through the anomaly detector's windows and writes the
// resulting baseline snapshot, so a live monitor can warm-start from it.
func newRTRSeedBaselineCmd() *cobra.Command {
	var (
		input  string
		output string
	)

	cmd := &cobra.Command{
		Use:   "seed-baseline",
		Short: "Seed an anomaly-detector baseline snapshot from recorded RTR telemetry",
		Long: `seed-baseline replays a recorded NDJSON telemetry file through the anomaly
detector's rolling windows and writes the resulting baseline snapshot. Run it
once against an existing collection to produce a reusable baseline that
"raven rtr monitor --anomaly-snapshot" loads on startup, skipping the live
warm-up period.

Only sync records populate the windows; connected/disconnected and structural
(reset/error) records are ignored. The input is treated as ground-truth-normal,
so anomalies are not reported during seeding.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := os.Open(input)
			if err != nil {
				return fmt.Errorf("open input %q: %w", input, err)
			}
			defer f.Close()

			detector, summary, err := telemetry.SeedBaseline(f)
			if err != nil {
				return fmt.Errorf("seed baseline from %q: %w", input, err)
			}

			outPath := expandHome(output)
			if err := telemetry.EnsureAnomalySnapshotDir(outPath); err != nil {
				return fmt.Errorf("create snapshot directory: %w", err)
			}
			if err := detector.Save(outPath); err != nil {
				return fmt.Errorf("save baseline snapshot: %w", err)
			}

			printSeedSummary(cmd.OutOrStdout(), summary, outPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "path to the recorded NDJSON telemetry file to seed from (required)")
	cmd.Flags().StringVar(&output, "output", "~/.raven/anomaly-baseline.json", "path to write the baseline snapshot to")
	_ = cmd.MarkFlagRequired("input")

	return cmd
}

// printSeedSummary writes a human-readable summary of a seeding run.
func printSeedSummary(w io.Writer, s *telemetry.SeedSummary, outPath string) {
	fmt.Fprintf(w, "lines processed: %d\n", s.LinesProcessed)
	fmt.Fprintf(w, "sync records:    %d (%d full syncs skipped)\n", s.SyncCount, s.FullSyncSkip)

	lastCache := ""
	for _, fill := range s.Fills {
		if fill.Cache != lastCache {
			fmt.Fprintf(w, "window fill levels for %s:\n", fill.Cache)
			lastCache = fill.Cache
		}
		status := ""
		if fill.Count >= fill.Cap {
			status = " (full)"
		}
		fmt.Fprintf(w, "  %s: %d/%d%s\n", fill.Metric, fill.Count, fill.Cap, status)
	}
	for _, g := range s.DataGaps {
		fmt.Fprintf(w, "gaps between data changes for %s: %d/%d, stale threshold %s (%s)\n",
			g.Cache, g.Gaps, telemetry.DataGapWindow, g.Threshold.Round(time.Second), g.Source)
	}

	fmt.Fprintf(w, "output: %s\n", outPath)
}
