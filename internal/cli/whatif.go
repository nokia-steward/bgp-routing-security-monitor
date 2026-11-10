package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
	"github.com/spf13/cobra"
)

func newWhatIfCmd(addr *string) *cobra.Command {
	var rejectInvalid, aspaEnforce bool
	var peer, format string

	cmd := &cobra.Command{
		Use:   "what-if",
		Short: "Simulate routing policy deployment impact",
		Long: `Simulate the impact of deploying ROV or ASPA enforcement without changing anything.

  raven what-if --reject-invalid
  raven what-if --aspa-enforce
  raven what-if --reject-invalid --peer 172.20.20.2
  raven what-if --reject-invalid --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !rejectInvalid && !aspaEnforce {
				return fmt.Errorf("specify --reject-invalid or --aspa-enforce")
			}

			params := url.Values{}
			if peer != "" {
				params.Set("peer", peer)
			}

			if rejectInvalid {
				resp, err := apiGet(*addr, "/api/v1/whatif/reject-invalid", params)
				if err != nil {
					return fmt.Errorf("what-if: %w", err)
				}
				defer resp.Body.Close()
				var result whatif.RejectInvalidResult
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return fmt.Errorf("what-if: decode: %w", err)
				}
				printRejectInvalidResult(os.Stdout, &result, format)
			}
			if aspaEnforce {
				resp, err := apiGet(*addr, "/api/v1/whatif/aspa-enforce", params)
				if err != nil {
					return fmt.Errorf("what-if: %w", err)
				}
				defer resp.Body.Close()
				var result whatif.ASPAEnforceResult
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return fmt.Errorf("what-if: decode: %w", err)
				}
				printASPAEnforceResult(&result, format)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&rejectInvalid, "reject-invalid", false, "Simulate deploying reject-invalid ROV policy")
	cmd.Flags().BoolVar(&aspaEnforce, "aspa-enforce", false, "Simulate deploying ASPA enforcement policy")
	cmd.Flags().StringVar(&peer, "peer", "", "Restrict to routes from a specific peer IP")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json")

	return cmd
}

func printRejectInvalidResult(out io.Writer, r *whatif.RejectInvalidResult, format string) {
	if format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.Encode(r) //nolint:errcheck
		return
	}

	pct := 0.0
	if r.TotalRoutes > 0 {
		pct = float64(r.RejectedRoutes) / float64(r.TotalRoutes) * 100
	}

	fmt.Fprintln(out, "\n  REJECT-INVALID IMPACT SUMMARY")
	fmt.Fprintln(out, "  ─────────────────────────────────────────────────")
	fmt.Fprintf(out, "  Routes currently received:     %d\n", r.TotalRoutes)
	fmt.Fprintf(out, "  Routes that would be rejected: %d (%.2f%%)\n", r.RejectedRoutes, pct)
	fmt.Fprintf(out, "  Prefixes affected:             %d\n", r.AffectedPrefixes)
	fmt.Fprintf(out, "  Unique origin ASNs affected:   %d\n", r.AffectedOrigins)
	fmt.Fprintf(out, "  Carrying BLACKHOLE (RFC 7999): %d routes, %d prefixes\n\n", r.BlackholeRoutes, r.BlackholePrefixes)

	if len(r.ByReason) > 0 {
		fmt.Fprintln(out, "  REJECTED BY ROV REASON")
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "  REASON\tROUTES\tPREFIXES")
		for _, b := range r.ByReason {
			fmt.Fprintf(w, "  %s\t%d\t%d\n", b.ReasonCode, b.RouteCount, b.PrefixCount)
		}
		w.Flush()
		fmt.Fprintln(out)
	}

	if len(r.TopOrigins) > 0 {
		fmt.Fprintln(out, "  TOP AFFECTED ORIGIN ASNs")
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "  ORIGIN ASN\tROUTES\tPREFIXES\tREASON")
		for _, o := range r.TopOrigins {
			fmt.Fprintf(w, "  AS%d\t%d\t%d\t%s\n", o.OriginASN, o.RouteCount, o.PrefixCount, o.ReasonSummary())
		}
		w.Flush()
		fmt.Fprintln(out)
	}

	if len(r.ByPeer) > 0 {
		fmt.Fprintln(out, "  BY BMP PEER")
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "  PEER\tREJECTED\tTOTAL\t%")
		for _, p := range r.ByPeer {
			peerPct := 0.0
			if p.Total > 0 {
				peerPct = float64(p.Rejected) / float64(p.Total) * 100
			}
			fmt.Fprintf(w, "  %s (AS%d)\t%d\t%d\t%.2f%%\n", p.PeerAddr, p.PeerASN, p.Rejected, p.Total, peerPct)
		}
		w.Flush()
		fmt.Fprintln(out)
	}
}

func printASPAEnforceResult(r *whatif.ASPAEnforceResult, format string) {
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r) //nolint:errcheck
		return
	}

	pct := 0.0
	unverPct := 0.0
	if r.TotalRoutes > 0 {
		pct = float64(r.RejectedRoutes) / float64(r.TotalRoutes) * 100
		unverPct = float64(r.UnverifiableRoutes) / float64(r.TotalRoutes) * 100
	}

	fmt.Println("\n  ASPA ENFORCEMENT IMPACT SUMMARY")
	fmt.Println("  ─────────────────────────────────────────────────")
	fmt.Printf("  Routes currently received:     %d\n", r.TotalRoutes)
	fmt.Printf("  Routes with path-suspect:      %d (%.2f%%) ← would be dropped\n", r.RejectedRoutes, pct)
	fmt.Printf("  Routes with no ASPA coverage:  %d (%.2f%%) ← unverifiable today\n", r.UnverifiableRoutes, unverPct)
	fmt.Printf("  Prefixes affected:             %d\n", r.AffectedPrefixes)
	fmt.Printf("  Unique origin ASNs affected:   %d\n\n", r.AffectedOrigins)

	if len(r.TopFailingHops) > 0 {
		fmt.Println("  TOP FAILING AS_PATH HOPS")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "  CUSTOMER ASN\tUNAUTH PROVIDER\tROUTES AFFECTED")
		for _, h := range r.TopFailingHops {
			fmt.Fprintf(w, "  AS%d\tAS%d\t%d\n", h.CustomerASN, h.ProviderASN, h.RouteCount)
		}
		w.Flush()
		fmt.Println()
	}
}
