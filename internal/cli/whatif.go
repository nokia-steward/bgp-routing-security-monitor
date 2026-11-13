package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
	"github.com/spf13/cobra"
)

func newWhatIfCmd(addr *string) *cobra.Command {
	var rejectInvalid, aspaEnforce bool
	var peer, format, rib string

	cmd := &cobra.Command{
		Use:   "what-if",
		Short: "Simulate routing policy deployment impact",
		Long: `Simulate the impact of deploying ROV or ASPA enforcement without changing anything.

  raven what-if --reject-invalid
  raven what-if --aspa-enforce
  raven what-if --reject-invalid --peer 172.20.20.2
  raven what-if --reject-invalid --rib adj-rib-in-post
  raven what-if --reject-invalid --format json

By default the simulation covers the routes received before import policy
(adj-rib-in-pre). --rib picks others: adj-rib-in-post, loc-rib, or all of
the three (a route reported in several RIBs then counts once per RIB). The
summary says which RIBs it covers; raven routes --peer with the same --rib
lists a peer's routes it counted.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !rejectInvalid && !aspaEnforce {
				return fmt.Errorf("specify --reject-invalid or --aspa-enforce")
			}

			params := url.Values{}
			if peer != "" {
				params.Set("peer", peer)
			}
			if _, err := whatif.ParseRIBs(rib); err != nil {
				return fmt.Errorf("--rib: %w", err)
			}
			if rib != "" {
				params.Set("rib", rib)
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
				printASPAEnforceResult(os.Stdout, &result, format)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&rejectInvalid, "reject-invalid", false, "Simulate deploying reject-invalid ROV policy")
	cmd.Flags().BoolVar(&aspaEnforce, "aspa-enforce", false, "Simulate deploying ASPA enforcement policy")
	cmd.Flags().StringVar(&peer, "peer", "", "Restrict to routes from a specific peer IP")
	cmd.Flags().StringVar(&rib, "rib", "", "RIBs to simulate on: adj-rib-in-pre, adj-rib-in-post, loc-rib or all (default adj-rib-in-pre)")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json")

	return cmd
}

// ribsCovered is a summary's RIBs line: the RIBs a result covers.
func ribsCovered(ribs []string) string {
	if len(ribs) == 0 {
		return "not reported (daemon older than what-if --rib)"
	}
	return strings.Join(ribs, ", ")
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
	fmt.Fprintf(out, "  RIBs covered:                  %s\n", ribsCovered(r.RIBs))
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
		if len(r.RIBs) > 0 {
			// raven routes' default view is not what-if's: name the RIBs
			// that list the same routes.
			fmt.Fprintf(out, "  (a peer's routes: raven routes --peer PEER --rib %s)\n", strings.Join(r.RIBs, ","))
		}
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

func printASPAEnforceResult(out io.Writer, r *whatif.ASPAEnforceResult, format string) {
	if format == "json" {
		enc := json.NewEncoder(out)
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

	fmt.Fprintln(out, "\n  ASPA ENFORCEMENT IMPACT SUMMARY")
	fmt.Fprintln(out, "  ─────────────────────────────────────────────────")
	fmt.Fprintf(out, "  RIBs covered:                  %s\n", ribsCovered(r.RIBs))
	fmt.Fprintf(out, "  Routes currently received:     %d\n", r.TotalRoutes)
	fmt.Fprintf(out, "  Routes with path-suspect:      %d (%.2f%%) ← would be dropped\n", r.RejectedRoutes, pct)
	fmt.Fprintf(out, "  Routes with no ASPA coverage:  %d (%.2f%%) ← unverifiable today\n", r.UnverifiableRoutes, unverPct)
	fmt.Fprintf(out, "  Prefixes affected:             %d\n", r.AffectedPrefixes)
	fmt.Fprintf(out, "  Unique origin ASNs affected:   %d\n\n", r.AffectedOrigins)

	if len(r.TopFailingHops) > 0 {
		fmt.Fprintln(out, "  TOP FAILING AS_PATH HOPS")
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "  CUSTOMER ASN\tUNAUTH PROVIDER\tROUTES AFFECTED")
		for _, h := range r.TopFailingHops {
			fmt.Fprintf(w, "  AS%d\tAS%d\t%d\n", h.CustomerASN, h.ProviderASN, h.RouteCount)
		}
		w.Flush()
		fmt.Fprintln(out)
	}
}
