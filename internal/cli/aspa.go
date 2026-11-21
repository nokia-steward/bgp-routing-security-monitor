package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/aspa/recommender"
	"github.com/spf13/cobra"
)

func newASPACmd(addr *string) *cobra.Command {
	var asn uint32
	var format string

	cmd := &cobra.Command{
		Use:   "aspa",
		Short: "Inspect ASPA records and get recommendations",
		Long: `Work with ASPA (AS Provider Authorization) data.

  raven aspa --asn 13335
  raven aspa recommend
  raven aspa recommend --peer 172.20.20.2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if asn == 0 {
				return cmd.Help()
			}
			params := url.Values{"asn": {fmt.Sprintf("%d", asn)}}
			resp, err := apiGet(*addr, "/api/v1/aspa/record", params)
			if err != nil {
				return fmt.Errorf("aspa: %w", err)
			}
			defer resp.Body.Close()
			var record struct {
				CustomerASN uint32   `json:"customer_asn"`
				Providers   []uint32 `json:"providers"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
				return fmt.Errorf("aspa: decode: %w", err)
			}
			printASPARecord(asn, record.Providers, format)
			return nil
		},
	}

	cmd.Flags().Uint32Var(&asn, "asn", 0, "Show ASPA record for a specific ASN")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json")
	cmd.AddCommand(newASPARecommendCmd(addr))
	return cmd
}

func newASPARecommendCmd(addr *string) *cobra.Command {
	var peer, format string
	var asn uint32
	var minObs, topN int
	var includeExisting bool

	cmd := &cobra.Command{
		Use:   "recommend",
		Short: "Suggest ASPA objects based on observed AS_PATHs",
		Long: `Analyse route table AS_PATHs and suggest which ASPA objects your neighbours should create.

  raven aspa recommend
  raven aspa recommend --peer 172.20.20.2
  raven aspa recommend --asn 64500
  raven aspa recommend --min-observations 10 --top 20`,
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if peer != "" {
				params.Set("peer", peer)
			}
			if asn != 0 {
				params.Set("asn", fmt.Sprintf("%d", asn))
			}
			if minObs != 0 {
				params.Set("min_observations", fmt.Sprintf("%d", minObs))
			}
			if topN != 0 {
				params.Set("top", fmt.Sprintf("%d", topN))
			}
			if includeExisting {
				params.Set("include_existing", "true")
			}
			resp, err := apiGet(*addr, "/api/v1/aspa/recommend", params)
			if err != nil {
				return fmt.Errorf("aspa recommend: %w", err)
			}
			defer resp.Body.Close()
			var suggestions []recommender.ASPASuggestion
			if err := json.NewDecoder(resp.Body).Decode(&suggestions); err != nil {
				return fmt.Errorf("aspa recommend: decode: %w", err)
			}
			printASPARecommendations(suggestions, format)
			return nil
		},
	}

	cmd.Flags().StringVar(&peer, "peer", "", "Restrict analysis to routes from a specific peer IP")
	cmd.Flags().Uint32Var(&asn, "asn", 0, "Show suggestions for a specific customer ASN")
	cmd.Flags().IntVar(&minObs, "min-observations", 1, "Minimum route observations to include a relationship")
	cmd.Flags().IntVar(&topN, "top", 20, "Show top N suggestions (0 = all)")
	cmd.Flags().BoolVar(&includeExisting, "include-existing", false, "Include ASNs with complete existing ASPA coverage")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json")
	return cmd
}

func printASPARecord(asn uint32, providers []uint32, format string) {
	if format == "json" {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"customer_asn": asn, "providers": providers}) //nolint:errcheck
		return
	}
	if len(providers) == 0 {
		fmt.Printf("  AS%d: no ASPA record in current RTR cache\n", asn)
		return
	}
	fmt.Printf("\n  ASPA RECORD — AS%d\n  ─────────────────────────────────\n", asn)
	fmt.Printf("  Provider set (%d):\n", len(providers))
	for _, p := range providers {
		fmt.Printf("    AS%d\n", p)
	}
	fmt.Println()
}

func printASPARecommendations(suggestions []recommender.ASPASuggestion, format string) {
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(suggestions) //nolint:errcheck
		return
	}
	if len(suggestions) == 0 {
		fmt.Println("  No suggestions — all observed ASNs have complete ASPA coverage, or not enough routes observed.")
		return
	}

	fmt.Printf("\n  ASPA OBJECT RECOMMENDATIONS (%d)\n", len(suggestions))
	fmt.Println("  Note: heuristic — based on observed AS_PATHs only. Verify with your peers.")

	for _, s := range suggestions {
		status := "no ASPA record"
		if s.AlreadyHasASPA {
			status = fmt.Sprintf("existing ASPA (%d providers)", len(s.ExistingProviders))
		}
		fmt.Printf("  ┌─ AS%d  [%s]  confidence: %d%%  observations: %d\n",
			s.CustomerASN, status, s.Confidence, s.ObservationCount)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  │  SUGGESTED PROVIDER\tOBSERVED\tSTATUS")
		for _, p := range s.SuggestedProviders {
			covered := "✗ MISSING"
			if p.AlreadyCovered {
				covered = "✓ in ASPA"
			}
			fmt.Fprintf(w, "  │  AS%d\t%d routes\t%s\n", p.ProviderASN, p.ObservedCount, covered)
		}
		w.Flush()
		fmt.Println("  └──────────────────────────────────────────────────")
	}
}
