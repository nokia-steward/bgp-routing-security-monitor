package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/audit"
	"github.com/spf13/cobra"
)

func newAuditCmd(addr *string) *cobra.Command {
	var router, rib, format string

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Security posture audit for a specific router",
		Long: `Run a read-only security posture audit for a single router.

  raven audit --router 10.0.0.1
  raven audit --router 192.0.2.1 --rib loc-rib
  raven audit --router 10.0.0.1 --format json

One RIB is audited, adj-rib-in-pre unless --rib names another. --router
matches a route's peer address; for --rib loc-rib, whose routes have no
peer address, the monitored router's address.
  raven audit --router 10.0.0.1 --format markdown`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if router == "" {
				return fmt.Errorf("--router is required")
			}

			params := url.Values{"router": {router}, "rib": {rib}}
			resp, err := apiGet(*addr, "/api/v1/audit", params)
			if err != nil {
				return fmt.Errorf("audit: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				var e struct {
					Error string `json:"error"`
				}
				if json.NewDecoder(resp.Body).Decode(&e) != nil || e.Error == "" {
					e.Error = resp.Status
				}
				return fmt.Errorf("audit: %s", e.Error)
			}

			var report audit.RouterAuditReport
			if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
				return fmt.Errorf("audit: decode: %w", err)
			}

			switch format {
			case "json":
				out, err := audit.FormatJSON(&report)
				if err != nil {
					return fmt.Errorf("audit: format json: %w", err)
				}
				fmt.Println(out)
			case "markdown":
				fmt.Print(audit.FormatMarkdown(&report))
			default:
				fmt.Print(audit.FormatTable(&report))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&router, "router", "", "Router ID to audit (required)")
	cmd.Flags().StringVar(&rib, "rib", "adj-rib-in-pre",
		"RIB to audit: adj-rib-in-pre (or pre-policy), adj-rib-in-post (or post-policy), loc-rib, adj-rib-out-pre or adj-rib-out-post")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json|markdown")

	return cmd
}
