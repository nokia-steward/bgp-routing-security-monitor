package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external/ripestat"
)

// Verdicts for the global-visibility check. These are stable
// machine-readable tokens; the banner labels are separate.
const (
	verdictGlobalMatch        = "MATCH"
	verdictGlobalDivergent    = "DIVERGENT"
	verdictGlobalLocalOnly    = "LOCAL_ONLY"
	verdictGlobalInconclusive = "INCONCLUSIVE"
)

// Where the comparison baseline came from.
const (
	originSourceBMP  = "bmp"
	originSourceFlag = "flag"
)

// globalReport is the structured output of `raven check global`.
type globalReport struct {
	Prefix string `json:"prefix"`
	// LocalOriginASN is the baseline the global view is compared against.
	LocalOriginASN uint32 `json:"local_origin_asn"`
	// LocalOriginSource is "bmp" when taken from the daemon's RIB, or
	// "flag" when supplied via --origin-asn.
	LocalOriginSource string `json:"local_origin_source"`
	LocalPeer         string `json:"local_peer,omitempty"`
	LocalPeerASN      uint32 `json:"local_peer_asn,omitempty"`
	LocalPosture      string `json:"local_posture,omitempty"`
	LocalROV          string `json:"local_rov,omitempty"`
	LocalASPA         string `json:"local_aspa,omitempty"`
	// LocalRouteCount is how many BMP-observed routes the daemon holds for
	// the prefix. Zero when the daemon was not consulted or had none.
	LocalRouteCount int `json:"local_route_count"`
	// LocalNote explains why local BMP state is absent, if it is.
	LocalNote string `json:"local_note,omitempty"`

	GlobalVisibility external.GlobalVisibilityResult `json:"global_visibility"`

	Verdict     string `json:"verdict"`
	Explanation string `json:"explanation"`
}

// checkGlobalCmd is `raven check global`.
var checkGlobalCmd = &cobra.Command{
	Use:   "global",
	Short: "Correlate a prefix against global BGP visibility via RIPEstat",
	Long: `Compare RAVEN's local BMP-observed origin for a prefix against the
origin ASNs that third-party route collectors see for it.

RAVEN's ROV and ASPA validation is local-vantage-point only: it knows what
your own BMP-attached routers received. That cannot tell you whether a
suspicious route is a real hijack the rest of the internet also sees, or a
purely local leak or misconfiguration. This check answers that question by
querying the RIPEstat looking-glass data call.

It is a one-shot, on-demand check. Nothing here runs on the BMP ingest path.`,
	RunE: runCheckGlobal,
}

func init() {
	checkGlobalCmd.Flags().String("prefix", "", "Prefix to correlate (required, CIDR)")
	checkGlobalCmd.Flags().Uint32("origin-asn", 0,
		"Origin ASN to compare against (default: the daemon's BMP-observed origin for the prefix)")
	checkGlobalCmd.Flags().String("format", "table", "Output format: table|json")

	checkCmd.AddCommand(checkGlobalCmd)
}

func runCheckGlobal(cmd *cobra.Command, args []string) error {
	daemonAddr, _ := cmd.Flags().GetString("address")
	prefixArg, _ := cmd.Flags().GetString("prefix")
	originASN, _ := cmd.Flags().GetUint32("origin-asn")
	format, _ := cmd.Flags().GetString("format")

	if prefixArg == "" {
		return fmt.Errorf("--prefix is required")
	}
	pfx, err := netip.ParsePrefix(prefixArg)
	if err != nil {
		return fmt.Errorf("invalid prefix %q: %w", prefixArg, err)
	}
	pfx = pfx.Masked()

	// AS0 is reserved and cannot originate a route, so an explicit
	// --origin-asn 0 is a mistake rather than a request to auto-detect.
	originFlagSet := cmd.Flags().Changed("origin-asn")
	if originFlagSet && originASN == 0 {
		return fmt.Errorf("--origin-asn must be a real ASN; AS0 is reserved")
	}

	rsCfg, err := loadRIPEstatConfig()
	if err != nil {
		return err
	}

	report := globalReport{Prefix: pfx.String()}

	// ── Local BMP view ───────────────────────────────────────────────────
	// The daemon's /api/v1/routes response shape is shared with
	// `check stealthy`, so its decoder is reused here.
	routes, routesErr := fetchStealthyRoutes(daemonAddr, pfx.String())
	switch {
	case routesErr != nil:
		// A missing daemon is not fatal: with --origin-asn the global view
		// still stands on its own.
		if !originFlagSet {
			return fmt.Errorf("%w\n  pass --origin-asn to correlate without a running daemon", routesErr)
		}
		report.LocalNote = "daemon unreachable — baseline taken from --origin-asn"
	case len(routes) == 0:
		if !originFlagSet {
			return fmt.Errorf("no routes found for prefix %s in BMP RIB\n"+
				"  pass --origin-asn to correlate a prefix the daemon has not seen", pfx)
		}
		report.LocalNote = "prefix not present in BMP RIB — baseline taken from --origin-asn"
	default:
		best := pickBestRoute(routes)
		report.LocalRouteCount = len(routes)
		report.LocalPeer = best.PeerAddr
		report.LocalPeerASN = best.neighborASN()
		report.LocalPosture = best.Posture
		report.LocalROV = best.ROV
		report.LocalASPA = best.ASPA
		if !originFlagSet {
			originASN = best.OriginASN
		}
	}

	report.LocalOriginASN = originASN
	report.LocalOriginSource = originSourceBMP
	if originFlagSet {
		report.LocalOriginSource = originSourceFlag
	}

	if format != "json" {
		fmt.Printf("Correlating global visibility for %s...\n\n", pfx)
		printLocalView(report)
		fmt.Printf("Global view (RIPEstat looking-glass, %s):\n", rsCfg.BaseURL)
	}

	// ── Global view ──────────────────────────────────────────────────────
	client, err := ripestat.New(ripestat.Config{
		BaseURL:         rsCfg.BaseURL,
		Timeout:         rsCfg.Timeout,
		CacheTTL:        rsCfg.CacheTTL,
		RateLimitPerMin: rsCfg.RateLimitPerMin,
	})
	if err != nil {
		return fmt.Errorf("ripestat client: %w", err)
	}

	// Bound the whole correlation slightly above the per-request timeout so
	// the context is a backstop, not the primary deadline.
	timeout := rsCfg.Timeout
	if timeout <= 0 {
		timeout = ripestat.DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout+2*time.Second)
	defer cancel()

	// Correlate never fails: an unreachable or malformed RIPEstat degrades
	// to an Inconclusive result.
	report.GlobalVisibility = external.Correlate(ctx, client, pfx, originASN, 0)
	report.Verdict, report.Explanation = globalVerdict(report.GlobalVisibility)

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	printGlobalView(report.GlobalVisibility)
	fmt.Println()
	printGlobalVerdictBox(report)
	return nil
}

// loadRIPEstatConfig reads the external.ripestat section, falling back to the
// package defaults when there is no config file at all.
//
// It deliberately does not require external.ripestat.enabled: invoking
// `raven check global` is itself the explicit opt-in. The enabled flag gates
// only the Event Engine's automatic correlation.
func loadRIPEstatConfig() (config.RIPEstatConfig, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.RIPEstatConfig{}, fmt.Errorf("config: %w", err)
	}
	rs := cfg.External.RIPEstat
	if rs.BaseURL == "" {
		rs.BaseURL = ripestat.DefaultBaseURL
	}
	return rs, nil
}

// globalVerdict maps a consensus to a stable verdict token and a one-line
// operator explanation.
func globalVerdict(r external.GlobalVisibilityResult) (verdict, explanation string) {
	switch r.Consensus {
	case external.ConsensusMatch:
		return verdictGlobalMatch, fmt.Sprintf(
			"Global majority origin matches local BMP view (%d collector peers)", r.CollectorCount)

	case external.ConsensusDivergent:
		majority, _ := r.MajorityOrigin()
		if len(r.GlobalOrigins) > 1 {
			return verdictGlobalDivergent, fmt.Sprintf(
				"MOAS conflict — %d origins seen globally, most-observed is AS%d", len(r.GlobalOrigins), majority)
		}
		return verdictGlobalDivergent, fmt.Sprintf(
			"The internet sees AS%d originating this prefix, not AS%d", majority, r.LocalOrigin)

	case external.ConsensusLocalOnly:
		return verdictGlobalLocalOnly,
			"No collector sees this prefix — a local leak or misconfiguration, not a propagated hijack"

	default:
		return verdictGlobalInconclusive, "Could not determine global visibility: " + r.Error
	}
}

// ─── Rendering ───────────────────────────────────────────────────────────────

// maxBannerWidth caps the verdict banner so a long error message cannot
// stretch it past a normal terminal.
const maxBannerWidth = 96

// truncateForBanner shortens s to at most limit runes, ending in an ellipsis
// when it had to cut. It counts runes, not bytes, so a multi-byte character
// is never split.
func truncateForBanner(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit-3]) + "..."
}

func printLocalView(r globalReport) {
	fmt.Println("Local view (BMP/RIB):")
	if r.LocalRouteCount == 0 {
		fmt.Printf("  Origin  : AS%d (from --origin-asn)\n", r.LocalOriginASN)
		if r.LocalNote != "" {
			fmt.Printf("  Note    : %s\n", r.LocalNote)
		}
		fmt.Println()
		return
	}
	fmt.Printf("  Route   : %s via AS%d (%s)\n", r.Prefix, r.LocalOriginASN, r.LocalPosture)
	fmt.Printf("  Peer    : %s (AS%d), %d route(s) in RIB\n", r.LocalPeer, r.LocalPeerASN, r.LocalRouteCount)
	fmt.Printf("  Local   : ROV %s, ASPA %s\n", r.LocalROV, r.LocalASPA)
	if r.LocalOriginSource == originSourceFlag {
		fmt.Printf("  Baseline: AS%d (overridden by --origin-asn)\n", r.LocalOriginASN)
	}
	fmt.Println()
}

func printGlobalView(r external.GlobalVisibilityResult) {
	if r.Consensus == external.ConsensusInconclusive {
		fmt.Printf("  unavailable — %s\n", r.Error)
		return
	}
	if len(r.GlobalOrigins) == 0 {
		fmt.Println("  no observations — no route collector carries this prefix")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  ORIGIN\tCOLLECTOR PEERS\tSHARE\tNOTE")
	for _, o := range r.GlobalOrigins {
		share := "-"
		if r.CollectorCount > 0 {
			share = fmt.Sprintf("%.0f%%", 100*float64(o.CollectorCount)/float64(r.CollectorCount))
		}
		note := ""
		if o.ASN == r.LocalOrigin {
			note = "matches local"
		}
		fmt.Fprintf(w, "  AS%d\t%d\t%s\t%s\n", o.ASN, o.CollectorCount, share, note)
	}
	if err := w.Flush(); err != nil {
		return
	}
	fmt.Printf("  %d collector peer observations in %s\n", r.CollectorCount, r.Latency.Round(time.Millisecond))
}

func printGlobalVerdictBox(r globalReport) {
	color := ansiReset
	switch r.Verdict {
	case verdictGlobalMatch:
		color = "\033[0;32m" // green
	case verdictGlobalDivergent:
		color = ansiRed + ansiBold
	case verdictGlobalLocalOnly:
		color = ansiAmber
	case verdictGlobalInconclusive:
		color = "\033[0;90m" // grey
	}

	// Display label diverges from the JSON verdict token: the latter is
	// stable and machine-readable, the former is a human banner.
	displayVerdict := r.Verdict
	switch r.Verdict {
	case verdictGlobalMatch:
		displayVerdict = "GLOBAL MATCH"
	case verdictGlobalDivergent:
		displayVerdict = "GLOBAL DIVERGENCE DETECTED"
	case verdictGlobalLocalOnly:
		displayVerdict = "LOCAL-ONLY ROUTE"
	}
	// A raw transport error can run to hundreds of characters, which would
	// stretch the banner past any terminal. The full text stays in the
	// detail line above and in --format json.
	line1 := truncateForBanner(fmt.Sprintf("%s: %s", displayVerdict, r.Explanation), maxBannerWidth)

	global := "?"
	if asn, ok := r.GlobalVisibility.MajorityOrigin(); ok {
		global = fmt.Sprintf("AS%d", asn)
	} else if r.GlobalVisibility.Consensus == external.ConsensusLocalOnly {
		global = "nobody"
	}
	line2 := fmt.Sprintf("Local RIB says: AS%d │ The internet says: %s", r.LocalOriginASN, global)

	// Pad on rune counts, not bytes: the box-drawing separator in line2 is
	// multi-byte, and %-*s would pad it two columns short.
	width := max(utf8.RuneCountInString(line1), utf8.RuneCountInString(line2), 46)
	bar := strings.Repeat("═", width+2)
	fmt.Printf("%s╔%s╗%s\n", color, bar, ansiReset)
	fmt.Printf("%s║ %s ║%s\n", color, padToRunes(line1, width), ansiReset)
	fmt.Printf("%s║ %s ║%s\n", color, padToRunes(line2, width), ansiReset)
	fmt.Printf("%s╚%s╝%s\n", color, bar, ansiReset)
}

// padToRunes right-pads s with spaces to width display columns, counting
// runes rather than bytes.
func padToRunes(s string, width int) string {
	if n := utf8.RuneCountInString(s); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}
