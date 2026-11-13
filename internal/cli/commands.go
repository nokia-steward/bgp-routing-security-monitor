package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/buildinfo"
	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/server"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// ─── serve ───

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the RAVEN daemon (BMP receiver + RTR client + outputs)",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := initLogger()
		log.Info("starting raven", "version", buildinfo.Version, "commit", buildinfo.Commit)

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}

		// Pre-flight: bind each configured listen address briefly to fail
		// fast with one clear message instead of three mid-startup bind
		// errors from BMP, API, and Prometheus goroutines.
		ports := []string{cfg.BMP.Listen, server.APIListen(cfg)}
		if cfg.Outputs.Prometheus != nil {
			ports = append(ports, cfg.Outputs.Prometheus.Listen)
		}
		if err := preflightPortCheck(ports); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		demo, _ := cmd.Flags().GetBool("demo")

		srv, err := server.New(cfg, log)
		if err != nil {
			return err
		}
		srv.SetDemoMode(demo)
		return srv.Run()
	},
}

// preflightPortCheck attempts to bind each listen address briefly and
// releases it. Returns a single human-readable error naming the first
// port already in use; nil if all ports are free.
func preflightPortCheck(addrs []string) error {
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			display := addr
			if _, port, splitErr := net.SplitHostPort(addr); splitErr == nil && port != "" {
				display = port
			}
			return fmt.Errorf(
				"ERROR: port %s already in use — is another raven serve running?\n"+
					"   Run: pkill -f 'raven serve' && sleep 2",
				display)
		}
		_ = ln.Close()
	}
	return nil
}

// ─── version ───

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show RAVEN version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("raven %s\n", buildinfo.Version)
		fmt.Printf("  commit: %s\n", buildinfo.Commit)
		fmt.Printf("  built:  %s\n", buildinfo.Date)
	},
}

// ─── status ───

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show BMP peer states, RTR cache health, and system status",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		resp, err := apiGet(addr, "/api/v1/status", routerParam(cmd))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var status struct {
			Version string    `json:"version"`
			Uptime  string    `json:"uptime"`
			BMP     []peerRow `json:"bmp_peers"`
			RTR     struct {
				VRPCount uint64 `json:"vrp_count"`
				Serial   uint32 `json:"serial"`
			} `json:"rtr"`
			RouteTable struct {
				TotalRoutes uint64            `json:"total_routes"`
				DefaultView []string          `json:"default_view"`
				ByPosture   map[string]uint64 `json:"by_posture"`
				ByRIB       map[string]uint64 `json:"by_rib"`
			} `json:"route_table"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return err
		}

		fmt.Printf("RAVEN %s  uptime %s\n\n", status.Version, status.Uptime)
		printRouteTable(os.Stdout, status.RouteTable.TotalRoutes, status.RouteTable.DefaultView,
			status.RouteTable.ByPosture, status.RouteTable.ByRIB)

		fmt.Printf("\nRPKI: %d VRPs (serial %d)\n", status.RTR.VRPCount, status.RTR.Serial)

		fmt.Printf("\nBMP Peers: %d\n", len(status.BMP))
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		out := anyOutbound(status.BMP)
		fmt.Fprintf(tw, "  ROUTER\tPEER\tTYPE\tASN\tSTATE\tROUTES%s\n", outHeader(out))
		for _, p := range status.BMP {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%s\t%d%s\n", p.router(), p.peer(), p.PeerType, p.ASN, p.State, p.RouteCount, p.outCell(out))
		}
		tw.Flush()
		return nil
	},
}

// postureOrder is the order raven status lists postures in, best first. It
// listed them in map order, which changed from one run to the next.
var postureOrder = []string{"secured", "path-only", "origin-only", "unverified", "path-suspect", "origin-invalid"}

// ribOrder is the order raven status lists RIBs in.
var ribOrder = []string{"adj-rib-in-pre", "adj-rib-in-post", "loc-rib", "adj-rib-out-pre", "adj-rib-out-post"}

// printRouteTable prints raven status's route table summary: the default
// view's total and postures, then every RIB's total. A posture or RIB the
// daemon reports that is not in the fixed order is listed after it.
func printRouteTable(w io.Writer, total uint64, view []string, byPosture, byRIB map[string]uint64) {
	viewText := strings.Join(view, " + ")
	if viewText == "" {
		viewText = "adj-rib-in-pre" // a daemon from before the default view
	}
	fmt.Fprintf(w, "Route Table: %d routes in the default view (%s)\n", total, viewText)
	for _, posture := range inOrder(postureOrder, byPosture) {
		fmt.Fprintf(w, "  %-20s %d\n", posture, byPosture[posture])
	}
	if len(byRIB) > 0 {
		fmt.Fprintf(w, "By RIB:\n")
		for _, rib := range inOrder(ribOrder, byRIB) {
			fmt.Fprintf(w, "  %-20s %d\n", rib, byRIB[rib])
		}
	}
}

// inOrder returns the keys of m: those in order first, in that order, then
// the others sorted.
func inOrder(order []string, m map[string]uint64) []string {
	var out, rest []string
	for _, k := range order {
		if _, ok := m[k]; ok {
			out = append(out, k)
		}
	}
	for k := range m {
		if !slices.Contains(order, k) {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	return append(out, rest...)
}

// ─── peers ───

// peerRow is a BMP peer as /api/v1/status and /api/v1/peers report it: one
// peer on one router, in one instance, with its route count there.
type peerRow struct {
	Router            string            `json:"router"`
	RouterName        string            `json:"router_name"`
	PeerDistinguisher string            `json:"peer_distinguisher"`
	PeerType          string            `json:"peer_type"`
	TableName         string            `json:"table_name"`
	Addr              string            `json:"addr"`
	ASN               uint32            `json:"asn"`
	RouterID          string            `json:"router_id"`
	State             string            `json:"state"`
	RouteCount        uint64            `json:"route_count"` // default view: Adj-RIB-In pre-policy, or Loc-RIB
	RoutesByRIB       map[string]uint64 `json:"routes_by_rib"`
	UpSince           string            `json:"up_since"`
	MalformedInput    bool              `json:"malformed_input"`
	MalformedReason   string            `json:"malformed_reason"`
}

// anyMalformed reports whether any peer is marked for malformed input: only
// then does peers show a MALFORMED column, the RFC 7606 reason or "-".
func anyMalformed(rows []peerRow) bool {
	for _, p := range rows {
		if p.MalformedInput {
			return true
		}
	}
	return false
}

func malformedHeader(show bool) string {
	if show {
		return "\tMALFORMED"
	}
	return ""
}

func (p peerRow) malformedCell(show bool) string {
	switch {
	case !show:
		return ""
	case p.MalformedInput:
		return "\t" + p.MalformedReason
	}
	return "\t-"
}

// anyOutbound reports whether any peer has Adj-RIB-Out routes: only then do
// status and peers show an OUT column, the peer's Adj-RIB-Out pre-policy
// count, beside ROUTES (received) so the two are never added together.
func anyOutbound(rows []peerRow) bool {
	for _, p := range rows {
		if p.RoutesByRIB["adj-rib-out-pre"] != 0 {
			return true
		}
	}
	return false
}

func outHeader(show bool) string {
	if show {
		return "\tOUT"
	}
	return ""
}

func (p peerRow) outCell(show bool) string {
	if show {
		return fmt.Sprintf("\t%d", p.RoutesByRIB["adj-rib-out-pre"])
	}
	return ""
}

// router is the ROUTER column: the router's sysName, or its address.
func (p peerRow) router() string { return routerLabel(p.Router, p.RouterName) }

// peer is the PEER column: the address, with the VRF's RD for a peer that
// is not in the global instance. A Loc-RIB instance has the zero address;
// it shows as loc-rib, with the RD for a VRF instance (its VRF/Table Name is
// in the API's table_name).
func (p peerRow) peer() string {
	s := p.Addr
	if p.PeerType == "loc-rib" {
		s = "loc-rib"
	}
	if p.PeerDistinguisher != "" {
		return s + " rd " + p.PeerDistinguisher
	}
	return s
}

func routerLabel(addr, name string) string {
	if name != "" {
		return name
	}
	return addr
}

// routerParam is the router query parameter from --router, or nil.
func routerParam(cmd *cobra.Command) url.Values {
	if v, _ := cmd.Flags().GetString("router"); v != "" {
		return url.Values{"router": {v}}
	}
	return nil
}

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List all BMP peers with session metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		resp, err := apiGet(addr, "/api/v1/peers", routerParam(cmd))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var peers []peerRow
		if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
			return err
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		out := anyOutbound(peers)
		bad := anyMalformed(peers)
		fmt.Fprintf(tw, "ROUTER\tPEER\tTYPE\tASN\tROUTER ID\tSTATE\tROUTES%s\tUP SINCE%s\n", outHeader(out), malformedHeader(bad))
		for _, p := range peers {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%d%s\t%s%s\n",
				p.router(), p.peer(), p.PeerType, p.ASN, p.RouterID, p.State, p.RouteCount, p.outCell(out), p.UpSince,
				p.malformedCell(bad))
		}
		tw.Flush()
		return nil
	},
}

// ─── routes ───

var routesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Query the route table (filterable by prefix, ASN, peer, posture)",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		params := url.Values{}

		if v, _ := cmd.Flags().GetString("prefix"); v != "" {
			params.Set("prefix", v)
		}
		switch m, _ := cmd.Flags().GetString("match"); m {
		case "", "exact":
		case "covering", "longer":
			if params.Get("prefix") == "" {
				return fmt.Errorf("--match %s needs --prefix", m)
			}
			params.Set("match", m)
		default:
			return fmt.Errorf("--match %q: want exact, covering or longer", m)
		}
		if v, _ := cmd.Flags().GetUint32("origin-asn"); v != 0 {
			params.Set("origin-asn", fmt.Sprintf("%d", v))
		}
		if v, _ := cmd.Flags().GetString("peer"); v != "" {
			params.Set("peer", v)
		}
		if v, _ := cmd.Flags().GetString("posture"); v != "" {
			params.Set("posture", v)
		}
		if err := afiParam(cmd, params); err != nil {
			return err
		}
		if v, _ := cmd.Flags().GetString("router"); v != "" {
			params.Set("router", v)
		}
		if v, _ := cmd.Flags().GetString("rib"); v != "" {
			params.Set("rib", v)
		}

		resp, err := apiGet(addr, "/api/v1/routes", params)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			io.Copy(os.Stdout, resp.Body)
			return nil
		}

		var routes []routeRow
		if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
			return err
		}
		printRoutes(os.Stdout, routes, format == "wide")
		if peer, _ := cmd.Flags().GetString("peer"); peer != "" && len(routes) == 0 {
			rib, _ := cmd.Flags().GetString("rib")
			if hint := peerRIBHint(addr, peer, rib); hint != "" {
				fmt.Fprintln(os.Stderr, hint)
			}
		}
		return nil
	},
}

// peerRIBHint explains an empty raven routes --peer: the peer's routes are
// all in RIBs the query did not list (by default the default view,
// adj-rib-in-pre and loc-rib). A local-instance peer whose router sends only
// post-policy routes is one: raven peers shows it with 0 routes, while
// what-if --rib adj-rib-in-post counts them. "" when there is nothing to
// say or the peers cannot be read.
func peerRIBHint(addr, peer, rib string) string {
	want := types.DefaultView
	if rib != "" {
		var names []string
		for _, n := range strings.Split(rib, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		s, err := types.ParseRIBSet(names)
		if err != nil {
			return ""
		}
		want = s
	}
	pa, err := netip.ParseAddr(peer)
	if err != nil {
		return ""
	}
	resp, err := apiGet(addr, "/api/v1/peers", nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var peers []struct {
		Addr        string            `json:"addr"`
		RoutesByRIB map[string]uint64 `json:"routes_by_rib"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return ""
	}
	elsewhere := map[types.RIBType]uint64{}
	for _, p := range peers {
		if a, err := netip.ParseAddr(p.Addr); err != nil || a.Unmap() != pa.Unmap() {
			continue
		}
		for name, n := range p.RoutesByRIB {
			if r, err := types.ParseRIBType(name); err == nil && !want.Has(r) && n > 0 {
				elsewhere[r] += n
			}
		}
	}
	if len(elsewhere) == 0 {
		return ""
	}
	var parts, ribs []string
	for _, r := range types.AllRIBTypes {
		if n := elsewhere[r]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d in %s", n, r))
			ribs = append(ribs, r.String())
		}
	}
	return fmt.Sprintf("no routes from peer %s in %s; it has %s (list them with --rib %s)",
		peer, strings.Join(want.Names(), ", "), strings.Join(parts, ", "), strings.Join(ribs, ","))
}

// routeRow is the part of an /api/v1/routes route that raven routes shows.
type routeRow struct {
	Prefix            string `json:"prefix"`
	Router            string `json:"router"`
	RouterName        string `json:"router_name"`
	PeerAddr          string `json:"peer"`
	PeerDistinguisher string `json:"peer_distinguisher"`
	PeerType          string `json:"peer_type"`
	PathID            uint32 `json:"path_id"`
	RIB               string `json:"rib"`
	OriginASN         uint32 `json:"origin_asn"`
	ROV               string `json:"rov"`
	ASPA              string `json:"aspa"`
	Posture           string `json:"posture"`

	ROVDecidingVRP *struct {
		Prefix    string `json:"prefix"`
		ASN       uint32 `json:"asn"`
		MaxLength uint8  `json:"max_length"`
	} `json:"rov_deciding_vrp"`
	ASPAProcedure       string `json:"aspa_procedure"`
	ASPAProcedureSource string `json:"aspa_procedure_source"`
	ASPAFailingHop      *struct {
		CustomerASN uint32 `json:"customer_asn"`
		ProviderASN uint32 `json:"provider_asn"`
	} `json:"aspa_failing_hop"`
}

// vrp is the wide VRP column: the VRP that decided the route's ROV, as
// "94.177.129.0/24-24 AS202744", or "-" if none did (not_found).
func (r routeRow) vrp() string {
	v := r.ROVDecidingVRP
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%s-%d AS%d", v.Prefix, v.MaxLength, v.ASN)
}

// printRoutes writes the raven routes table; wide adds the deciding VRP and
// the ASPA procedure, its source and the failing hop.
func printRoutes(out io.Writer, routes []routeRow, wide bool) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	prefixes := make([]string, len(routes))
	for i, r := range routes {
		prefixes[i] = r.Prefix
	}
	pw := prefixColWidth(prefixes)
	fmt.Fprintf(tw, "%-*s\tROUTER\tPEER\tRIB\tORIGIN\tROV\tASPA\tPOSTURE", pw, "PREFIX")
	if wide {
		fmt.Fprint(tw, "\tVRP\tASPA PROCEDURE\tPROCEDURE SOURCE\tFAILING HOP")
	}
	fmt.Fprintln(tw)
	for _, r := range routes {
		origin := fmt.Sprintf("AS%d", r.OriginASN)
		if r.OriginASN == 0 {
			origin = "-"
		}
		// A Loc-RIB route has no peer: it is the router's own best path.
		peer := r.PeerAddr
		if r.PeerType == "loc-rib" {
			peer = "-"
		}
		if r.PeerDistinguisher != "" {
			peer += " rd " + r.PeerDistinguisher
		}
		if r.PathID != 0 {
			peer = fmt.Sprintf("%s path %d", peer, r.PathID)
		}
		fmt.Fprintf(tw, "%-*s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
			pw, r.Prefix, routerLabel(r.Router, r.RouterName), peer, r.RIB, origin, r.ROV, r.ASPA, r.Posture)
		if wide {
			hop := "-"
			if h := r.ASPAFailingHop; h != nil {
				hop = fmt.Sprintf("%d->%d", h.CustomerASN, h.ProviderASN)
			}
			fmt.Fprintf(tw, "\t%s\t%s\t%s\t%s", r.vrp(), r.ASPAProcedure, r.ASPAProcedureSource, hop)
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()
}

// prefixColWidth returns the column width to use for a PREFIX column: the
// longest prefix string in the result set, but never less than 24 characters
// so the column reads cleanly with IPv6 entries like 2001:db8:2121::/48.
func prefixColWidth(prefixes []string) int {
	w := 24
	for _, p := range prefixes {
		if l := len(p); l > w {
			w = l
		}
	}
	return w
}

// ─── validate ───

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "One-shot validation of a prefix against current RPKI state",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		prefix, _ := cmd.Flags().GetString("prefix")

		// One-shot validation against an RTR cache does not exist yet;
		// these flags were accepted and silently ignored.
		for _, name := range []string{"origin-asn", "rtr"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("--%s is not supported yet; validate reads the running daemon's routes for --prefix", name)
			}
		}
		if prefix == "" {
			return fmt.Errorf("--prefix is required")
		}

		params := url.Values{"prefix": {prefix}}
		resp, err := apiGet(addr, "/api/v1/routes", params)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var routes []struct {
			Prefix    string `json:"prefix"`
			PeerAddr  string `json:"peer"`
			OriginASN uint32 `json:"origin_asn"`
			ROV       string `json:"rov"`
			ROVReason string `json:"rov_reason"`
			Posture   string `json:"posture"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
			return err
		}

		if len(routes) == 0 {
			fmt.Println("no routes found for prefix", prefix)
			return nil
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		prefixes := make([]string, len(routes))
		for i, r := range routes {
			prefixes[i] = r.Prefix
		}
		pw := prefixColWidth(prefixes)
		fmt.Fprintf(tw, "%-*s\tPEER\tORIGIN\tROV\tPOSTURE\tREASON\n", pw, "PREFIX")
		for _, r := range routes {
			origin := fmt.Sprintf("AS%d", r.OriginASN)
			if r.OriginASN == 0 {
				origin = "-"
			}
			fmt.Fprintf(tw, "%-*s\t%s\t%s\t%s\t%s\t%s\n",
				pw, r.Prefix, r.PeerAddr, origin, r.ROV, r.Posture, r.ROVReason)
		}
		tw.Flush()
		return nil
	},
}

// ─── watch ───

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Stream live validation state changes",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		params := url.Values{}
		// Each filter used to be read here but posture was the only one sent.
		if v, _ := cmd.Flags().GetString("prefix"); v != "" {
			params.Set("prefix", v)
		}
		if v, _ := cmd.Flags().GetUint32("origin-asn"); v != 0 {
			params.Set("origin-asn", fmt.Sprintf("%d", v))
		}
		if v, _ := cmd.Flags().GetString("peer"); v != "" {
			params.Set("peer", v)
		}
		if v, _ := cmd.Flags().GetString("posture"); v != "" {
			params.Set("posture", v)
		}
		if err := afiParam(cmd, params); err != nil {
			return err
		}
		if v, _ := cmd.Flags().GetString("router"); v != "" {
			params.Set("router", v)
		}
		if v, _ := cmd.Flags().GetString("rib"); v != "" {
			params.Set("rib", v)
		}

		u := fmt.Sprintf("http://%s/api/v1/watch", addr)
		if len(params) > 0 {
			u += "?" + params.Encode()
		}

		resp, err := http.Get(u)
		if err != nil {
			return fmt.Errorf("connect to daemon: %w\n  is 'raven serve' running?", err)
		}
		defer resp.Body.Close()

		fmt.Println("watching for route events... (Ctrl+C to stop)")
		fmt.Println()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := line[6:]

			var r watchRoute
			if err := json.Unmarshal([]byte(data), &r); err != nil {
				continue
			}
			fmt.Println(r.line())
		}
		return scanner.Err()
	},
}

// watchRoute is the part of a watch event's route that raven watch shows.
type watchRoute struct {
	Prefix         string   `json:"prefix"`
	PeerAddr       string   `json:"peer"`
	PeerType       string   `json:"peer_type"`
	RIB            string   `json:"rib"`
	OriginASN      uint32   `json:"origin_asn"`
	ASPath         []uint32 `json:"as_path"`
	ROV            string   `json:"rov"`
	ASPA           string   `json:"aspa"`
	ASPAFailingHop *struct {
		CustomerASN uint32 `json:"customer_asn"`
		ProviderASN uint32 `json:"provider_asn"`
	} `json:"aspa_failing_hop"`
	Posture string `json:"posture"`
}

// line is r as one raven watch line. An ASPA Invalid shows its failing hop
// as hop(C→P): C's ASPA does not list P.
func (r watchRoute) line() string {
	origin := fmt.Sprintf("AS%d", r.OriginASN)
	if r.OriginASN == 0 {
		origin = "-"
	}
	aspa := "ASPA:" + r.ASPA
	if h := r.ASPAFailingHop; h != nil {
		aspa += fmt.Sprintf(" hop(%d→%d)", h.CustomerASN, h.ProviderASN)
	}
	via := r.PeerAddr
	if r.PeerType == "loc-rib" {
		via = "loc-rib"
	}
	rib := ""
	if r.RIB != "" {
		rib = " rib:" + r.RIB
	}
	return fmt.Sprintf("[%s] %s via %s%s origin:%s AS_PATH:%v rov:%s %s posture:%s",
		r.Posture, r.Prefix, via, rib, origin, r.ASPath, r.ROV, aspa, r.Posture)
}

// ─── helpers ───

func apiGet(addr string, path string, params url.Values) (*http.Response, error) {
	u := fmt.Sprintf("http://%s%s", addr, path)
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	resp, err := http.Get(u) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("connect to daemon at %s: %w\n  is 'raven serve' running?", addr, err)
	}
	return resp, nil
}

func apiPost(addr string, path string) (*http.Response, error) {
	u := fmt.Sprintf("http://%s%s", addr, path)
	resp, err := http.Post(u, "application/json", http.NoBody) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("connect to daemon at %s: %w\n  is 'raven serve' running?", addr, err)
	}
	return resp, nil
}

func init() {
	// serve flags
	serveCmd.Flags().Bool("demo", false, "use test VRPs instead of live RTR connection")

	// status and peers flags: --router limits the peers listed. Status
	// totals stay daemon-wide.
	statusCmd.Flags().String("router", "", "show only this monitored router's peers: its address or BMP sysName")
	peersCmd.Flags().String("router", "", "show only this monitored router's peers: its address or BMP sysName")

	// routes flags
	routesCmd.Flags().String("prefix", "", "filter by prefix (e.g. 1.0.0.0/24)")
	routesCmd.Flags().String("match", "exact", "how --prefix matches: exact, covering (the prefix and every less specific) or longer (the prefix and every more specific)")
	routesCmd.Flags().Uint32("origin-asn", 0, "filter by origin ASN")
	routesCmd.Flags().String("peer", "", "filter by BMP peer address")
	routesCmd.Flags().String("posture", "", "filter by security posture")
	routesCmd.Flags().String("afi", "", afiFlagHelp)
	routesCmd.Flags().String("router", "", "filter by monitored router: its address or BMP sysName")
	routesCmd.Flags().String("rib", "", ribFlagHelp)
	routesCmd.Flags().String("format", "table", "output format: table, wide, json")

	// validate flags
	validateCmd.Flags().String("prefix", "", "prefix to validate (required)")
	validateCmd.Flags().Uint32("origin-asn", 0, "origin ASN to validate (not supported yet)")
	validateCmd.Flags().String("rtr", "", "RTR cache address for one-shot mode (not supported yet)")

	// watch flags
	watchCmd.Flags().String("prefix", "", "filter by prefix")
	watchCmd.Flags().Uint32("origin-asn", 0, "filter by origin ASN")
	watchCmd.Flags().String("peer", "", "filter by peer")
	watchCmd.Flags().String("posture", "", "filter by posture")
	watchCmd.Flags().String("afi", "", afiFlagHelp)
	watchCmd.Flags().String("router", "", "filter by monitored router: its address or BMP sysName")
	watchCmd.Flags().String("rib", "", ribFlagHelp)
}

// afiFlagHelp is the help of routes and watch --afi.
const afiFlagHelp = "filter by address family: ipv4 or ipv6 (default: both)"

// afiParam sets the afi query parameter from --afi, checked here so a typo
// fails before any request. The daemon filters.
func afiParam(cmd *cobra.Command, params url.Values) error {
	v, _ := cmd.Flags().GetString("afi")
	afi, err := api.ParseAFI(v)
	if err != nil {
		return fmt.Errorf("--afi: %w", err)
	}
	if afi != 0 {
		params.Set("afi", fmt.Sprintf("ipv%d", afi))
	}
	return nil
}

// ribFlagHelp is the help of routes and watch --rib.
const ribFlagHelp = "RIBs to list, comma-separated: adj-rib-in-pre (or pre-policy), adj-rib-in-post (or post-policy), " +
	"loc-rib, adj-rib-out-pre, adj-rib-out-post (default: the default view, adj-rib-in-pre and loc-rib)"
