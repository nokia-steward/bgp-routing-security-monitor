package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/server"
)

// ─── watch ───

// watchBackoff is how long raven watch waits before each reconnect: least
// first, doubling up to most, less up to a fifth of jitter (#81).
var watchBackoff = struct{ least, most time.Duration }{time.Second, 30 * time.Second}

func newWatchCmd(addr *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Stream live validation state changes",
		Long: `Stream live validation state changes.

Events go to stdout, one line each. Everything else goes to stderr: when
the stream ends or the daemon cannot be reached, raven watch says why and
reconnects with backoff (1 s doubling to 30 s), and says so when the
stream is back. Events sent while it was away are not replayed. With
--once it exits non-zero instead. Ctrl+C, SIGTERM and SIGHUP exit 0.`,
		// As the root command: main prints the error, and an error that is
		// not a usage error does not print the usage.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
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
			once, _ := cmd.Flags().GetBool("once")

			u := fmt.Sprintf("http://%s/api/v1/watch", *addr)
			if len(params) > 0 {
				u += "?" + params.Encode()
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), server.ShutdownSignals...)
			defer stop()
			return runWatch(ctx, watchOptions{
				url: u, addr: *addr, once: once,
				least: watchBackoff.least, most: watchBackoff.most,
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().String("prefix", "", "filter by prefix")
	cmd.Flags().Uint32("origin-asn", 0, "filter by origin ASN")
	cmd.Flags().String("peer", "", "filter by peer")
	cmd.Flags().String("posture", "", "filter by posture")
	cmd.Flags().String("afi", "", afiFlagHelp)
	cmd.Flags().String("router", "", "filter by monitored router: its address or BMP sysName")
	cmd.Flags().String("rib", "", ribFlagHelp)
	cmd.Flags().Bool("once", false, "exit non-zero when the stream ends or fails, instead of reconnecting")
	return cmd
}

// watchOptions is one raven watch run: the watch URL, filters included
// (sent unchanged on every reconnect), the daemon's address for messages,
// --once, and the backoff bounds.
type watchOptions struct {
	url, addr   string
	once        bool
	least, most time.Duration
}

// errWatchRefused is a watch the daemon answered with a 4xx (a bad filter):
// reconnecting would get the same answer.
var errWatchRefused = errors.New("daemon refused the watch")

// runWatch streams the watch at o.url, an event per line to stdout, until
// ctx is done (nil: Ctrl+C or a shutdown signal). A stream that ends or
// fails, or a connect that fails, is reported to stderr and retried with
// backoff; with o.once it is returned instead. A 4xx is always returned.
func runWatch(ctx context.Context, o watchOptions, stdout, stderr io.Writer) error {
	b := backoff{least: o.least, most: o.most}
	var (
		connected  bool      // a stream has been open
		down       time.Time // when the last stream ended, or the first connect failed
		lastReason string    // the last connect failure reported, not repeated
	)
	for {
		resp, err := openWatch(ctx, o.url)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			switch {
			case connected:
				fmt.Fprintf(stderr, "raven watch: reconnected to %s after %s; events during the gap were not replayed\n",
					o.addr, roundGap(time.Since(down)))
			case !down.IsZero():
				fmt.Fprintf(stderr, "raven watch: connected to %s after %s of retries\n", o.addr, roundGap(time.Since(down)))
				fallthrough
			default:
				fmt.Fprintln(stderr, "watching for route events... (Ctrl+C to stop)")
			}
			connected, lastReason = true, ""
			b.reset()
			reason := streamWatch(resp.Body, stdout)
			resp.Body.Close()
			if ctx.Err() != nil {
				return nil
			}
			down = time.Now()
			if o.once {
				return fmt.Errorf("watch stream from %s ended: %s", o.addr, reason)
			}
			fmt.Fprintf(stderr, "raven watch: stream ended: %s; reconnecting\n", reason)
		} else {
			if errors.Is(err, errWatchRefused) {
				return err
			}
			msg := fmt.Sprintf("connect to daemon at %s: %v", o.addr, err)
			if o.once {
				return fmt.Errorf("%s\n  is 'raven serve' running?", msg)
			}
			if down.IsZero() {
				down = time.Now()
			}
			if msg != lastReason {
				verb := "reconnect failed"
				if !connected {
					verb = "cannot connect"
				}
				fmt.Fprintf(stderr, "raven watch: %s: %s; retrying\n", verb, msg)
				lastReason = msg
			}
		}
		t := time.NewTimer(b.next())
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// openWatch opens the watch stream at u. A non-200 answer is an error,
// errWatchRefused for a 4xx.
func openWatch(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	detail := strings.TrimSpace(string(body))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return nil, fmt.Errorf("%w: %s: %s", errWatchRefused, resp.Status, detail)
	}
	return nil, fmt.Errorf("%s: %s", resp.Status, detail)
}

// streamWatch writes each event of the stream body as a line to stdout
// until the stream ends, and returns why it ended.
func streamWatch(body io.Reader, stdout io.Writer) string {
	sc := bufio.NewScanner(body)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var r watchRoute
		if err := json.Unmarshal([]byte(data), &r); err != nil {
			continue
		}
		fmt.Fprintln(stdout, r.line())
	}
	if err := sc.Err(); err != nil {
		return err.Error()
	}
	return "the daemon closed it"
}

// roundGap is d to a tenth of a second, or a second from a minute on.
func roundGap(d time.Duration) time.Duration {
	if d >= time.Minute {
		return d.Round(time.Second)
	}
	return d.Round(100 * time.Millisecond)
}

// backoff is the wait before each reconnect: least, doubling to most, each
// less up to a fifth at random so that many watchers of one restarted
// daemon do not all reconnect at once. It never exceeds most.
type backoff struct {
	least, most time.Duration
	cur         time.Duration
}

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.least
	} else {
		b.cur = min(2*b.cur, b.most)
	}
	return b.cur - time.Duration(rand.Float64()*float64(b.cur)/5)
}

func (b *backoff) reset() { b.cur = 0 }

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
