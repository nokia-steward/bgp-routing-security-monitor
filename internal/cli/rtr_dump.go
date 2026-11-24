package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/dump"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// rtrSnapshot is what one RTR session held at its first End of Data.
type rtrSnapshot struct {
	md    dump.Metadata
	vrps  []types.VRP
	aspas []types.ASPARecord
}

// takeRTRSnapshot opens a session with client's cache and returns the
// records it held at the first End of Data, read on the client's goroutine
// so that they, the serial and the fingerprint belong to the same sync.
func takeRTRSnapshot(ctx context.Context, client *rtr.Client, cache string, vrps *store.VRPStore,
	aspas *store.ASPAStore, now func() time.Time) (*rtrSnapshot, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	got := make(chan *rtrSnapshot, 1)
	client.SetOnSync(func() {
		snap := &rtrSnapshot{
			md: dump.Metadata{
				Generated:       now(),
				Cache:           cache,
				SessionID:       vrps.SessionID(),
				Serial:          client.Serial(),
				ProtocolVersion: client.ProtocolVersion(),
				DataFingerprint: client.DataFingerprint().String(),
			},
			vrps: vrps.All(),
		}
		if snap.md.ASPAAvailable() {
			snap.aspas = aspas.Snapshot()
		}
		select {
		case got <- snap:
			cancel() // one sync is all this command needs
		default:
		}
	})

	done := make(chan struct{})
	go func() {
		client.Start(ctx)
		close(done)
	}()

	select {
	case snap := <-got:
		<-done
		return snap, nil
	case <-ctx.Done():
		<-done
		select {
		case snap := <-got: // the sync and the deadline raced
			return snap, nil
		default:
		}
		return nil, fmt.Errorf("no complete sync from %s: %w", cache, context.Cause(ctx))
	}
}

func newRTRDumpCmd() *cobra.Command {
	var (
		cache      string
		transport  string
		rtrVersion string
		output     string
		timeout    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Write the VRPs and ASPAs an RTR cache serves, as JSON",
		Long: `dump opens one RTR session with a cache, waits for the first complete sync
(End of Data), writes the records the cache served and exits.

The output follows the layout of Routinator's "json" format: a "metadata"
object, then "roas" ({ "asn": "AS…", "prefix": …, "maxLength": … }) and
"aspas" ({ "customer": "AS…", "providers": ["AS…", …] }), one record a line,
sorted and without duplicates (providers too), so that two dumps compare with
a plain diff. The metadata holds the cache, the session ID, the serial, the
RTR version of the session, the time and the data fingerprint that the
telemetry of "rtr monitor" records as data_fingerprint.

RTR does not carry the trust anchor of a record, so the records have no "ta":
look a record up in a validator's "jsonext" export to find its trust anchor
and repository. A session below RTR version 2 carries no ASPA: the "aspas"
list is then left out and the metadata says that ASPAs were unavailable, so an
empty list always means a cache that holds none.`,
		Example: `  raven rtr dump --cache rtr.example.net:3323 > a.json
  raven rtr dump --cache other.example.net:3323 -o b.json
  diff a.json b.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if transport != "tcp" && transport != "tls" {
				return fmt.Errorf("invalid --transport %q: must be \"tcp\" or \"tls\"", transport)
			}
			log := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn}))
			vrps, aspas := store.NewVRPStore(), store.NewASPAStore()
			client, err := newMonitorClientStores(cache, transport, rtrVersion, vrps, aspas, nil, log)
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeoutCause(ctx, timeout,
					fmt.Errorf("timed out after %s", timeout))
				defer cancel()
			}
			snap, err := takeRTRSnapshot(ctx, client, cache, vrps, aspas, time.Now)
			if err != nil {
				return err
			}

			snap.vrps, snap.aspas = dump.SortVRPs(snap.vrps), dump.SortASPAs(snap.aspas)
			if err := writeRTRDump(cmd.OutOrStdout(), output, snap); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: session %d, serial %d, RTR version %d, %d VRPs, %s\n",
				cache, snap.md.SessionID, snap.md.Serial, snap.md.ProtocolVersion, len(snap.vrps), aspaSummary(snap))
			return nil
		},
	}

	cmd.Flags().StringVar(&cache, "cache", "localhost:3323", "RTR cache address (host:port)")
	cmd.Flags().StringVar(&transport, "transport", "tcp", "RTR transport: tcp or tls")
	cmd.Flags().StringVar(&rtrVersion, "rtr-version", "auto",
		"RTR protocol version: auto (from 2 down to what the cache speaks), or 0, 1 or 2 to pin it")
	cmd.Flags().StringVarP(&output, "output", "o", "-", "file to write the JSON to (- for standard output)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "give up when the first sync has not ended by then (0 waits forever)")

	return cmd
}

// writeRTRDump writes the snapshot to the file output, or to stdout when
// output is empty or "-".
func writeRTRDump(stdout io.Writer, output string, snap *rtrSnapshot) error {
	if output == "" || output == "-" {
		return dump.Write(stdout, snap.md, snap.vrps, snap.aspas)
	}
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create %q: %w", output, err)
	}
	if err := dump.Write(f, snap.md, snap.vrps, snap.aspas); err != nil {
		f.Close()
		return fmt.Errorf("write %q: %w", output, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %q: %w", output, err)
	}
	return nil
}

// aspaSummary says how many ASPAs the snapshot holds, or that its session
// carried none.
func aspaSummary(s *rtrSnapshot) string {
	if !s.md.ASPAAvailable() {
		return "no ASPA in this RTR version"
	}
	return fmt.Sprintf("%d ASPAs", len(s.aspas))
}
