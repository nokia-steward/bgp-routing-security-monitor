package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
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

// progressEvery is how often dump says on stderr how many records the
// session has received, while it waits for the first End of Data.
var progressEvery = 10 * time.Second

// takeRTRSnapshot opens a session with client's cache and returns the
// records it held at the first End of Data, read on the client's goroutine
// so that they, the serial and the fingerprint belong to the same sync.
//
// A cache that cannot be reached at all (the first dial fails) ends it at
// once with the dial's error; once a session has connected, one that drops
// before the End of Data is tried again until ctx ends. progress, if not
// nil, gets a line when the cache answers and then every progressEvery
// with the records received so far, so that a slow transfer can be told
// from a hang.
func takeRTRSnapshot(ctx context.Context, client *rtr.Client, cache string, vrps *store.VRPStore,
	aspas *store.ASPAStore, now func() time.Time, progress io.Writer) (*rtrSnapshot, error) {
	ctx, cancel := context.WithCancelCause(ctx)

	connected := false // owned by the goroutine running Start
	client.SetOnSessionEnd(func(err error, dialed bool) {
		if dialed {
			connected = true
			return
		}
		if !connected {
			cancel(&unreachableError{cache: cache, err: err})
		}
	})
	var wg sync.WaitGroup
	defer func() { cancel(nil); wg.Wait() }() // no progress line once this returns
	if progress != nil {
		progress = &lockedWriter{w: progress}
		client.SetOnEstablished(func(version uint8) {
			fmt.Fprintf(progress, "%s: session open at RTR version %d, waiting for the first End of Data\n", cache, version)
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(progressEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					fmt.Fprintf(progress, "%s: %d records received so far\n", cache, client.RecordsReceived())
				}
			}
		}()
	}

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
			cancel(nil) // one sync is all this command needs
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
		cause := context.Cause(ctx)
		if reach := (*unreachableError)(nil); errors.As(cause, &reach) {
			return nil, cause
		}
		return nil, fmt.Errorf("no complete sync from %s: %w", cache, cause)
	}
}

// lockedWriter serialises the progress lines, written from the goroutine
// running Start and from the ticker.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// unreachableError is a cache that the first dial could not connect to.
type unreachableError struct {
	cache string
	err   error
}

func (e *unreachableError) Error() string { return fmt.Sprintf("cannot reach %s: %v", e.cache, e.err) }
func (e *unreachableError) Unwrap() error { return e.err }

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
			snap, err := takeRTRSnapshot(ctx, client, cache, vrps, aspas, time.Now, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			// dump.Write sorts and deduplicates: the records go to it as the stores hold them
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
