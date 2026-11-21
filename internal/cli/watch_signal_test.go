//go:build unix

package cli

import (
	"syscall"
	"testing"
	"time"
)

// #81: Ctrl+C, SIGTERM and SIGHUP end raven watch at once, with exit 0,
// even while it waits to reconnect.
func TestWatchSignalDuringBackoffExits(t *testing.T) {
	defer func(b struct{ least, most time.Duration }) { watchBackoff = b }(watchBackoff)
	watchBackoff.least, watchBackoff.most = time.Minute, time.Minute
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			w := startWatch(t, freeAddr(t))
			// Printed after the signal handler is in place, just before the
			// one-minute wait.
			w.stderrHas(t, "cannot connect")
			sent := time.Now()
			if err := syscall.Kill(syscall.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			if err := w.wait(t, time.Second); err != nil {
				t.Errorf("watch: %v, want nil (exit 0)", err)
			}
			t.Logf("exited %v after %v", sig, time.Since(sent).Round(time.Millisecond))
		})
	}
}
