package rtrtest

import (
	"net"
	"sync"
	"testing"
	"time"
)

// cleanupTB is a testing.TB whose cleanups the test runs itself, and whose
// Logf blocks until release is closed: it holds the Server's goroutine
// inside a log call for as long as the test wants.
type cleanupTB struct {
	testing.TB
	cleanups []func()
	logged   chan struct{}
	once     sync.Once
	release  chan struct{}
}

func (tb *cleanupTB) Cleanup(f func()) { tb.cleanups = append(tb.cleanups, f) }

func (tb *cleanupTB) Logf(string, ...any) {
	tb.once.Do(func() { close(tb.logged) })
	<-tb.release
}

func (tb *cleanupTB) runCleanups() {
	for i := len(tb.cleanups) - 1; i >= 0; i-- {
		tb.cleanups[i]()
	}
}

// TestServerStopsBeforeTestCompletes checks that a Server's cleanups return
// only once its answering goroutine has, so that it cannot log to a test
// that has completed (CI run 46026953789: a data race on the finished test,
// under -race). The goroutine is held in a log call past the start of
// cleanup; before, cleanup returned with it still running.
func TestServerStopsBeforeTestCompletes(t *testing.T) {
	tb := &cleanupTB{TB: t, logged: make(chan struct{}), release: make(chan struct{})}
	s := NewServer(tb, ServerConfig{MaxVersion: 2})
	// Megabytes of Prefix PDUs, more than the socket buffers hold, so the
	// answer is still being written when the client resets the connection.
	s.SetData(GenVRPs(0, 200_000, 65000), nil)
	client, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	tc := client.(*net.TCPConn)
	tc.SetReadBuffer(4096)
	if _, err := client.Write(pdu(2, PDUResetQuery, 0)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(s.Received()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the server never received the query")
		}
		time.Sleep(time.Millisecond)
	}
	tc.SetLinger(0)
	client.Close() // RST: the server's Write fails, and it logs that
	select {
	case <-tb.logged:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never logged its failed send")
	}

	// The server's goroutine is now in Logf; let it out after cleanup has
	// begun.
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(tb.release)
	}()
	tb.runCleanups()
	select {
	case <-s.loopDone:
	default:
		t.Fatal("the server's goroutine was still running after its cleanups returned")
	}
}
