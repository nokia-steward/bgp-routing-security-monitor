//go:build linux

package rtr

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
)

// keepAliveOpts reads the keepalive socket options of conn's TCP socket.
func keepAliveOpts(t *testing.T, conn net.Conn) (on, idle, intvl, cnt int) {
	t.Helper()
	if tc, ok := conn.(*tls.Conn); ok {
		conn = tc.NetConn()
	}
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		get := func(level, opt int) int {
			v, err := syscall.GetsockoptInt(int(fd), level, opt)
			if err != nil && serr == nil {
				serr = err
			}
			return v
		}
		on = get(syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
		idle = get(syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
		intvl = get(syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL)
		cnt = get(syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT)
	})
	if err != nil || serr != nil {
		t.Fatalf("read socket options: %v %v", err, serr)
	}
	return on, idle, intvl, cnt
}

// The sockets of live RTR sessions, plain TCP and TLS, carry the keepalive
// settings: on, 60s idle, 15s between probes, 4 probes.
func TestRTRSessionSocketsHaveKeepAlive(t *testing.T) {
	type opts struct{ on, idle, intvl, cnt int }
	check := func(t *testing.T, c *Client) {
		t.Helper()
		got := make(chan opts, 1)
		c.connHook = func(conn net.Conn) {
			var o opts
			o.on, o.idle, o.intvl, o.cnt = keepAliveOpts(t, conn)
			got <- o
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.Start(ctx)
		}()
		defer func() {
			cancel()
			<-done
		}()
		select {
		case o := <-got:
			if want := (opts{1, 60, 15, 4}); o != want {
				t.Errorf("socket keepalive (on, idle s, interval s, count) = %+v, want %+v", o, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("client did not connect within 5s")
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("tcp", func(t *testing.T) {
		cache := rtrtest.NewCache(t)
		c, err := NewClient(cache.Addr(), "tcp", nil, store.NewVRPStore(), store.NewASPAStore(), 2, log)
		if err != nil {
			t.Fatal(err)
		}
		check(t, c)
	})

	t.Run("tls", func(t *testing.T) {
		serverCert, caPEM := generateSelfSignedCert(t)
		caPath := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		addr, _ := startTLSServer(t, serverCert, make(chan struct{}, 1))
		c, err := NewClient(addr, "tls", &config.TLSConfig{CA: caPath}, store.NewVRPStore(), store.NewASPAStore(), 2, log)
		if err != nil {
			t.Fatal(err)
		}
		check(t, c)
	})
}
