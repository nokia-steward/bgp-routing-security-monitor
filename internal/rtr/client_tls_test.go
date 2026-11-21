package rtr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
)

// generateSelfSignedCert builds an ECDSA P-256 self-signed cert valid for 127.0.0.1.
// Returns the in-memory tls.Certificate (for the server) and PEM-encoded cert bytes
// (for writing a CA file the client trusts).
func generateSelfSignedCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "raven-rtr-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, certPEM
}

// startTLSServer starts a TLS listener that, on each accepted conn, signals via
// connected and then drains until EOF. Returns the listen address and a
// closeAccepted func that drops accepted conns (so client-side reads return
// promptly). The listener itself is closed via t.Cleanup at end of test.
func startTLSServer(t *testing.T, serverCert tls.Certificate, connected chan<- struct{}) (string, func()) {
	t.Helper()

	cfg := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	var (
		mu    sync.Mutex
		conns []net.Conn
	)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				if err := tc.Handshake(); err != nil {
					conn.Close()
					continue
				}
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			select {
			case connected <- struct{}{}:
			default:
			}
			go func(c net.Conn) {
				io.Copy(io.Discard, c)
				c.Close()
			}(conn)
		}
	}()

	closeAccepted := func() {
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		conns = nil
		mu.Unlock()
	}
	t.Cleanup(func() {
		ln.Close()
		closeAccepted()
	})

	return ln.Addr().String(), closeAccepted
}

func TestRTRClientTLS(t *testing.T) {
	serverCert, caPEM := generateSelfSignedCert(t)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	connected := make(chan struct{}, 1)
	addr, closeAccepted := startTLSServer(t, serverCert, connected)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("connects with matching CA", func(t *testing.T) {
		client, err := NewClient(addr, "tls", &config.TLSConfig{CA: caPath}, store.NewVRPStore(), store.NewASPAStore(), 2, log)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		// runSession blocks until the connection closes or context is cancelled.
		// We only care that the TLS handshake completed, so check the signal
		// channel and tear down.
		done := make(chan error, 1)
		go func() { done <- client.runSession(ctx) }()

		select {
		case <-connected:
			// handshake succeeded
		case err := <-done:
			t.Fatalf("runSession returned before handshake: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for TLS handshake")
		}
		// Closing server-side conns unblocks the client's read; ctx cancel alone
		// will not interrupt a blocked TLS Read.
		closeAccepted()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("runSession did not return after closing server conns")
		}
	})

	t.Run("rejects with wrong CA", func(t *testing.T) {
		// A different self-signed cert — the server's cert won't chain to this.
		_, wrongCAPEM := generateSelfSignedCert(t)
		wrongPath := filepath.Join(dir, "wrong-ca.pem")
		if err := os.WriteFile(wrongPath, wrongCAPEM, 0o600); err != nil {
			t.Fatalf("write wrong CA: %v", err)
		}

		client, err := NewClient(addr, "tls", &config.TLSConfig{CA: wrongPath}, store.NewVRPStore(), store.NewASPAStore(), 2, log)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err = client.runSession(ctx)
		if err == nil {
			t.Fatal("expected TLS verification error, got nil")
		}
		if !strings.Contains(err.Error(), "connect") {
			t.Fatalf("expected connect error, got: %v", err)
		}
	})

	t.Run("rejects when tls-min-version exceeds server max", func(t *testing.T) {
		// Server caps the handshake at TLS 1.2 while the client pins a minimum of
		// TLS 1.3. If TLSMinVersion() is wired into the dialed tls.Config, the two
		// ranges don't overlap and the handshake must fail with a version error.
		// A passing handshake here would mean the field was silently ignored.
		srvCfg := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		}
		ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
		if err != nil {
			t.Fatalf("tls.Listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				if tc, ok := conn.(*tls.Conn); ok {
					tc.Handshake() // expected to fail on version mismatch
				}
				conn.Close()
			}
		}()

		client, err := NewClient(ln.Addr().String(), "tls",
			&config.TLSConfig{CA: caPath, MinVersion: "1.3"},
			store.NewVRPStore(), store.NewASPAStore(), 2, log)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err = client.runSession(ctx)
		if err == nil {
			t.Fatal("expected TLS version mismatch error, got nil")
		}
		if !strings.Contains(err.Error(), "connect") {
			t.Fatalf("expected connect error, got: %v", err)
		}
	})
}
