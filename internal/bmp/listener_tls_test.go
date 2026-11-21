package bmp

import (
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
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/config"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// generateBMPTestCert builds an ECDSA P-256 self-signed cert valid for 127.0.0.1
// with v3 extensions, returning the cert+key PEM-encoded for writing to disk
// and the cert PEM (also suitable as a CA bundle, since the cert is self-signed).
func generateBMPTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "raven-bmp-test"},
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
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestBMPListenerTLS(t *testing.T) {
	certPEM, keyPEM := generateBMPTestCert(t)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bmp.crt")
	keyPath := filepath.Join(dir, "bmp.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	tlsCfg, err := BuildTLSConfig(&config.TLSConfig{Cert: certPath, Key: keyPath})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}

	ingestCh := make(chan types.IngestEvent, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Listen on a random localhost port. We bypass Listener.Start so we don't
	// have to drive the full accept loop — we only need to verify TLS handshake.
	listener := NewListener("127.0.0.1:0", tlsCfg, ingestCh, log)
	ln, err := tls.Listen("tcp", listener.addr, listener.tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Echo server: accept and immediately close so the dial-side handshake
	// completes, but no BMP framing is required.
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := conn.(*tls.Conn); ok {
			_ = tc.Handshake()
		}
		accepted <- struct{}{}
		conn.Close()
	}()

	t.Run("tls dial with matching CA succeeds", func(t *testing.T) {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certPEM) {
			t.Fatal("AppendCertsFromPEM failed")
		}
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("tls.Dial: %v", err)
		}
		defer conn.Close()

		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not accept connection")
		}
	})

	t.Run("plain tcp dial to tls listener fails handshake-like read", func(t *testing.T) {
		// Need a second connection — re-accept on the server side.
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// The server will try to read a TLS ClientHello; we send junk
			// instead. Reading from the server side will fail; we only care
			// that the client sees an error too.
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake() // expected to error
			}
		}()

		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		defer raw.Close()

		// Send a non-TLS payload (a plausible BMP common header would do; we
		// just send random bytes). The server will fail to negotiate TLS and
		// close. A subsequent Read should return an error rather than valid
		// BMP-looking data.
		if _, err := raw.Write([]byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x06}); err != nil {
			t.Fatalf("write: %v", err)
		}
		raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		_, err = raw.Read(buf)
		if err == nil {
			t.Fatal("expected read error on plain dial to TLS listener, got nil")
		}
	})

}
