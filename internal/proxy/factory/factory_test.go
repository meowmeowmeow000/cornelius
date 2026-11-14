package factory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"cornelius/internal/config"
)

// TestDialFallsBackWhenServerRejectsECH proves the ECH safety net end to
// end: a server that does not speak ECH (a plain stdlib TLS server) makes
// the first handshake fail with an ECH rejection, and the dialer retries
// once without ECH instead of failing the dial.
func TestDialFallsBackWhenServerRejectsECH(t *testing.T) {
	// DoH server publishing a real ECH config for a different host.
	answer := dohAnswer(`1 . ech=` + testECHBase64)
	var dohHits atomic.Int32
	dohSrv := testDoHServer(t, answer, http.StatusOK, &dohHits)
	defer dohSrv.Close()
	oldEndpoint := dohEndpoint
	dohEndpoint = dohSrv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	// Plain TLS server (no ECH) on localhost with a self-signed cert.
	cert := selfSignedLocalhostCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// Complete the handshake; the client closes after it.
				_ = conn.(*tls.Conn).Handshake()
			}(c)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	route := config.RouteCandidate{
		TargetIP:    "127.0.0.1",
		TargetPort:  uint16(port),
		CleanSNI:    "localhost",
		StealthMode: ModeTLSFrag,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := DialStealthTunnel(ctx, StealthDialConfig{
		Route:       route,
		FragDelayMs: 1,
		AllowInsec:  true,
		ECHEnabled:  true,
		// The test server's cert is self-signed, so the ECH rejection
		// verification (which ignores InsecureSkipVerify by design) would
		// fail on it. Accept the rejection here; in production the
		// callback is nil and the outer cert is verified against the
		// system roots.
		ECHRejectionVerify: func(utls.ConnectionState) error { return nil },
	})
	if err != nil {
		t.Fatalf("dial should succeed via the ECH fallback, got: %v", err)
	}
	defer conn.Close()
	if dohHits.Load() != 1 {
		t.Fatalf("DoH was queried %d times, want 1", dohHits.Load())
	}
}

func selfSignedLocalhostCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestResolveSNIDirectionHonorsExplicitFrontingMode(t *testing.T) {
	route := config.RouteCandidate{
		CleanSNI:    "worker.example.com",
		StealthMode: ModeSNIFront,
		SpoofSNI:    "cdn.example.net",
	}

	dir, outer, inner := ResolveSNIDirection(route)
	if dir != config.SNISPFDirectionFronting {
		t.Fatalf("ResolveSNIDirection() direction = %q, want %q", dir, config.SNISPFDirectionFronting)
	}
	if outer != route.SpoofSNI {
		t.Fatalf("ResolveSNIDirection() outerSNI = %q, want %q", outer, route.SpoofSNI)
	}
	if inner != route.CleanSNI {
		t.Fatalf("ResolveSNIDirection() innerHost = %q, want %q", inner, route.CleanSNI)
	}
}

func TestResolveSNIDirectionFallsBackToLegacyWithoutSpoofSNI(t *testing.T) {
	route := config.RouteCandidate{
		CleanSNI:    "worker.example.com",
		StealthMode: ModeSNIFront,
	}

	dir, outer, inner := ResolveSNIDirection(route)
	if dir != config.SNISPFDirectionLegacy {
		t.Fatalf("ResolveSNIDirection() direction = %q, want %q", dir, config.SNISPFDirectionLegacy)
	}
	if outer != route.CleanSNI {
		t.Fatalf("ResolveSNIDirection() outerSNI = %q, want %q", outer, route.CleanSNI)
	}
	if inner != route.CleanSNI {
		t.Fatalf("ResolveSNIDirection() innerHost = %q, want %q", inner, route.CleanSNI)
	}
}
