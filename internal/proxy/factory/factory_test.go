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
	"strings"
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

// countingTLSServer starts a plain stdlib TLS server (no ECH) on
// localhost and counts accepted connections, so a test can prove how
// many dials the client actually made.
func countingTLSServer(t *testing.T, cert tls.Certificate) (port int, accepts *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	accepts = &atomic.Int32{}
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepts
}

func strictTestRoute(port int, host string) config.RouteCandidate {
	return config.RouteCandidate{
		TargetIP:    "127.0.0.1",
		TargetPort:  uint16(port),
		CleanSNI:    host,
		StealthMode: ModeTLSFrag,
	}
}

// TestDialStrictRefusesWhenServerRejectsECH is the fail-closed half of
// TestDialFallsBackWhenServerRejectsECH: same server, same config, but
// strict mode must fail the dial outright and never retry without ECH —
// exactly one connection reaches the server.
func TestDialStrictRefusesWhenServerRejectsECH(t *testing.T) {
	answer := dohAnswer(`1 . ech=` + testECHBase64)
	dohSrv := testDoHServer(t, answer, http.StatusOK, nil)
	defer dohSrv.Close()
	oldEndpoint := dohEndpoint
	dohEndpoint = dohSrv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	cert := selfSignedLocalhostCert(t)
	port, accepts := countingTLSServer(t, cert)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := DialStealthTunnel(ctx, StealthDialConfig{
		Route:              strictTestRoute(port, "strict-reject.example"),
		FragDelayMs:        1,
		AllowInsec:         true,
		ECHEnabled:         true,
		ECHRequired:        true,
		ECHRejectionVerify: func(utls.ConnectionState) error { return nil },
	})
	if err == nil {
		t.Fatal("strict dial should fail when the server rejects ECH")
	}
	if !strings.Contains(err.Error(), "strict ECH required") {
		t.Fatalf("error should name strict mode, got: %v", err)
	}
	if accepts.Load() != 1 {
		t.Fatalf("server saw %d connections, want 1 (strict mode must not retry without ECH)", accepts.Load())
	}
}

// TestDialStrictRefusesWhenFetchFails: with no usable ECH config at all,
// strict mode must fail before any dial is attempted — the server sees
// zero connections. The same failure without strict mode still dials.
func TestDialStrictRefusesWhenFetchFails(t *testing.T) {
	oldEndpoint := dohEndpoint
	dohEndpoint = "http://127.0.0.1:1" // nothing listens here
	defer func() { dohEndpoint = oldEndpoint }()

	cert := selfSignedLocalhostCert(t)
	port, accepts := countingTLSServer(t, cert)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := DialStealthTunnel(ctx, StealthDialConfig{
		Route:       strictTestRoute(port, "strict-fetch.example"),
		FragDelayMs: 1,
		AllowInsec:  true,
		ECHEnabled:  true,
		ECHRequired: true,
	})
	if err == nil {
		t.Fatal("strict dial should fail when no ECH config can be fetched")
	}
	if !strings.Contains(err.Error(), "strict ECH required") {
		t.Fatalf("error should name strict mode, got: %v", err)
	}
	if accepts.Load() != 0 {
		t.Fatalf("server saw %d connections, want 0 (strict mode must fail before dialling)", accepts.Load())
	}

	// Control: without strict mode the same fetch failure falls back and dials.
	conn, err := DialStealthTunnel(ctx, StealthDialConfig{
		Route:       strictTestRoute(port, "strict-fetch.example"),
		FragDelayMs: 1,
		AllowInsec:  true,
		ECHEnabled:  true,
	})
	if err != nil {
		t.Fatalf("non-strict dial should succeed via fallback, got: %v", err)
	}
	defer conn.Close()
	if accepts.Load() != 1 {
		t.Fatalf("server saw %d connections, want 1 (fallback dial)", accepts.Load())
	}
}

// TestDialStrictUsesPastedConfig: a pasted config replaces the DoH fetch
// entirely — the DoH server is never queried — and strict mode still
// refuses when the server rejects ECH.
func TestDialStrictUsesPastedConfig(t *testing.T) {
	answer := dohAnswer(`1 . ech=` + testECHBase64)
	var dohHits atomic.Int32
	dohSrv := testDoHServer(t, answer, http.StatusOK, &dohHits)
	defer dohSrv.Close()
	oldEndpoint := dohEndpoint
	dohEndpoint = dohSrv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	cert := selfSignedLocalhostCert(t)
	port, accepts := countingTLSServer(t, cert)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := DialStealthTunnel(ctx, StealthDialConfig{
		Route:              strictTestRoute(port, "strict-pasted.example"),
		FragDelayMs:        1,
		AllowInsec:         true,
		ECHEnabled:         true,
		ECHRequired:        true,
		ECHConfigB64:       testECHBase64,
		ECHRejectionVerify: func(utls.ConnectionState) error { return nil },
	})
	if err == nil {
		t.Fatal("strict dial with a pasted config should fail when the server rejects ECH")
	}
	if !strings.Contains(err.Error(), "strict ECH required") {
		t.Fatalf("error should name strict mode, got: %v", err)
	}
	if dohHits.Load() != 0 {
		t.Fatalf("DoH was queried %d times, want 0 (pasted config replaces the fetch)", dohHits.Load())
	}
	if accepts.Load() != 1 {
		t.Fatalf("server saw %d connections, want 1 (strict mode must not retry without ECH)", accepts.Load())
	}
}

// TestDialStrictRequiresECHEnabled: strict mode without ECH enabled is a
// contradiction — the dialer must refuse rather than silently dial plain.
func TestDialStrictRequiresECHEnabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := DialStealthTunnel(ctx, StealthDialConfig{
		Route:       strictTestRoute(443, "strict-noech.example"),
		ECHEnabled:  false,
		ECHRequired: true,
	})
	if err == nil {
		t.Fatal("strict mode without ECH enabled should fail")
	}
	if !strings.Contains(err.Error(), "strict ECH required but ECH is not enabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}
