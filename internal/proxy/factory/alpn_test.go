package factory

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"cornelius/internal/config"
)

// TestForceHTTP11Spec locks the ALPN fix: every fingerprint the dialer
// can use must offer http/1.1 and nothing else, so the server cannot
// pick h2. Before the fix the Chrome specs offered ["h2", "http/1.1"]
// and Config.NextProtos was silently overwritten by the fingerprint.
func TestForceHTTP11Spec(t *testing.T) {
	ids := map[string]utls.ClientHelloID{
		"chrome_131":   utls.HelloChrome_131,
		"chrome_133":   utls.HelloChrome_133,
		"chrome_auto":  utls.HelloChrome_Auto,
		"firefox_auto": utls.HelloFirefox_Auto,
		"ios_auto":     utls.HelloIOS_Auto,
		"edge_auto":    utls.HelloEdge_Auto,
	}
	for name, id := range ids {
		spec, err := forceHTTP11Spec(id)
		if err != nil {
			t.Fatalf("%s: forceHTTP11Spec: %v", name, err)
		}
		var alpns [][]string
		for _, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpns = append(alpns, alpn.AlpnProtocols)
			}
		}
		if len(alpns) != 1 {
			t.Fatalf("%s: got %d ALPN extensions, want 1", name, len(alpns))
		}
		if len(alpns[0]) != 1 || alpns[0][0] != "http/1.1" {
			t.Fatalf("%s: ALPN = %v, want [http/1.1]", name, alpns[0])
		}
		if len(spec.CipherSuites) == 0 {
			t.Fatalf("%s: spec lost its cipher suites", name)
		}
	}
}

// TestDialNegotiatesHTTP11 proves the fix end to end: a server offering
// h2 first still negotiates http/1.1 with the dialer, because the
// ClientHello offers only http/1.1. Before the fix the server picked
// h2, and the HTTP/1.1 WebSocket upgrade over that session died with
// EOF — the doctor failure on every edge, and ws_verified=false on
// every scanned route.
func TestDialNegotiatesHTTP11(t *testing.T) {
	cert := selfSignedLocalhostCert(t)
	negotiated := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tc := conn.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					return
				}
				negotiated <- tc.ConnectionState().NegotiatedProtocol
			}(c)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	route := config.RouteCandidate{
		TargetIP:    "127.0.0.1",
		TargetPort:  uint16(port),
		CleanSNI:    "localhost",
		StealthMode: ModeTLSFrag,
		Fingerprint: "chrome_auto",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := DialStealthTunnel(ctx, StealthDialConfig{
		Route:      route,
		AllowInsec: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	select {
	case proto := <-negotiated:
		if proto != "http/1.1" {
			t.Fatalf("negotiated ALPN = %q, want http/1.1", proto)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never reported a negotiated protocol")
	}
}
