package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cornelius/internal/mockworker"
	"cornelius/internal/proxy/factory"
)

// The real ECH config for bold-heart-a6e2.nedaymarg.workers.dev, as
// published in its DNS HTTPS record (fetched 2026-11-14). Public name:
// cloudflare-ech.com. Duplicated from the factory tests: this package
// cannot import them.
const testECHBase64 = "AEX+DQBBZQAgACAOj1t+953ib/8pSWcLg5LSAYErxMb1kJVE0R3m/XdmagAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

// relayFakeWorker answers the WebSocket upgrade, then relays every SMUX
// stream to targetAddr — a small stand-in for worker/worker.js, which
// dials the target from the stream's target header. Here every stream
// goes to the same test DoH server, which is all the test needs: the
// point is proving bytes flow session -> stream -> relay -> DoH server
// and back, not the Worker's target selection. The relay itself lives in
// internal/mockworker now, so this is the same fake the end-to-end tests
// use — not a second one.
func relayFakeWorker(t *testing.T, server net.Conn, targetAddr string) {
	t.Helper()
	go mockworker.ServeConn(server, targetAddr, mockworker.DefaultWSPath)
}

// doWSUpgrade performs the client side of the WebSocket upgrade, the way
// the dialer does it before handing the conn to a session. It reads the
// response one byte at a time: a buffered reader could swallow the first
// frame bytes that follow the upgrade.
func doWSUpgrade(t *testing.T, conn net.Conn, host, path string) {
	t.Helper()
	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		t.Fatal(err)
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, host, base64.StdEncoding.EncodeToString(keyBytes[:]))
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	var resp []byte
	one := make([]byte, 1)
	for !strings.HasSuffix(string(resp), "\r\n\r\n") {
		n, err := conn.Read(one)
		if err != nil {
			t.Fatal(err)
		}
		resp = append(resp, one[:n]...)
		if len(resp) > 4096 {
			t.Fatal("upgrade response too large")
		}
	}
	if !strings.Contains(string(resp), "101") {
		t.Fatalf("upgrade status = %q, want 101", strings.TrimSpace(string(resp)))
	}
}

// TestFetchECHConfigThroughConn proves the whole through-tunnel path:
// a SMUX session over a fake Worker relays one stream to a DoH server,
// and the fetched config is the real published one.
func TestFetchECHConfigThroughConn(t *testing.T) {
	answer := `{"Status":0,"Answer":[{"name":"h.example","type":65,"TTL":300,"data":"1 . ech=` + testECHBase64 + `"}]}`
	dohSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(answer))
	}))
	defer dohSrv.Close()

	// The test DoH server's cert is self-signed; the production config
	// verifies against the system roots.
	oldTLS := overConnTLSConfig
	overConnTLSConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	defer func() { overConnTLSConfig = oldTLS }()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	relayFakeWorker(t, server, dohSrv.Listener.Addr().String())
	doWSUpgrade(t, client, "worker.example.workers.dev", "/secret-knock-99")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	list, ttl, err := FetchECHConfigThroughConn(ctx, client, "through-conn.example")
	if err != nil {
		t.Fatalf("fetch through the tunnel failed: %v", err)
	}
	want, _ := base64.StdEncoding.DecodeString(testECHBase64)
	if string(list) != string(want) {
		t.Fatal("fetched list does not match the published config")
	}
	if ttl != 300*time.Second {
		t.Fatalf("ttl = %v, want 300s", ttl)
	}
}

func TestNeedsECHRefresh(t *testing.T) {
	if !needsECHRefresh(true, "refresh-needed.example") {
		t.Fatal("expected a refresh when ECH is on and nothing is cached")
	}
	if needsECHRefresh(false, "refresh-needed.example") {
		t.Fatal("no refresh when ECH is off")
	}
	if needsECHRefresh(true, "") {
		t.Fatal("no refresh with no host")
	}
	want, _ := base64.StdEncoding.DecodeString(testECHBase64)
	factory.StoreECHConfig("refresh-needed.example", want, 300*time.Second)
	if needsECHRefresh(true, "refresh-needed.example") {
		t.Fatal("no refresh when a fresh config is cached")
	}
}
