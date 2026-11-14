package scanner

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeWorker answers a WebSocket upgrade and echoes SMUX NOPs, like the
// real Cloudflare Worker in worker/worker.js.
func runFakeWorker(t *testing.T, server net.Conn, status string) {
	t.Helper()
	br := bufio.NewReader(server)
	go func() {
		defer server.Close()
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = server.Write([]byte("HTTP/1.1 " + status + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		if !strings.Contains(status, "101") {
			return
		}
		for {
			msg, err := readWSMessage(br, server)
			if err != nil {
				return
			}
			if len(msg) == 8 && msg[0] == 0x01 && msg[1] == 0x03 {
				// Unmasked server binary frame with the NOP echo.
				frame := []byte{0x82, 0x08}
				frame = append(frame, msg...)
				if _, err := server.Write(frame); err != nil {
					return
				}
			}
		}
	}()
}

func TestVerifyTunnelEchoesNOP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	runFakeWorker(t, server, "101 Switching Protocols")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !verifyTunnel(ctx, client, "worker.example.workers.dev", "/secret-knock-99") {
		t.Fatal("verifyTunnel() = false, want true for a Worker that echoes NOP")
	}
}

func TestVerifyTunnelRejectsBadUpgrade(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	runFakeWorker(t, server, "404 Not Found")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if verifyTunnel(ctx, client, "worker.example.workers.dev", "/secret-knock-99") {
		t.Fatal("verifyTunnel() = true, want false for a 404 upgrade")
	}
}

func TestWSBinaryRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	want := []byte{0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	errCh := make(chan error, 1)
	go func() { errCh <- writeWSBinary(client, want) }()
	got, err := readWSMessage(bufio.NewReader(server), server)
	if err != nil {
		t.Fatalf("readWSMessage() error: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("writeWSBinary() error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("round-trip mismatch: got %v, want %v", got, want)
	}
}
