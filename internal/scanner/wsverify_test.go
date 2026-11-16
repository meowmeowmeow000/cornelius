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
	ok, reason := verifyTunnel(ctx, client, "worker.example.workers.dev", "/secret-knock-99")
	if !ok || reason != "" {
		t.Fatalf("verifyTunnel() = (%v, %q), want (true, \"\")", ok, reason)
	}
}

func TestVerifyTunnelRejectsBadUpgrade(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	runFakeWorker(t, server, "404 Not Found")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, reason := verifyTunnel(ctx, client, "worker.example.workers.dev", "/secret-knock-99")
	if ok || reason != "upgrade" {
		t.Fatalf("verifyTunnel() = (%v, %q), want (false, \"upgrade\")", ok, reason)
	}
}

// runLossyFakeWorker answers the upgrade and then echoes every NOP after
// the first dropFirst — simulating a lossy path that swallows probes.
func runLossyFakeWorker(t *testing.T, server net.Conn, dropFirst int) {
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
		_, _ = server.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		seen := 0
		for {
			msg, err := readWSMessage(br, server)
			if err != nil {
				return
			}
			if len(msg) == 8 && msg[0] == 0x01 && msg[1] == 0x03 {
				seen++
				if seen <= dropFirst {
					continue // packet "lost" — no echo
				}
				frame := []byte{0x82, 0x08}
				frame = append(frame, msg...)
				if _, err := server.Write(frame); err != nil {
					return
				}
			}
		}
	}()
}

func TestVerifyTunnelResendsUntilSecondEcho(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// Drop the first NOP: with the old send-once code this probe would
	// have burned its whole budget and failed.
	runLossyFakeWorker(t, server, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	ok, reason := verifyTunnel(ctx, client, "worker.example.workers.dev", "/secret-knock-99")
	if !ok || reason != "" {
		t.Fatalf("verifyTunnel() = (%v, %q), want (true, \"\") after resend", ok, reason)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("verifyTunnel took %v; the resend should have succeeded in ~1.5s", elapsed)
	}
}

func TestVerifyTunnelNeedsTwoEchoes(t *testing.T) {
	// Echo exactly one NOP, then go silent: one echo must NOT be enough.
	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()
	go func() {
		defer server2.Close()
		br := bufio.NewReader(server2)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = server2.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		echoed := false
		for {
			msg, err := readWSMessage(br, server2)
			if err != nil {
				return
			}
			if len(msg) == 8 && msg[0] == 0x01 && msg[1] == 0x03 && !echoed {
				echoed = true
				frame := []byte{0x82, 0x08}
				frame = append(frame, msg...)
				if _, err := server2.Write(frame); err != nil {
					return
				}
			}
			// Later NOPs are read and swallowed, never echoed.
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, reason := verifyTunnel(ctx, client2, "worker.example.workers.dev", "/secret-knock-99")
	if ok || reason != "no-traffic" {
		t.Fatalf("verifyTunnel() = (%v, %q), want (false, \"no-traffic\") with only one echo", ok, reason)
	}
}

func TestVerifyTunnelNoTraffic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// Upgrade succeeds but the Worker never speaks SMUX: handshake ok,
	// no traffic. The reason must say so.
	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = server.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		// Read and discard NOPs forever, echo nothing.
		for {
			if _, err := readWSMessage(br, server); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, reason := verifyTunnel(ctx, client, "worker.example.workers.dev", "/secret-knock-99")
	if ok || reason != "no-traffic" {
		t.Fatalf("verifyTunnel() = (%v, %q), want (false, \"no-traffic\")", ok, reason)
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
