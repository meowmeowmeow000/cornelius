package mockworker

import (
	"bufio"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// These tests pin the mock's fidelity to the real Worker (worker.js):
// the upgrade-header check, NOP echo, FIN on target close, first-PSH
// rest forwarding, and the frame-length guard. Each was a real
// divergence found by the round-12 Gemini review.

func TestServeConnRequiresUpgradeHeaders(t *testing.T) {
	srv, err := Start("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cases := []struct {
		name       string
		upgrade    bool
		connection bool
		wantStatus string
	}{
		{"no Upgrade header", false, true, "404"},
		{"no Connection header", true, false, "404"},
		{"both headers", true, true, "101"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", srv.Addr(), &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var sb strings.Builder
			sb.WriteString("GET /secret-knock-99 HTTP/1.1\r\nHost: localhost\r\n")
			if tc.upgrade {
				sb.WriteString("Upgrade: websocket\r\n")
			}
			if tc.connection {
				sb.WriteString("Connection: Upgrade\r\n")
			}
			sb.WriteString("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
			if _, err := conn.Write([]byte(sb.String())); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			br := bufio.NewReader(conn)
			status, err := br.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(status, tc.wantStatus) {
				t.Fatalf("status line = %q, want it to contain %s", status, tc.wantStatus)
			}
		})
	}
}

func TestRelayEchoesNOP(t *testing.T) {
	ln := startEchoTarget(t)
	srv, err := Start(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, br := upgradeConn(t, srv)
	writeMaskedFrame(t, conn, smuxFrame(cmdNOP, 0, nil))
	frame := readFrame(t, br, 2*time.Second)
	if len(frame) < 2 || frame[0] != smuxVersion || frame[1] != cmdNOP {
		t.Fatalf("echoed frame = %x, want a SMUX NOP", frame)
	}
}

func TestRelaySendsFINOnTargetClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	srv, err := Start(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, br := upgradeConn(t, srv)
	writeMaskedFrame(t, conn, smuxFrame(cmdPSH, 1, targetHeader("127.0.0.1", 80)))
	deadline := time.Now().Add(2 * time.Second)
	for {
		frame := readFrame(t, br, time.Until(deadline))
		if len(frame) >= smuxHdrSize && frame[0] == smuxVersion && frame[1] == cmdFIN &&
			binary.LittleEndian.Uint32(frame[4:8]) == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no FIN for stream 1 after the target closed, last frame = %x", frame)
		}
	}
}

func TestRelayForwardsPiggybackedData(t *testing.T) {
	ln := startEchoTarget(t)
	srv, err := Start(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, br := upgradeConn(t, srv)
	// First PSH carries the header AND application bytes, like a
	// fast-open write would. The mock must forward the bytes after the
	// header to the target, as the real Worker forwards target.rest.
	payload := append(targetHeader("127.0.0.1", 80), []byte("hello")...)
	writeMaskedFrame(t, conn, smuxFrame(cmdPSH, 1, payload))
	deadline := time.Now().Add(2 * time.Second)
	for {
		frame := readFrame(t, br, time.Until(deadline))
		if len(frame) >= smuxHdrSize && frame[0] == smuxVersion && frame[1] == cmdPSH &&
			string(frame[smuxHdrSize:]) == "hello" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("piggybacked bytes were not echoed back, last frame = %x", frame)
		}
	}
}

func TestReadWSFrameRejectsHugeLength(t *testing.T) {
	srv, err := Start("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, br := upgradeConnRaw(t, srv)
	// 0x82 0xFF: masked, length 127; eight 0xFF ext bytes make the
	// length -1 as int64. Without the guard, make([]byte, -1) panics
	// and crashes the whole test process; with it, the relay returns
	// an error and closes the connection.
	raw := []byte{0x82, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	// The relay must fail fast and close the connection — not block
	// (which would surface here as the 2s read deadline expiring).
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("connection stayed open after the malformed frame, want it closed")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("connection took %v to close after the malformed frame, want < 1s", elapsed)
	}
}

func startEchoTarget(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln
}

// upgradeConn dials the mock, completes the upgrade, and returns the
// connection (for writing frames) and the buffered reader positioned at
// the first WebSocket frame.
func upgradeConn(t *testing.T, srv *Server) (net.Conn, *bufio.Reader) {
	t.Helper()
	return upgradeConnRaw(t, srv)
}

func upgradeConnRaw(t *testing.T, srv *Server) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := tls.Dial("tcp", srv.Addr(), &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	req := "GET /secret-knock-99 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade status line = %q, want 101", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, br
}

func readFrame(t *testing.T, br *bufio.Reader, timeout time.Duration) []byte {
	t.Helper()
	if timeout <= 0 {
		t.Fatal("readFrame timed out waiting for a frame")
	}
	// The conn's read deadline (set by upgradeConnRaw, 2s from the
	// upgrade) bounds this read; a timeout surfaces as an error here.
	frame, err := readWSFrame(br)
	if err != nil {
		t.Fatalf("reading a frame: %v", err)
	}
	return frame
}

func writeMaskedFrame(t *testing.T, w io.Writer, payload []byte) {
	t.Helper()
	if len(payload) > 125 {
		t.Fatalf("test helper only writes short frames, got %d bytes", len(payload))
	}
	var mask [4]byte
	if _, err := cryptorand.Read(mask[:]); err != nil {
		t.Fatal(err)
	}
	frame := []byte{0x82, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	frame = append(frame, masked...)
	if _, err := w.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func smuxFrame(cmd byte, id uint32, payload []byte) []byte {
	f := make([]byte, smuxHdrSize+len(payload))
	f[0] = smuxVersion
	f[1] = cmd
	binary.LittleEndian.PutUint16(f[2:4], uint16(len(payload)))
	binary.LittleEndian.PutUint32(f[4:8], id)
	copy(f[smuxHdrSize:], payload)
	return f
}

func targetHeader(host string, port uint16) []byte {
	h := make([]byte, 1+len(host)+2)
	h[0] = byte(len(host))
	copy(h[1:], host)
	binary.BigEndian.PutUint16(h[1+len(host):], port)
	return h
}
