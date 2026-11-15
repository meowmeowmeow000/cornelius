package scanner

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// verifyTimeout bounds the whole WebSocket + SMUX verification, and
// nopResend is how often the NOP is re-sent while waiting for echoes.
// Aether's scanner learned this the hard way (v2.1.0): a data-plane probe
// sent once and never repeated means a single lost packet costs the whole
// per-probe budget instead of 700 ms. Cornelius's NOP echo had exactly
// that failure mode — one NOP, one chance, up to 8 s wasted.
const (
	verifyTimeout   = 8 * time.Second
	nopResend       = 700 * time.Millisecond
	nopEchoesNeeded = 2
)

// verifyTunnel checks the full path, not just the TLS handshake: it performs
// the WebSocket upgrade at wsPath and waits for SMUX NOP echoes. A route
// that handshakes but cannot upgrade (wrong path, dead Worker, 403) must
// never be promoted to primary — that is exactly how the tunnel used to
// fail while the scanner called the edge "clean".
//
// It returns (verified, reason). reason is "" on success and names the
// failure otherwise, so the doctor and the strategist can tell a route
// that handshakes but passes no traffic ("no-traffic") from one that never
// handshakes at all:
//   - "upgrade": no WebSocket 101 (wrong path, 403, dead Worker)
//   - "no-traffic": upgraded, but no SMUX echo before the deadline
//   - "closed": the connection errored after the upgrade
//
// conn is the post-handshake TLS connection. It is left open for the caller
// to close; this function never closes it. On success the connection
// deadline is restored to the verification deadline, as before.
func verifyTunnel(ctx context.Context, conn net.Conn, host, wsPath string) (bool, string) {
	deadline := time.Now().Add(verifyTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		return false, "closed"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36\r\n\r\n",
		wsPath, host, base64.StdEncoding.EncodeToString(keyBytes[:]))
	if _, err := conn.Write([]byte(req)); err != nil {
		return false, "closed"
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		return false, "upgrade"
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return false, "upgrade"
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// SMUX NOP frame: [version=1][cmd=3][len=0 LE][stream=0 LE].
	// Sent once now, then re-sent every nopResend until nopEchoesNeeded
	// echoes arrive — one lost NOP must not cost the whole probe.
	nop := []byte{0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if err := writeWSBinary(conn, nop); err != nil {
		return false, "closed"
	}
	echoes := 0
	resend := time.NewTicker(nopResend)
	defer resend.Stop()
	for {
		// Short read window so the resend ticker gets checked
		// regularly; a blocking read would stall resends entirely.
		// NOTE: SetDeadline covers writes too, so the deadline must be
		// refreshed before every resend write — a write attempted
		// under an already-expired read deadline fails instantly.
		readDeadline := time.Now().Add(100 * time.Millisecond)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		_ = conn.SetDeadline(readDeadline)
		msg, err := readWSMessage(br, conn)
		if err == nil {
			if len(msg) == 8 && msg[0] == 0x01 && msg[1] == 0x03 {
				echoes++
				if echoes >= nopEchoesNeeded {
					// Restore the verification deadline for the
					// caller's later use of the connection.
					_ = conn.SetDeadline(deadline)
					return true, ""
				}
			}
			// Any other message (e.g. a stray FIN) is not the echo;
			// keep waiting until the deadline.
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			if time.Now().After(deadline) || ctx.Err() != nil {
				return false, "no-traffic"
			}
			select {
			case <-resend.C:
				_ = conn.SetDeadline(deadline)
				if err := writeWSBinary(conn, nop); err != nil {
					return false, "closed"
				}
			default:
			}
			continue
		}
		return false, "closed"
	}
}

// writeWSBinary sends payload as one masked RFC 6455 binary frame, as a
// client must.
func writeWSBinary(w io.Writer, payload []byte) error {
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	frame := make([]byte, 0, len(payload)+14)
	frame = append(frame, 0x82) // FIN + binary opcode
	switch {
	case len(payload) <= 125:
		frame = append(frame, 0x80|byte(len(payload)))
	case len(payload) <= 65535:
		frame = append(frame, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, 0x80|127)
		var lb [8]byte
		binary.BigEndian.PutUint64(lb[:], uint64(len(payload)))
		frame = append(frame, lb[:]...)
	}
	frame = append(frame, mask[:]...)
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	frame = append(frame, masked...)
	_, err := w.Write(frame)
	return err
}

// readWSMessage reads one WebSocket message, answering pings with pongs.
func readWSMessage(br *bufio.Reader, w io.Writer) ([]byte, error) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return nil, err
		}
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		length := uint64(hdr[1] & 0x7F)
		if length == 126 {
			var ext [2]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				return nil, err
			}
			length = uint64(binary.BigEndian.Uint16(ext[:]))
		} else if length == 127 {
			var ext [8]byte
			if _, err := io.ReadFull(br, ext[:]); err != nil {
				return nil, err
			}
			length = binary.BigEndian.Uint64(ext[:])
		}
		if length > 16*1024*1024 {
			return nil, errors.New("websocket frame exceeds 16MB limit")
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(br, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(br, payload); err != nil {
				return nil, err
			}
			if masked {
				for i := range payload {
					payload[i] ^= mask[i&3]
				}
			}
		}
		switch opcode {
		case 0x08:
			return nil, io.EOF
		case 0x09: // ping: answer with a pong and keep reading
			pong := []byte{0x8A, byte(len(payload))}
			pong = append(pong, payload...)
			_, _ = w.Write(pong)
			continue
		case 0x0A: // pong: ignore
			continue
		case 0x00, 0x01, 0x02:
			return payload, nil
		default:
			continue
		}
	}
}
