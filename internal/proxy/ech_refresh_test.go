package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cornelius/internal/proxy/factory"
)

// The real ECH config for bold-heart-a6e2.nedaymarg.workers.dev, as
// published in its DNS HTTPS record (fetched 2026-11-14). Public name:
// cloudflare-ech.com. Duplicated from the factory tests: this package
// cannot import them.
const testECHBase64 = "AEX+DQBBZQAgACAOj1t+953ib/8pSWcLg5LSAYErxMb1kJVE0R3m/XdmagAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

// readWSFrame reads one WebSocket frame. Client frames are masked;
// server frames are not.
func readWSFrame(br *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, err
	}
	masked := hdr[1]&0x80 != 0
	length := int64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return nil, err
		}
		length = int64(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, nil
}

// writeWSFrame writes one unmasked server binary frame.
func writeWSFrame(w io.Writer, payload []byte) error {
	var hdr []byte
	hdr = append(hdr, 0x82)
	switch {
	case len(payload) < 126:
		hdr = append(hdr, byte(len(payload)))
	case len(payload) <= 0xffff:
		hdr = append(hdr, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		hdr = append(hdr, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		hdr = append(hdr, ext[:]...)
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// relayFakeWorker answers the WebSocket upgrade, then relays every SMUX
// stream to targetAddr — a small stand-in for worker/worker.js, which
// dials the target from the stream's target header. Here every stream
// goes to the same test DoH server, which is all the test needs: the
// point is proving bytes flow session -> stream -> relay -> DoH server
// and back, not the Worker's target selection.
func relayFakeWorker(t *testing.T, server net.Conn, targetAddr string) {
	t.Helper()
	br := bufio.NewReader(server)
	var writeMu sync.Mutex
	streams := map[uint32]net.Conn{}
	var streamsMu sync.Mutex
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
		var rxBuf []byte
		for {
			msg, err := readWSFrame(br)
			if err != nil {
				return
			}
			rxBuf = append(rxBuf, msg...)
			for len(rxBuf) >= smuxHdrSize {
				if rxBuf[0] != smuxVersion {
					return
				}
				cmd := rxBuf[1]
				length := int(binary.LittleEndian.Uint16(rxBuf[2:4]))
				streamID := binary.LittleEndian.Uint32(rxBuf[4:8])
				if len(rxBuf) < smuxHdrSize+length {
					break
				}
				payload := append([]byte(nil), rxBuf[smuxHdrSize:smuxHdrSize+length]...)
				rxBuf = rxBuf[smuxHdrSize+length:]
				switch cmd {
				case cmdSYN: // nothing to do until the target header arrives
				case cmdPSH:
					streamsMu.Lock()
					target, ok := streams[streamID]
					streamsMu.Unlock()
					if !ok {
						// First PSH carries the target header.
						if len(payload) < 3 {
							continue
						}
						target, err = net.Dial("tcp", targetAddr)
						if err != nil {
							return
						}
						streamsMu.Lock()
						streams[streamID] = target
						streamsMu.Unlock()
						go func(id uint32, tc net.Conn) {
							defer tc.Close()
							buf := make([]byte, 16384)
							for {
								n, err := tc.Read(buf)
								if n > 0 {
									frame := make([]byte, smuxHdrSize+n)
									frame[0] = smuxVersion
									frame[1] = cmdPSH
									binary.LittleEndian.PutUint16(frame[2:4], uint16(n))
									binary.LittleEndian.PutUint32(frame[4:8], id)
									copy(frame[smuxHdrSize:], buf[:n])
									writeMu.Lock()
									werr := writeWSFrame(server, frame)
									writeMu.Unlock()
									if werr != nil {
										return
									}
								}
								if err != nil {
									return
								}
							}
						}(streamID, target)
						continue
					}
					if _, err := target.Write(payload); err != nil {
						return
					}
				case cmdFIN:
					streamsMu.Lock()
					if target, ok := streams[streamID]; ok {
						_ = target.Close()
						delete(streams, streamID)
					}
					streamsMu.Unlock()
				case cmdNOP: // keepalive — ignore
				}
			}
		}
	}()
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
