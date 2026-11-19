// Package mockworker is a fake Cloudflare Worker for tests.
//
// It speaks the real tunnel protocol end to end: TLS (self-signed cert
// for localhost), the WebSocket upgrade on the secret path, then SMUX v1
// frames relayed to a target address — the same shape as worker/worker.js.
// It deliberately does NOT speak ECH: the dialer under test runs with ECH
// off, so no DoH fetch and no ECH config are involved.
//
// Test-only: no production code imports this package. The relay core here
// is the single fake Worker in the repo — the old relayFakeWorker in the
// proxy tests is a thin wrapper over ServeConn.
package mockworker

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// DefaultWSPath is the secret WebSocket path, matching the shipped
// combat.profile. A request to any other path gets a 404, like the real
// Worker (Cloudflare would 404 a wrong path before the upgrade).
const DefaultWSPath = "/secret-knock-99"

const (
	smuxVersion = 1
	cmdSYN      = 0
	cmdFIN      = 1
	cmdPSH      = 2
	cmdNOP      = 3
	cmdRST      = 4 // full close; FIN is half-close only
	smuxHdrSize = 8
)

// mockStream is one relayed stream: the target connection plus the state
// of its two halves (guarded by relaySMUX's streamsMu).
type mockStream struct {
	conn      net.Conn
	readDone  bool // target sent EOF; we sent FIN to the client
	writeDone bool // client sent FIN; target's write side is closed
}

// Server is a running fake Worker listening on 127.0.0.1 with an
// ephemeral port. Use Addr or Port to point a route at it.
type Server struct {
	ln         net.Listener
	targetAddr string
	wsPath     string

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	done   chan struct{}
	wg     sync.WaitGroup
}

// Start launches a fake Worker relaying every SMUX stream to targetAddr.
// The server speaks TLS with a self-signed cert for localhost, so dialers
// must run with AllowInsecureCerts (InsecureSkipVerify).
func Start(targetAddr string) (*Server, error) {
	return StartWithPath(targetAddr, DefaultWSPath)
}

// StartWithPath is Start with an explicit WebSocket path.
func StartWithPath(targetAddr, wsPath string) (*Server, error) {
	cert, err := selfSignedLocalhostCert()
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return nil, err
	}
	s := &Server{
		ln:         ln,
		targetAddr: targetAddr,
		wsPath:     wsPath,
		conns:      make(map[net.Conn]struct{}),
		done:       make(chan struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// Addr returns the listen address, e.g. "127.0.0.1:41235".
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Port returns the ephemeral listen port.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// Close stops accepting and closes every open connection.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	_ = s.ln.Close()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			ServeConn(conn, s.targetAddr, s.wsPath)
		}()
	}
}

// ServeConn serves one already-accepted connection: it reads the HTTP
// upgrade request, answers 101 on the right path (404 otherwise), then
// relays SMUX streams to targetAddr until the connection ends. Blocking;
// callers run it in a goroutine. This is the relay core the proxy tests
// used to carry inline; it lives here so every test fake is the same fake.
func ServeConn(conn net.Conn, targetAddr, wsPath string) {
	// Closing here is load-bearing: when the relay exits, the peer's
	// pending writes must fail fast instead of blocking forever on a
	// connection nobody reads anymore (the old inline relay closed the
	// conn on return too; dropping that close deadlocked the
	// through-tunnel test under -race).
	defer conn.Close()
	br := bufio.NewReader(conn)
	// Read the upgrade request headers. The same reader must be used for
	// the WebSocket frames afterwards: it may already hold frame bytes.
	var reqLine string
	headers := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if reqLine == "" {
			reqLine = strings.TrimSpace(line)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if i := strings.Index(line, ":"); i > 0 {
			headers[strings.ToLower(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}
	parts := strings.Fields(reqLine)
	// The real Worker 404s anything without the WebSocket upgrade
	// headers; a mock that answered 101 regardless would let a dialer
	// regression (dropping the Upgrade header) pass here and fail
	// against Cloudflare.
	if len(parts) < 2 || parts[0] != "GET" || parts[1] != wsPath ||
		!strings.EqualFold(headers["upgrade"], "websocket") ||
		!strings.Contains(strings.ToLower(headers["connection"]), "upgrade") {
		_, _ = conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); err != nil {
		return
	}
	relaySMUX(conn, br, targetAddr)
}

// relaySMUX runs the SMUX frame loop: SYN opens nothing until the target
// header arrives on the first PSH; later PSHs carry stream bytes; FIN
// half-closes the target (write side only, like the real Worker); RST
// closes it fully; NOP is a keepalive. Every stream dials targetAddr —
// the fake does not implement the Worker's target selection, it proves
// bytes flow session -> stream -> relay -> target and back.
func relaySMUX(server net.Conn, br *bufio.Reader, targetAddr string) {
	var writeMu sync.Mutex
	streams := map[uint32]*mockStream{}
	var streamsMu sync.Mutex
	defer func() {
		streamsMu.Lock()
		for _, ms := range streams {
			_ = ms.conn.Close()
		}
		streamsMu.Unlock()
	}()
	// finishLocked drops a stream once both halves are done. Caller holds
	// streamsMu.
	finishLocked := func(id uint32, ms *mockStream) {
		if ms.readDone && ms.writeDone {
			_ = ms.conn.Close()
			if streams[id] == ms {
				delete(streams, id)
			}
		}
	}
	// sendRST tells the client the stream is fully closed — the real
	// Worker's answer to a dial failure, a socket write failure or a broken
	// socket (FIN would claim the stream is still writable).
	sendRST := func(id uint32) {
		rst := make([]byte, smuxHdrSize)
		rst[0] = smuxVersion
		rst[1] = cmdRST
		binary.LittleEndian.PutUint32(rst[4:8], id)
		writeMu.Lock()
		_ = writeWSFrame(server, rst)
		writeMu.Unlock()
	}
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
				ms, ok := streams[streamID]
				streamsMu.Unlock()
				if !ok {
					// First PSH carries the target header:
					// [1-byte hostLen][host][2-byte BE port], then any
					// bytes that arrived after it. The real Worker
					// forwards that rest to the destination
					// (openTarget writes target.rest); dropping it
					// would silently lose data if the client ever
					// piggybacks on the first write.
					if len(payload) < 3 {
						continue
					}
					hostLen := int(payload[0])
					if len(payload) < 1+hostLen+2 {
						continue
					}
					rest := payload[1+hostLen+2:]
					target, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
					if err != nil {
						// The stream is dead; the session is not.
						// Answering RST (instead of returning)
						// keeps one dead target from killing every
						// other stream on the session.
						sendRST(streamID)
						continue
					}
					ms = &mockStream{conn: target}
					streamsMu.Lock()
					streams[streamID] = ms
					streamsMu.Unlock()
					go func(id uint32, ms *mockStream) {
						tc := ms.conn
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
								streamsMu.Lock()
								live := streams[id] == ms
								streamsMu.Unlock()
								if !live {
									// Already torn down (client RST, or a
									// write failure that sent its own RST).
									return
								}
								if err != io.EOF {
									// Broken socket, not a clean EOF: RST,
									// like the real Worker's pump error path.
									streamsMu.Lock()
									_ = tc.Close()
									delete(streams, id)
									streamsMu.Unlock()
									sendRST(id)
									return
								}
								// Target closed its side: send FIN (a
								// half-close, like the real Worker's
								// pumpSocketToClient) and keep the stream
								// until the client has half-closed too, so
								// a client bug in FIN handling cannot pass
								// against the mock and fail against the
								// real Worker.
								fin := make([]byte, smuxHdrSize)
								fin[0] = smuxVersion
								fin[1] = cmdFIN
								binary.LittleEndian.PutUint32(fin[4:8], id)
								writeMu.Lock()
								_ = writeWSFrame(server, fin)
								writeMu.Unlock()
								streamsMu.Lock()
								ms.readDone = true
								finishLocked(id, ms)
								streamsMu.Unlock()
								return
							}
						}
					}(streamID, ms)
					if len(rest) > 0 {
						if _, err := target.Write(rest); err != nil {
							streamsMu.Lock()
							_ = target.Close()
							delete(streams, streamID)
							streamsMu.Unlock()
							sendRST(streamID)
							continue
						}
					}
					continue
				}
				streamsMu.Lock()
				wd := ms.writeDone
				streamsMu.Unlock()
				if wd {
					continue // write side already half-closed: drop late data
				}
				if _, err := ms.conn.Write(payload); err != nil {
					// The target went away after the stream opened
					// (e.g. the peer sent a late close_notify after
					// the target already closed). Kill the stream,
					// not the relay: a late PSH must not wedge the
					// whole session.
					streamsMu.Lock()
					_ = ms.conn.Close()
					delete(streams, streamID)
					streamsMu.Unlock()
					sendRST(streamID)
					continue
				}
			case cmdFIN:
				// Half-close: only the target's write side ends; its
				// replies keep flowing back until it closes.
				streamsMu.Lock()
				if ms, ok := streams[streamID]; ok && !ms.writeDone {
					if tc, isTCP := ms.conn.(*net.TCPConn); isTCP {
						_ = tc.CloseWrite()
					} else {
						_ = ms.conn.Close()
					}
					ms.writeDone = true
					finishLocked(streamID, ms)
				}
				streamsMu.Unlock()
			case cmdRST:
				streamsMu.Lock()
				if ms, ok := streams[streamID]; ok {
					_ = ms.conn.Close()
					delete(streams, streamID)
				}
				streamsMu.Unlock()
			case cmdNOP: // keepalive — echo it back, like the real Worker,
				// so the client's 25s no-RX watchdog never fires on an
				// idle session. Ignoring it would reap idle sessions
				// against the mock that stay alive against the real
				// Worker.
				frame := make([]byte, smuxHdrSize)
				frame[0] = smuxVersion
				frame[1] = cmdNOP
				writeMu.Lock()
				_ = writeWSFrame(server, frame)
				writeMu.Unlock()
			}
		}
	}
}

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
	// Bound the allocation before reading the mask, like the client's
	// own reader (16MB cap): an 8-byte ext with the high bit set would
	// make length negative and make([]byte, length) would panic,
	// crashing the test process. Checking here also means a malformed
	// frame fails fast instead of blocking on the mask bytes that a
	// well-formed frame of that length would carry.
	if length < 0 || length > 16*1024*1024 {
		return nil, fmt.Errorf("websocket frame length %d out of range", length)
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

func selfSignedLocalhostCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return tls.Certificate{}, err
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
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("build self-signed cert: %w", err)
	}
	return cert, nil
}
