package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"cornelius/internal/proxy/pool"
	"cornelius/internal/telemetry"
)

const (
	smuxVersion = 1
	cmdSYN      = 0
	cmdFIN      = 1
	cmdPSH      = 2
	cmdNOP      = 3
	cmdRST      = 4 // full close of both directions; FIN (1) is half-close only
	smuxHdrSize = 8
	maxChunk    = 16384
)

type wsConn struct {
	raw     net.Conn
	writeMu sync.Mutex
	readMu  sync.Mutex
}

func (w *wsConn) WriteBinary(payload []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.writeFrameLocked(0x82, payload) // FIN + binary opcode
}

// WritePong answers a ping with a pong carrying the same payload. It is
// best-effort by design: it is called from ReadMessage, which holds
// readMu, so it must never block the read path — if another goroutine is
// mid-write it skips the reply, and the write itself has a short
// deadline so a dead peer cannot stall the reader either. An unanswered
// ping can get the session killed by the edge, but a stalled readLoop
// kills it for certain.
func (w *wsConn) WritePong(payload []byte) {
	if !w.writeMu.TryLock() {
		return
	}
	defer w.writeMu.Unlock()
	_ = w.raw.SetWriteDeadline(time.Now().Add(time.Second))
	defer w.raw.SetWriteDeadline(time.Time{})
	_ = w.writeFrameLocked(0x8A, payload) // FIN + pong opcode
}

// writeFrameLocked writes one masked client frame with the given opcode.
// Callers must hold writeMu.
func (w *wsConn) writeFrameLocked(opcode byte, payload []byte) error {
	// RFC 6455: frames sent by a client MUST be masked, and the peer parses
	// standard WebSocket frames (see ReadMessage). The SMUX payload therefore
	// travels inside a binary frame. Writing raw bytes here used to be a
	// protocol error: a spec-compliant server reads the first SMUX byte as a
	// frame header and the connection dies.
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	frame := make([]byte, 0, len(payload)+14)
	frame = append(frame, opcode)
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
	if _, err := w.raw.Write(frame); err != nil {
		return err
	}
	return nil
}

func (w *wsConn) ReadMessage() ([]byte, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	var hdr [2]byte
	if _, err := io.ReadFull(w.raw, hdr[:]); err != nil {
		return nil, err
	}
	fin := (hdr[0] & 0x80) != 0
	opcode := hdr[0] & 0x0F
	masked := (hdr[1] & 0x80) != 0
	length := uint64(hdr[1] & 0x7F)

	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(w.raw, ext[:]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(w.raw, ext[:]); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > 16*1024*1024 {
		return nil, errors.New("websocket frame exceeds 16MB limit")
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.raw, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(w.raw, payload); err != nil {
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
	case 0x09:
		// Ping: never hand the payload to the SMUX parser — readLoop
		// would parse it as a frame header and kill the session.
		// Answer with a pong (best-effort) and report no message,
		// exactly like pong (0x0A) already does; readLoop skips
		// empty messages.
		w.WritePong(payload)
		return nil, nil
	case 0x0A:
		return nil, nil
	case 0x00, 0x01, 0x02:
		if fin {
			return payload, nil
		}
		return payload, nil
	default:
		return nil, nil
	}
}

func (w *wsConn) Close() error {
	return w.raw.Close()
}

type smuxSession struct {
	ws        *wsConn
	mu        sync.RWMutex
	streams   map[uint32]*smuxStream
	nextID    uint32
	lastRx    atomic.Int64
	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}
}

func newSmuxSession(raw net.Conn) *smuxSession {
	s := &smuxSession{
		ws:      &wsConn{raw: raw},
		streams: make(map[uint32]*smuxStream),
		nextID:  1,
		done:    make(chan struct{}),
	}
	s.lastRx.Store(time.Now().UnixNano())
	go s.readLoop()
	go s.keepaliveLoop()
	return s
}

func (s *smuxSession) sendFrame(cmd byte, streamID uint32, payload []byte) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	frame := make([]byte, smuxHdrSize+len(payload))
	frame[0] = smuxVersion
	frame[1] = cmd
	binary.LittleEndian.PutUint16(frame[2:4], uint16(len(payload)))
	binary.LittleEndian.PutUint32(frame[4:8], streamID)
	copy(frame[smuxHdrSize:], payload)
	return s.ws.WriteBinary(frame)
}

func (s *smuxSession) keepaliveLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, s.lastRx.Load())) > 25*time.Second {
				s.Close()
				return
			}
			if err := s.sendFrame(cmdNOP, 0, nil); err != nil {
				s.Close()
				return
			}
		}
	}
}

func (s *smuxSession) readLoop() {
	defer s.Close()
	var rxBuf []byte
	for {
		msg, err := s.ws.ReadMessage()
		if err != nil {
			return
		}
		if len(msg) == 0 {
			continue
		}
		s.lastRx.Store(time.Now().UnixNano())
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
			case cmdPSH:
				s.mu.RLock()
				st := s.streams[streamID]
				s.mu.RUnlock()
				if st != nil && len(payload) > 0 {
					select {
					case st.rxCh <- payload:
					case <-st.done:
					}
				}
			case cmdFIN:
				// Half-close: the peer will send no more data. Only the
				// read side hits EOF; the stream stays registered so our
				// write side keeps working until Close() (or RST).
				s.mu.RLock()
				st := s.streams[streamID]
				s.mu.RUnlock()
				if st != nil {
					st.closeRead()
				}
			case cmdRST:
				// Full close: both directions are dead, forget the stream.
				s.mu.Lock()
				st := s.streams[streamID]
				delete(s.streams, streamID)
				s.mu.Unlock()
				if st != nil {
					st.closeLocal()
				}
			case cmdNOP:
			}
		}
	}
}

func (s *smuxSession) OpenStream(ctx context.Context, host string, port uint16) (*smuxStream, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("invalid target host length: %d", len(host))
	}

	id := atomic.AddUint32(&s.nextID, 2) - 2
	st := &smuxStream{
		sess:  s,
		id:    id,
		rxCh:  make(chan []byte, 64),
		done:  make(chan struct{}),
		rxEOF: make(chan struct{}),
	}

	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.sendFrame(cmdSYN, id, nil); err != nil {
		st.Close()
		return nil, err
	}

	hdr := make([]byte, 1+len(host)+2)
	hdr[0] = byte(len(host))
	copy(hdr[1:1+len(host)], host)
	binary.BigEndian.PutUint16(hdr[1+len(host):], port)
	if err := s.sendFrame(cmdPSH, id, hdr); err != nil {
		st.Close()
		return nil, err
	}

	select {
	case <-ctx.Done():
		st.Close()
		return nil, ctx.Err()
	default:
	}

	return st, nil
}

func (s *smuxSession) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
		_ = s.ws.Close()
		s.mu.Lock()
		for id, st := range s.streams {
			st.closeLocal()
			delete(s.streams, id)
		}
		s.mu.Unlock()
	})
}

// smuxStream is one multiplexed stream. Its two directions are
// independent (see worker/PROTOCOL.md):
//
//   - read side: ends on the peer's FIN (rxEOF) — Read drains buffered
//     data, then returns io.EOF — or on a full close (done).
//   - write side: ends on CloseWrite() (we sent FIN); Write then fails.
//
// Close() is the full close: it ends both directions and sends RST.
type smuxStream struct {
	sess      *smuxSession
	id        uint32
	rxCh      chan []byte
	pending   []byte
	done      chan struct{} // full close (Close, peer RST, session death)
	rxEOF     chan struct{} // peer half-closed (FIN): no more data will arrive
	wmu       sync.Mutex    // serialises Write against the CloseWrite FIN
	closeOnce sync.Once
	eofOnce   sync.Once
	wcOnce    sync.Once
	wClosed   atomic.Bool // our write side is closed (FIN sent or Close)
}

func (st *smuxStream) Read(p []byte) (int, error) {
	if len(st.pending) > 0 {
		n := copy(p, st.pending)
		st.pending = st.pending[n:]
		return n, nil
	}
	select {
	case chunk := <-st.rxCh:
		n := copy(p, chunk)
		if n < len(chunk) {
			st.pending = chunk[n:]
		}
		return n, nil
	case <-st.done:
	case <-st.rxEOF:
	}
	// Closed or half-closed by the peer: drain what was already buffered
	// (the readLoop enqueues every PSH before it processes the FIN), then
	// report EOF.
	select {
	case chunk := <-st.rxCh:
		n := copy(p, chunk)
		if n < len(chunk) {
			st.pending = chunk[n:]
		}
		return n, nil
	default:
		return 0, io.EOF
	}
}

func (st *smuxStream) Write(p []byte) (int, error) {
	// Fast path: the write side is already closed (CloseWrite or Close).
	// Check before taking wmu — the CloseWrite FIN goroutine holds wmu
	// while it sends, and on a dead peer that send blocks forever, so
	// taking the lock first would wedge a Write after CloseWrite behind
	// it instead of failing at once (this hung the race suite for the
	// full 10m test timeout). The per-chunk check under wmu below is
	// still the ordering guarantee: it catches a CloseWrite that lands
	// after this check, so no PSH can follow a FIN.
	if st.wClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	// wmu orders every PSH before the FIN that CloseWrite sends: the FIN
	// goroutine takes the same lock, and the closed check is repeated per
	// chunk under it, so no PSH can follow a FIN.
	st.wmu.Lock()
	defer st.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		if st.wClosed.Load() {
			return total, io.ErrClosedPipe
		}
		chunk := p
		if len(chunk) > maxChunk {
			chunk = p[:maxChunk]
		}
		if err := st.sess.sendFrame(cmdPSH, st.id, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	if st.wClosed.Load() && total == 0 {
		return 0, io.ErrClosedPipe
	}
	return total, nil
}

// closeLocal is the full close driven by the peer (RST) or the session:
// no frame is sent back.
func (st *smuxStream) closeLocal() {
	st.closeOnce.Do(func() {
		close(st.done)
	})
}

// closeRead records the peer's FIN: the read side hits EOF once the
// buffered data is drained, while the write side stays usable.
func (st *smuxStream) closeRead() {
	st.eofOnce.Do(func() {
		if st.rxEOF != nil {
			close(st.rxEOF)
		}
	})
}

// CloseWrite half-closes the stream: it tells the peer (FIN) that no more
// data will be sent, but keeps the read side open so the peer's reply can
// still be received. It is the smux equivalent of (*net.TCPConn).CloseWrite.
//
// It never blocks on the network. Like Close(), the frame is sent from a
// goroutine: WriteBinary holds the session's writeMu across a blocking raw
// Write, so a synchronous FIN to a peer that stopped reading with a full
// send buffer would block the caller forever (in the SOCKS handler that
// leaks the goroutine and wedges wg.Wait()). The write side is marked
// closed immediately, so a Write after CloseWrite fails at once. The FIN
// goroutine takes wmu, so it is ordered after any Write already in
// progress; a FIN stuck behind a dead peer unblocks when the session
// closes the connection (or the keepalive reaps the silent session).
// Trade-off: CloseWrite always returns nil — a FIN that fails to send is
// not reported to the caller; the session teardown reports it instead.
func (st *smuxStream) CloseWrite() error {
	st.wcOnce.Do(func() {
		st.wClosed.Store(true)
		select {
		case <-st.done:
			return // already fully closed; nothing to tell the peer
		default:
		}
		if st.sess.closed.Load() {
			return
		}
		go func() {
			st.wmu.Lock()
			defer st.wmu.Unlock()
			_ = st.sess.sendFrame(cmdFIN, st.id, nil)
		}()
	})
	return nil
}

// Close fully closes the stream in both directions and sends RST. If both
// halves already finished gracefully (we sent FIN, the peer sent FIN) no
// RST is needed.
func (st *smuxStream) Close() error {
	st.closeOnce.Do(func() {
		close(st.done)
		st.sess.mu.Lock()
		delete(st.sess.streams, st.id)
		st.sess.mu.Unlock()
		bothHalvesDone := st.wClosed.Load()
		if bothHalvesDone {
			select {
			case <-st.rxEOF:
			default:
				bothHalvesDone = false
			}
		}
		st.wClosed.Store(true)
		// Best-effort RST: send it from a goroutine so Close() never
		// blocks on the network. WriteBinary holds writeMu across a
		// blocking raw Write, so a synchronous frame to a peer that
		// stopped reading with a full send buffer would wedge closeOnce
		// (any concurrent Close waits on it) and writeMu (no more frames,
		// including keepalives, could go out on that session). The RST is
		// a courtesy — the peer reaps the stream on session close or
		// silence — and a stuck RST unblocks when the session closes the
		// connection, or when the keepalive reaps the silent session
		// after 25 s (that path needs no writeMu). A session that is
		// already closed gets no RST at all.
		if !bothHalvesDone && !st.sess.closed.Load() {
			go st.sess.sendFrame(cmdRST, st.id, nil)
		}
	})
	return nil
}

type smuxManager struct {
	warmPool *pool.WarmPool
	mu       sync.Mutex
	active   *smuxSession
}

func (m *smuxManager) openStream(ctx context.Context, host string, port uint16) (*smuxStream, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		// The first attempt may use a pooled connection; a retry must
		// not draw another pooled one — a pooled connection that just
		// proved dead was usually killed by the same idle window as
		// the rest of the pool, so the retry dials fresh instead.
		sess, err := m.getOrDialSession(ctx, attempt > 0)
		if err != nil {
			// A dial failure is the same dead-edge symptom as a
			// stream failure, and it used to fail fast on attempt 0
			// without retrying at all (live: a fresh dial to
			// 104.18.0.181 timed out while doctor still passed).
			// Rotate and retry while attempts remain.
			lastErr = err
			if ctx.Err() != nil || attempt >= 2 {
				break
			}
			m.rotateForRetry(attempt)
			continue
		}
		st, err := sess.OpenStream(ctx, host, port)
		if err == nil {
			return st, nil
		}
		lastErr = err
		telemetry.Log.Warn("Failed to open multiplexed worker stream, retrying with a fresh session", slog.Int("attempt", attempt+1), slog.String("host", host), slog.String("err", err.Error()))
		sess.Close()
		m.mu.Lock()
		if m.active == sess {
			m.active = nil
		}
		m.mu.Unlock()
		if attempt >= 2 {
			break
		}
		m.rotateForRetry(attempt)
	}
	return nil, fmt.Errorf("failed to open multiplexed worker stream after 3 attempts: %w", lastErr)
}

// rotateForRetry moves the pool to the next failover edge after a failed
// attempt, so the retry dials a different edge instead of the same dead
// one. Without it, all three attempts dial the one dead IP while the
// failover list sits unused (live: 104.18.0.181 dead, 104.18.0.82
// intermittent, retries never left .181). If there is no failover to
// rotate to, the retry dials the same edge as before.
func (m *smuxManager) rotateForRetry(attempt int) {
	next, ok := m.warmPool.RotateToNextFailover()
	if !ok {
		return
	}
	telemetry.Log.Warn("Rotating to next failover edge for retry", slog.Int("attempt", attempt+2), slog.String("route", next.TargetIP))
}

func (m *smuxManager) getOrDialSession(ctx context.Context, fresh bool) (*smuxSession, error) {
	if !fresh {
		m.mu.Lock()
		if m.active != nil && !m.active.closed.Load() {
			sess := m.active
			m.mu.Unlock()
			return sess, nil
		}
		m.mu.Unlock()
	}

	var raw net.Conn
	var err error
	if fresh {
		raw, err = m.warmPool.AcquireFresh(ctx)
	} else {
		raw, err = m.warmPool.Acquire(ctx)
	}
	if err != nil {
		return nil, err
	}
	sess := newSmuxSession(raw)

	m.mu.Lock()
	if m.active != nil && !m.active.closed.Load() {
		existing := m.active
		m.mu.Unlock()
		sess.Close()
		return existing, nil
	}
	m.active = sess
	m.mu.Unlock()
	return sess, nil
}

func StartSOCKS5Server(ctx context.Context, listenAddr string, warmPool *pool.WarmPool) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		telemetry.Log.Error("Failed to bind SOCKS5 listener", slog.String("addr", listenAddr), slog.String("err", err.Error()))
		return
	}
	telemetry.Log.Info("Cornelius native SOCKS5->Worker tunnel active", slog.String("addr", listenAddr))

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	mgr := &smuxManager{warmPool: warmPool}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
			continue
		}
		go handleSOCKS5Client(ctx, conn, mgr)
	}
}

func handleSOCKS5Client(parentCtx context.Context, client net.Conn, mgr *smuxManager) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))

	var greet [2]byte
	if _, err := io.ReadFull(client, greet[:]); err != nil || greet[0] != 0x05 {
		return
	}
	methods := make([]byte, greet[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	var req [4]byte
	if _, err := io.ReadFull(client, req[:]); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01:
		var ip4 [4]byte
		if _, err := io.ReadFull(client, ip4[:]); err != nil {
			return
		}
		host = net.IP(ip4[:]).String()
	case 0x03:
		var dlen [1]byte
		if _, err := io.ReadFull(client, dlen[:]); err != nil {
			return
		}
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(client, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04:
		var ip6 [16]byte
		if _, err := io.ReadFull(client, ip6[:]); err != nil {
			return
		}
		host = net.IP(ip6[:]).String()
	default:
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(client, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	dialCtx, cancel := context.WithTimeout(parentCtx, 12*time.Second)
	stream, err := mgr.openStream(dialCtx, host, port)
	cancel()
	if err != nil {
		telemetry.Log.Warn("SOCKS5 upstream failed", slog.String("host", host), slog.String("err", err.Error()))
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	_ = client.SetDeadline(time.Time{})
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	telemetry.ActiveStreams.Add(1)
	defer telemetry.ActiveStreams.Add(^uint64(0))

	var wg sync.WaitGroup
	wg.Add(2)
	var lastStreamRx atomic.Int64
	lastStreamRx.Store(time.Now().UnixNano())
	replyDone := make(chan struct{}) // closed when io.Copy(client, stream) ends
	go func() {
		defer wg.Done()
		n, err := io.Copy(stream, client)
		if n > 0 {
			telemetry.TotalBytesTx.Add(uint64(n))
		}
		if err != nil {
			// The client reset or the stream died: nothing more can be
			// delivered in either direction, so tear the stream down.
			_ = stream.Close()
			return
		}
		// Clean EOF from the client: it finished sending. Half-close
		// only the write side so the target's reply can still arrive
		// and io.Copy(client, stream) below can complete. The deferred
		// stream.Close() does the full close once both copies end.
		_ = stream.CloseWrite()
		// The client can no longer send, and TCP gives us no signal when
		// it later closes (a FIN-then-close is silent). Watch for it so a
		// target that never EOFs (HTTP keep-alive) cannot pin this stream.
		watchHalfClosedClient(client, stream, &lastStreamRx, replyDone)
	}()
	go func() {
		defer wg.Done()
		defer close(replyDone)
		n, _ := io.Copy(client, &activityReader{r: stream, last: &lastStreamRx})
		if n > 0 {
			telemetry.TotalBytesRx.Add(uint64(n))
		}
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// halfCloseIdleNanos bounds how long a stream whose client has half-closed
// may sit with no data arriving from the target before the stream is fully
// closed. It must stay well under the 25 s session keepalive. A var (atomic)
// so tests can shorten it.
var halfCloseIdleNanos atomic.Int64

func init() { halfCloseIdleNanos.Store(int64(15 * time.Second)) }

// activityReader records when the stream last delivered data.
type activityReader struct {
	r    io.Reader
	last *atomic.Int64
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.last.Store(time.Now().UnixNano())
	}
	return n, err
}

// watchHalfClosedClient runs after the client half-closed. It fully closes
// the stream when the client is gone, which unblocks io.Copy(client, stream):
//
//   - the client socket reports an error (RST from an abortive close, or a
//     keepalive failure) — checked via SO_ERROR; or
//   - nothing has arrived from the target for halfCloseIdleNanos. This is
//     the only way to notice a plain close: after shutdown(SHUT_WR) the
//     kernel emits nothing further when the client closes, and the proxy
//     has nothing it could write to probe. Trade-off: a target that stays
//     silent longer than the timeout gets cut after a client half-close.
//
// It returns as soon as the reply direction ends (done is closed).
func watchHalfClosedClient(client net.Conn, stream *smuxStream, last *atomic.Int64, done <-chan struct{}) {
	timeout := time.Duration(halfCloseIdleNanos.Load())
	interval := timeout / 4
	if interval < 20*time.Millisecond {
		interval = 20 * time.Millisecond
	}
	if interval > time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			idle := timeout > 0 && time.Since(time.Unix(0, last.Load())) > timeout
			if idle || clientSocketFailed(client) {
				_ = stream.Close()
				return
			}
		}
	}
}
