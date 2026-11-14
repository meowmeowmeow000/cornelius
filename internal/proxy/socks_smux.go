package proxy

import (
	"context"
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

	if _, err := w.raw.Write(payload); err != nil {
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
		return payload, nil
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
		sess: s,
		id:   id,
		rxCh: make(chan []byte, 64),
		done: make(chan struct{}),
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

type smuxStream struct {
	sess      *smuxSession
	id        uint32
	rxCh      chan []byte
	pending   []byte
	done      chan struct{}
	closeOnce sync.Once
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
}

func (st *smuxStream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
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
	return total, nil
}

func (st *smuxStream) closeLocal() {
	st.closeOnce.Do(func() {
		close(st.done)
	})
}

func (st *smuxStream) Close() error {
	st.closeOnce.Do(func() {
		close(st.done)
		st.sess.mu.Lock()
		delete(st.sess.streams, st.id)
		st.sess.mu.Unlock()
		_ = st.sess.sendFrame(cmdFIN, st.id, nil)
	})
	return nil
}

type smuxManager struct {
	warmPool *pool.WarmPool
	mu       sync.Mutex
	active   *smuxSession
}

func (m *smuxManager) openStream(ctx context.Context, host string, port uint16) (*smuxStream, error) {
	for attempt := 0; attempt < 3; attempt++ {
		sess, err := m.getOrDialSession(ctx)
		if err != nil {
			return nil, err
		}
		st, err := sess.OpenStream(ctx, host, port)
		if err == nil {
			return st, nil
		}
		sess.Close()
		m.mu.Lock()
		if m.active == sess {
			m.active = nil
		}
		m.mu.Unlock()
	}
	return nil, errors.New("failed to open multiplexed worker stream after 3 attempts")
}

func (m *smuxManager) getOrDialSession(ctx context.Context) (*smuxSession, error) {
	m.mu.Lock()
	if m.active != nil && !m.active.closed.Load() {
		sess := m.active
		m.mu.Unlock()
		return sess, nil
	}
	m.mu.Unlock()

	raw, err := m.warmPool.Acquire(ctx)
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
	go func() {
		defer wg.Done()
		n, _ := io.Copy(stream, client)
		if n > 0 {
			telemetry.TotalBytesTx.Add(uint64(n))
		}
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, stream)
		if n > 0 {
			telemetry.TotalBytesRx.Add(uint64(n))
		}
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}
