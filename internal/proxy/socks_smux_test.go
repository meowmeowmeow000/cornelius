package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"cornelius/internal/config"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/proxy/pool"
)

func TestWsConnRoundTrip(t *testing.T) {
	// WriteBinary must emit a standard masked WebSocket binary frame that
	// ReadMessage on the other end can parse back to the same payload.
	// This is the exact exchange the daemon has with the Cloudflare Worker.
	for _, size := range []int{13, 200, 70000} {
		want := make([]byte, size)
		for i := range want {
			want[i] = byte(i * 7)
		}
		server, client := net.Pipe()
		w := &wsConn{raw: client}
		r := &wsConn{raw: server}
		errCh := make(chan error, 1)
		go func() {
			errCh <- w.WriteBinary(want)
		}()
		got, err := r.ReadMessage()
		if err != nil {
			t.Fatalf("size %d: ReadMessage() returned error: %v", size, err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("size %d: WriteBinary() returned error: %v", size, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("size %d: round-trip mismatch: got %d bytes, want %d", size, len(got), len(want))
		}
		server.Close()
		client.Close()
	}
}

func TestWsConnPingIsNotAMessage(t *testing.T) {
	// A ping frame must never reach the SMUX parser: readLoop would read
	// its payload as a frame header and kill the session. ReadMessage
	// must answer with a pong and report no message, and the next real
	// frame must still parse.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	w := &wsConn{raw: client}
	r := &wsConn{raw: server}

	// Send a ping with a non-empty payload (the old code returned it as
	// a message, and a non-empty payload is what kills the parser).
	go func() {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()
		_ = w.writeFrameLocked(0x89, []byte("hello")) // FIN + ping opcode
	}()

	type result struct {
		msg []byte
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		msg, err := r.ReadMessage()
		resCh <- result{msg, err}
	}()

	// Read the pong back: 0x8A, masked length 5, mask, masked payload.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatalf("reading pong header: %v", err)
	}
	if hdr[0] != 0x8A || hdr[1] != 0x85 {
		t.Fatalf("pong header = %02x %02x, want 8a 85", hdr[0], hdr[1])
	}
	var mask [4]byte
	if _, err := io.ReadFull(client, mask[:]); err != nil {
		t.Fatalf("reading pong mask: %v", err)
	}
	masked := make([]byte, 5)
	if _, err := io.ReadFull(client, masked); err != nil {
		t.Fatalf("reading pong payload: %v", err)
	}
	for i := range masked {
		masked[i] ^= mask[i&3]
	}
	if string(masked) != "hello" {
		t.Fatalf("pong payload = %q, want hello", masked)
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("ReadMessage() on a ping returned error: %v", res.err)
		}
		if len(res.msg) != 0 {
			t.Fatalf("ReadMessage() on a ping returned %q, want no message", res.msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadMessage() on a ping did not return")
	}

	// The read path must survive the ping: a binary frame still parses.
	go func() {
		_ = w.WriteBinary([]byte("data"))
	}()
	got, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() after ping returned error: %v", err)
	}
	if string(got) != "data" {
		t.Fatalf("ReadMessage() after ping = %q, want data", got)
	}
}

func testDeadRoute(ip string) config.RouteCandidate {
	return config.RouteCandidate{
		TargetIP:        ip,
		TargetPort:      1, // closed port: every dial fails fast
		SNISPFDirection: config.SNISPFDirectionLegacy,
		CleanSNI:        "worker.test",
		WSPath:          "/secret-knock-99",
		StealthMode:     factory.ModeTLSFrag,
		ExpectedTTL:     55,
	}
}

func TestOpenStreamRotatesFailoverOnDialFailure(t *testing.T) {
	// Every edge is a closed localhost port, so every dial fails fast.
	// openStream must still burn all 3 attempts, rotating to a different
	// edge each time. The live bug: all 3 attempts dialled the same dead
	// 104.18.0.181 while the failover list sat unused.
	prof := &config.CombatProfile{
		PrimaryRoute: testDeadRoute("127.0.0.1"),
		FailoverRoutes: []config.RouteCandidate{
			testDeadRoute("127.0.0.2"),
			testDeadRoute("127.0.0.3"),
		},
	}
	prof.Modules.StealthFactory.DefaultWSPath = "/secret-knock-99"
	prof.Modules.StealthFactory.AllowInsecureCerts = true
	p := pool.NewWarmPool(prof)
	defer p.Close()
	mgr := &smuxManager{warmPool: p}

	_, err := mgr.openStream(context.Background(), "example.com", 443)
	if err == nil {
		t.Fatal("openStream() with all edges dead must fail")
	}
	if !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("openStream() error = %q, want it to report 3 attempts", err.Error())
	}
	if got := p.ActiveRoute().TargetIP; got != "127.0.0.3" {
		t.Fatalf("active route after retries = %q, want 127.0.0.3 (rotated twice)", got)
	}
}

func TestOpenStreamDoesNotWaitForUnrelatedSessionTraffic(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	sess := &smuxSession{
		ws:      &wsConn{raw: client},
		streams: make(map[uint32]*smuxStream),
		nextID:  1,
		done:    make(chan struct{}),
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	sess.lastRx.Store(time.Now().Add(-time.Hour).UnixNano())
	st, err := sess.OpenStream(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatalf("OpenStream() returned error: %v", err)
	}
	if st == nil {
		t.Fatal("OpenStream() returned nil stream")
	}
	if _, ok := sess.streams[st.id]; !ok {
		t.Fatal("OpenStream() did not register the stream")
	}
}
