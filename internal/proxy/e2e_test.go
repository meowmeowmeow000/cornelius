package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cornelius/internal/config"
	"cornelius/internal/mockworker"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/proxy/pool"
	"cornelius/internal/telemetry"
)

// TestEndToEndThroughMockWorker is the doctor's live test, hermetic: the
// real dialer (uTLS + fragmentation + WebSocket upgrade) against a fake
// Worker, then a real SMUX stream through it to a local HTTP target.
// It runs in CI — no network, no root, no real Worker.
func TestEndToEndThroughMockWorker(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("mock-worker-ok"))
	}))
	defer target.Close()

	mock, err := mockworker.Start(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	for _, mode := range []string{factory.ModeTLSFrag, factory.ModeTLSMicroFrag} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := factory.DialStealthTunnel(ctx, factory.StealthDialConfig{
				Route: config.RouteCandidate{
					TargetIP:    "127.0.0.1",
					TargetPort:  uint16(mock.Port()),
					CleanSNI:    "localhost",
					StealthMode: mode,
					WSPath:      mockworker.DefaultWSPath,
				},
				FragDelayMs: 1,
				AllowInsec:  true,
				WSPath:      mockworker.DefaultWSPath,
			})
			if err != nil {
				t.Fatalf("dial through mock worker failed: %v", err)
			}
			defer conn.Close()

			sess := newSmuxSession(conn)
			defer sess.Close()
			// Two streams on one session: the tunnel multiplexes, it
			// does not spend one dial per request.
			for i := 0; i < 2; i++ {
				body := fetchThroughStream(t, ctx, sess, "example.com", 80)
				if !strings.Contains(body, "mock-worker-ok") {
					t.Fatalf("stream %d: response %q does not contain the target marker", i, body)
				}
			}
		})
	}
}

// TestDialToWrongWSPathFails proves the upgrade goes to the secret path:
// the mock Worker 404s any other path, and the dialer must fail instead
// of sending raw SMUX at the wrong endpoint.
func TestDialToWrongWSPathFails(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("mock-worker-ok"))
	}))
	defer target.Close()

	mock, err := mockworker.Start(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := factory.DialStealthTunnel(ctx, factory.StealthDialConfig{
		Route: config.RouteCandidate{
			TargetIP:    "127.0.0.1",
			TargetPort:  uint16(mock.Port()),
			CleanSNI:    "localhost",
			StealthMode: factory.ModeTLSFrag,
			WSPath:      "/wrong-path",
		},
		FragDelayMs: 1,
		AllowInsec:  true,
		WSPath:      "/wrong-path",
	})
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial to the wrong WebSocket path must fail")
	}
}

// TestSOCKS5ThroughMockWorker is the daemon's core pipeline end to end:
// SOCKS5 listener -> smuxManager -> warm pool -> real dial -> fake Worker
// -> local HTTP target. Same shape as the running daemon, with the
// network replaced by localhost.
func TestSOCKS5ThroughMockWorker(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("mock-worker-ok"))
	}))
	defer target.Close()

	mock, err := mockworker.Start(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	profile := &config.CombatProfile{
		WorkerHost: "localhost",
		Modules: config.ModulesConfig{
			StealthFactory: config.StealthFactoryConfig{
				DefaultWSPath:        mockworker.DefaultWSPath,
				FragmentationDelayMs: 1,
				AllowInsecureCerts:   true,
			},
			WarmPool: config.WarmPoolConfig{TargetCapacity: 2},
		},
		PrimaryRoute: config.RouteCandidate{
			TargetIP:    "127.0.0.1",
			TargetPort:  uint16(mock.Port()),
			CleanSNI:    "localhost",
			StealthMode: factory.ModeTLSFrag,
			WSPath:      mockworker.DefaultWSPath,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := pool.NewWarmPool(profile)
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// The pool's maintainer warms real tunnels against the mock Worker.
	// Snapshot the counter first: it is process-global, so a previous
	// test in this binary must not satisfy the wait for us.
	before := telemetry.PoolHealthyPipes.Load()
	deadline := time.Now().Add(10 * time.Second)
	for telemetry.PoolHealthyPipes.Load() <= before {
		if time.Now().After(deadline) {
			t.Fatal("warm pool did not fill against the mock Worker")
		}
		time.Sleep(50 * time.Millisecond)
	}

	socksAddr := free127Addr(t)
	go StartSOCKS5Server(ctx, socksAddr, p)
	waitForListener(t, socksAddr, 5*time.Second)

	body := socksFetch(t, socksAddr, "example.com", 80)
	if !strings.Contains(body, "mock-worker-ok") {
		t.Fatalf("SOCKS fetch returned %q, want the target marker", body)
	}
}

// fetchThroughStream opens one SMUX stream, sends a GET, and reads the
// response. It mirrors the doctor's live stream test.
func fetchThroughStream(t *testing.T, ctx context.Context, sess *smuxSession, host string, port uint16) string {
	t.Helper()
	streamCtx, streamCancel := context.WithTimeout(ctx, 10*time.Second)
	defer streamCancel()
	st, err := sess.OpenStream(streamCtx, host, port)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer st.Close()
	if _, err := st.Write([]byte("GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n")); err != nil {
		t.Fatalf("write through stream: %v", err)
	}
	type readResult struct {
		n   int
		err error
	}
	buf := make([]byte, 4096)
	resCh := make(chan readResult, 1)
	go func() {
		n, err := st.Read(buf)
		resCh <- readResult{n, err}
	}()
	select {
	case res := <-resCh:
		if res.err != nil || res.n == 0 || !strings.HasPrefix(string(buf[:res.n]), "HTTP/") {
			t.Fatalf("no HTTP response through the tunnel: n=%d err=%v", res.n, res.err)
		}
		return string(buf[:res.n])
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a response through the tunnel")
		return ""
	}
}

// free127Addr returns an unused 127.0.0.1:port for a listener to bind.
func free127Addr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitForListener polls until something accepts on addr.
func waitForListener(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing listening on %s after %v", addr, timeout)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// socksFetch speaks SOCKS5 to addr, CONNECTs to host:port, sends a GET,
// and returns the response body.
func socksFetch(t *testing.T, socksAddr, host string, port uint16) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatal(err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("SOCKS greeting reply = %v, want [5 0]", greet)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS CONNECT reply = %v, want success", reply)
	}

	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if strings.Contains(sb.String(), "mock-worker-ok") {
				return sb.String()
			}
		}
		if err != nil {
			t.Fatalf("SOCKS fetch ended without the target marker: %q (err %v)", sb.String(), err)
		}
	}
}
