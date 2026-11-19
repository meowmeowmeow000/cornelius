package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"cornelius/internal/config"
	"cornelius/internal/mockworker"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/proxy/pool"
	"cornelius/internal/telemetry"
)

// startHalfCloseSOCKS runs the real SOCKS5 server + warm pool against a
// mock Worker that relays to targetAddr, and returns the SOCKS address.
func startHalfCloseSOCKS(t *testing.T, targetAddr string) string {
	t.Helper()
	mock, err := mockworker.Start(targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mock.Close)

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
	t.Cleanup(cancel)
	p := pool.NewWarmPool(profile)
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

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
	return socksAddr
}

// socksConnect performs the SOCKS5 greeting + CONNECT and returns the
// tunnelled connection.
func socksConnect(t *testing.T, socksAddr, host string, port uint16) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil || greet[1] != 0x00 {
		t.Fatalf("SOCKS greeting: %v %v", greet, err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0x00 {
		t.Fatalf("SOCKS CONNECT reply: %v %v", reply, err)
	}
	return conn
}

// TestSOCKSClientHalfCloseStillReceivesFullReply is the regression test
// for FIN meaning full close. The client sends a request and half-closes
// (what `io.Copy(stream, client)` finishing triggers). The target only
// answers after it has seen that EOF, so the reply is produced strictly
// after the client's FIN. With the old behaviour (FIN closes the whole
// stream and the Worker kills the target socket) the reply is lost and
// the client reads nothing; with half-close the client receives the full
// reply, then a clean EOF.
func TestSOCKSClientHalfCloseStillReceivesFullReply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A reply bigger than one SMUX chunk, written in pieces after a delay.
	reply := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	gotReq := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, _ := io.ReadAll(c) // blocks until the client half-closes
		gotReq <- req
		time.Sleep(200 * time.Millisecond) // reply strictly after the FIN
		half := len(reply) / 2
		_, _ = c.Write(reply[:half])
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(reply[half:])
	}()

	socksAddr := startHalfCloseSOCKS(t, ln.Addr().String())
	conn := socksConnect(t, socksAddr, "example.com", 80)
	defer conn.Close()

	if _, err := conn.Write([]byte("request-body")); err != nil {
		t.Fatal(err)
	}
	// Half-close: we are done sending but still want the reply.
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading the reply: %v (got %d of %d bytes)", err, len(got), len(reply))
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("reply truncated or corrupt: got %d bytes, want %d", len(got), len(reply))
	}
	select {
	case req := <-gotReq:
		if string(req) != "request-body" {
			t.Fatalf("target saw request %q, want %q", req, "request-body")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never saw the client's EOF")
	}
}

// TestStreamHalfCloseIsPerDirection exercises the smuxStream API directly:
// the peer's FIN is read-side EOF only (our writes still reach the target),
// and CloseWrite() ends only our write side.
func TestStreamHalfCloseIsPerDirection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	late := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("early"))
		_ = c.(*net.TCPConn).CloseWrite() // target done talking -> Worker sends FIN
		b, _ := io.ReadAll(c)             // ...but it still reads what we send
		late <- string(b)
	}()

	mock, err := mockworker.Start(ln.Addr().String())
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
			WSPath:      mockworker.DefaultWSPath,
		},
		FragDelayMs: 1,
		AllowInsec:  true,
		WSPath:      mockworker.DefaultWSPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sess := newSmuxSession(conn)
	defer sess.Close()

	st, err := sess.OpenStream(ctx, "example.com", 80)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Worker FIN -> read-side EOF after the buffered data.
	got, err := io.ReadAll(st)
	if err != nil || string(got) != "early" {
		t.Fatalf("read side: got %q err %v, want %q then EOF", got, err, "early")
	}
	// ...but the stream is NOT closed: our write side still works.
	if _, err := st.Write([]byte("late")); err != nil {
		t.Fatalf("write after peer FIN failed (FIN must not be a full close): %v", err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("Write after CloseWrite must fail")
	}
	select {
	case s := <-late:
		if s != "late" {
			t.Fatalf("target received %q after the Worker FIN, want %q", s, "late")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never received data written after the peer's FIN")
	}
}

// pipeStream returns a stream on a session whose peer (the returned server
// end of a net.Pipe) is under the test's control. net.Pipe is unbuffered, so
// a peer that never reads blocks every raw Write — the dead-peer case.
func pipeStream(t *testing.T) (*smuxStream, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	sess := newSmuxSession(client)
	st := &smuxStream{sess: sess, id: 2, rxCh: make(chan []byte, 64), done: make(chan struct{}), rxEOF: make(chan struct{})}
	sess.mu.Lock()
	sess.streams[2] = st
	sess.mu.Unlock()
	t.Cleanup(func() {
		sess.Close()
		_ = server.Close()
	})
	return st, server
}

// TestCloseWriteNeverBlocksOnDeadPeer: CloseWrite must not block on the
// network. WriteBinary holds writeMu across a blocking raw Write, so a
// synchronous FIN to a peer that never reads would hang the SOCKS handler
// goroutine (and wg.Wait) forever. Fails on a synchronous CloseWrite.
func TestCloseWriteNeverBlocksOnDeadPeer(t *testing.T) {
	st, _ := pipeStream(t) // the peer never reads

	returned := make(chan error, 1)
	go func() { returned <- st.CloseWrite() }()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("CloseWrite() = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CloseWrite() blocked on a dead peer; it must send the FIN asynchronously")
	}
	// Guarded with a timeout so a future regression fails fast with a
	// clear message instead of hanging the whole package until the
	// test timeout (that is how this deadlock surfaced in CI).
	writeReturned := make(chan error, 1)
	go func() { _, err := st.Write([]byte("x")); writeReturned <- err }()
	select {
	case err := <-writeReturned:
		if err == nil {
			t.Fatal("Write after CloseWrite must fail immediately")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write after CloseWrite blocked; it must fail immediately")
	}
	// A following full close must not wedge behind the stuck FIN either.
	closed := make(chan struct{})
	go func() { _ = st.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() blocked behind a stuck CloseWrite FIN")
	}
}

// TestNoPSHAfterFIN: Write racing CloseWrite must never put a PSH on the
// wire after the FIN.
func TestNoPSHAfterFIN(t *testing.T) {
	st, server := pipeStream(t)

	var cmds []byte
	var cmdsMu sync.Mutex
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			var hdr [2]byte
			if _, err := io.ReadFull(server, hdr[:]); err != nil {
				return
			}
			n := int(hdr[1] & 0x7f) // small frames only: 8-byte header + 1 byte
			buf := make([]byte, 4+n)
			if _, err := io.ReadFull(server, buf); err != nil {
				return
			}
			mask, body := buf[:4], buf[4:]
			cmdsMu.Lock()
			cmds = append(cmds, body[1]^mask[1&3])
			cmdsMu.Unlock()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if _, err := st.Write([]byte("x")); err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	_ = st.CloseWrite()
	wg.Wait()

	// Wait for the FIN goroutine to flush, then stop the reader.
	deadline := time.Now().Add(2 * time.Second)
	for {
		cmdsMu.Lock()
		fin := bytes.IndexByte(cmds, cmdFIN)
		cmdsMu.Unlock()
		if fin >= 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = server.Close()
	<-readerDone

	cmdsMu.Lock()
	defer cmdsMu.Unlock()
	fin := bytes.IndexByte(cmds, cmdFIN)
	if fin < 0 {
		t.Fatal("no FIN reached the peer")
	}
	if bytes.IndexByte(cmds[fin+1:], cmdPSH) >= 0 {
		t.Fatalf("a PSH followed the FIN on the wire: %v", cmds[fin:])
	}
}

// startAbortTarget is a TCP target for the abort tests. The first byte of
// each connection picks the behaviour: 'H' = HTTP keep-alive style (read the
// request, never reply, never EOF), 'E' = echo.
func startAbortTarget(t *testing.T) string {
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
			go func() {
				defer c.Close()
				var tag [1]byte
				if _, err := io.ReadFull(c, tag[:]); err != nil {
					return
				}
				if tag[0] == 'E' {
					_, _ = io.Copy(c, c)
					return
				}
				_, _ = io.Copy(io.Discard, c) // 'H': EOF on client FIN, then silence
				select {}                     // keep-alive: never closes, never replies
			}()
		}
	}()
	return ln.Addr().String()
}

func waitStreams(t *testing.T, want uint64, within time.Duration, what string) time.Duration {
	t.Helper()
	start := time.Now()
	for telemetry.ActiveStreams.Load() != want {
		if time.Since(start) > within {
			t.Fatalf("%s: ActiveStreams = %d after %v, want %d (handler still pinned)", what, telemetry.ActiveStreams.Load(), within, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return time.Since(start)
}

func echoOnce(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write %q: %v", msg, err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
		t.Fatalf("echo of %q: got %q err %v", msg, got, err)
	}
}

// TestSOCKSHalfClosedClientAbortReleasesStream: the client half-closes, the
// target never replies and never EOFs, then the client goes away. The
// handler must return promptly (not wait for the 25 s session keepalive),
// and neither the session nor other streams may be killed.
func TestSOCKSHalfClosedClientAbortReleasesStream(t *testing.T) {
	target := startAbortTarget(t)
	socksAddr := startHalfCloseSOCKS(t, target)
	// Let handlers from earlier tests finish so the counter is stable.
	for prev, stable := telemetry.ActiveStreams.Load(), 0; stable < 10; time.Sleep(30 * time.Millisecond) {
		if cur := telemetry.ActiveStreams.Load(); cur == prev {
			stable++
		} else {
			prev, stable = cur, 0
		}
	}

	for _, tc := range []struct {
		name string
		idle time.Duration
		// closeA ends the half-closed client's connection.
		closeA func(c *net.TCPConn)
		bound  time.Duration
	}{
		// Plain close after FIN is silent on the wire: only the idle
		// timeout can notice it.
		{"plain-close-idle-timeout", 400 * time.Millisecond, func(c *net.TCPConn) { _ = c.Close() }, 5 * time.Second},
		// An abortive close (RST) is caught by the socket-error check even
		// with the idle timeout out of the picture.
		{"abortive-close-rst", time.Hour, func(c *net.TCPConn) { _ = c.SetLinger(0); _ = c.Close() }, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := halfCloseIdleNanos.Swap(int64(tc.idle))
			defer halfCloseIdleNanos.Store(prev)

			// An unrelated live stream that must survive the abort.
			b := socksConnect(t, socksAddr, "example.com", 80)
			defer b.Close()
			if _, err := b.Write([]byte("E")); err != nil { // tag: echo target
				t.Fatal(err)
			}
			echoOnce(t, b, "ping")
			base := telemetry.ActiveStreams.Load()

			a := socksConnect(t, socksAddr, "example.com", 80).(*net.TCPConn)
			if _, err := a.Write([]byte("Hrequest")); err != nil {
				t.Fatal(err)
			}
			if err := a.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			waitStreams(t, base+1, 5*time.Second, "A registered")
			time.Sleep(100 * time.Millisecond) // let the handler reach its post-half-close wait
			tc.closeA(a)

			took := waitStreams(t, base, tc.bound, "after the client left")
			t.Logf("handler released the stream %v after the client left", took)

			// The session and the other stream are intact.
			echoOnce(t, b, "pong")
			c := socksConnect(t, socksAddr, "example.com", 80)
			defer c.Close()
			if _, err := c.Write([]byte("E")); err != nil {
				t.Fatal(err)
			}
			echoOnce(t, c, "fresh")
		})
	}
}
