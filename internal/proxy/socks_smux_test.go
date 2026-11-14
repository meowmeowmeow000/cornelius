package proxy

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
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
