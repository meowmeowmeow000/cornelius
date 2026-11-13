package proxy

import "testing"

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
