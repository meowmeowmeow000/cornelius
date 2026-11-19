package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestStreamCloseNeverBlocksOnDeadPeer is a regression test for the
// deadlock the race detector found in round 12: smuxStream.Close()
// sent the close frame synchronously, and WriteBinary holds writeMu across a
// blocking raw Write. To a peer that stopped reading with a full send
// buffer, Close() blocked forever — wedging closeOnce (any concurrent
// Close waits on it) and writeMu (no more frames, including keepalives,
// could go out on that session). The RST is now best-effort (sent from
// a goroutine), so Close() must return promptly even when the peer
// never reads.
func TestStreamCloseNeverBlocksOnDeadPeer(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	sess := newSmuxSession(client)
	defer sess.Close()
	st := &smuxStream{sess: sess, id: 2, rxCh: make(chan []byte, 64), done: make(chan struct{})}
	sess.mu.Lock()
	sess.streams[2] = st
	sess.mu.Unlock()

	// The peer never reads: any synchronous write would block forever.
	start := time.Now()
	if err := st.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Close() took %v with a dead peer, want < 2s", elapsed)
	}
	select {
	case <-st.done:
	default:
		t.Fatal("Close() must close the stream's done channel")
	}
	sess.mu.RLock()
	_, stillThere := sess.streams[2]
	sess.mu.RUnlock()
	if stillThere {
		t.Fatal("Close() must remove the stream from the session")
	}
}

// TestStreamCloseSendsRSTWhenPeerReads proves the async RST (full close) is not
// dropped: when the peer is reading, the frame must still arrive.
func TestStreamCloseSendsRSTWhenPeerReads(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	sess := newSmuxSession(client)
	defer sess.Close()
	st := &smuxStream{sess: sess, id: 2, rxCh: make(chan []byte, 64), done: make(chan struct{})}
	sess.mu.Lock()
	sess.streams[2] = st
	sess.mu.Unlock()

	if err := st.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}

	// One WS frame: 0x82, length byte with the mask bit, 4 mask bytes,
	// 8 masked SMUX bytes.
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame := make([]byte, 14)
	if _, err := io.ReadFull(server, frame); err != nil {
		t.Fatalf("reading the RST frame: %v", err)
	}
	if frame[0] != 0x82 || frame[1] != 0x80|8 {
		t.Fatalf("frame header = %x, want a masked 8-byte binary frame", frame[:2])
	}
	mask := frame[2:6]
	payload := make([]byte, 8)
	for i := range payload {
		payload[i] = frame[6+i] ^ mask[i&3]
	}
	if payload[0] != smuxVersion || payload[1] != cmdRST {
		t.Fatalf("SMUX header = %x, want version %d cmd RST (%d)", payload[:2], smuxVersion, cmdRST)
	}
	if got := binary.LittleEndian.Uint32(payload[4:8]); got != 2 {
		t.Fatalf("RST stream id = %d, want 2", got)
	}
}
