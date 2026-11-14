package tlshandshake

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func fakeClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	// Minimal plausible ClientHello record: 5-byte header + payload with the
	// SNI embedded at a realistic offset.
	payload := make([]byte, 0, 200)
	payload = append(payload, 0x03, 0x03)                        // legacy version
	payload = append(payload, bytes.Repeat([]byte{0x11}, 32)...) // random
	payload = append(payload, 0x00)                              // session id len
	payload = append(payload, 0x00, 0x02, 0x13, 0x01)            // cipher suites
	payload = append(payload, 0x01, 0x00)                        // compression
	payload = append(payload, 0x00, 0x2b)                        // extensions len (fake)
	payload = append(payload, []byte(sni)...)
	payload = append(payload, bytes.Repeat([]byte{0x22}, 40)...)
	rec := []byte{0x16, 0x03, 0x01, 0, 0}
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	return append(rec, payload...)
}

func reassemble(t *testing.T, frags [][]byte) []byte {
	t.Helper()
	var out []byte
	for _, f := range frags {
		if len(f) < 5 || f[0] != 0x16 {
			t.Fatalf("fragment is not a TLS record: %v", f[:min(5, len(f))])
		}
		l := int(binary.BigEndian.Uint16(f[3:5]))
		if l != len(f)-5 {
			t.Fatalf("fragment length field %d != actual %d", l, len(f)-5)
		}
		out = append(out, f[5:]...)
	}
	return out
}

func TestSplitReassemblesToOriginal(t *testing.T) {
	sni := "bold-heart-a6e2.nedaymarg.workers.dev"
	rec := fakeClientHello(t, sni)
	for i := 0; i < 50; i++ {
		for _, micro := range []bool{false, true} {
			frags := SplitClientHello(rec, sni, micro)
			if len(frags) < 2 {
				t.Fatalf("micro=%v: expected at least 2 fragments, got %d", micro, len(frags))
			}
			if got := reassemble(t, frags); !bytes.Equal(got, rec[5:]) {
				t.Fatalf("micro=%v: reassembled payload differs from original", micro)
			}
		}
	}
}

func TestSplitAlwaysCutsInsideSNI(t *testing.T) {
	sni := "bold-heart-a6e2.nedaymarg.workers.dev"
	rec := fakeClientHello(t, sni)
	sniIdx := bytes.Index(rec[5:], []byte(sni))
	for i := 0; i < 50; i++ {
		frags := SplitClientHello(rec, sni, i%2 == 0)
		// Walk the fragment boundaries and check one falls inside the SNI.
		off := 0
		cutInside := false
		for _, f := range frags[:len(frags)-1] {
			off += len(f) - 5
			if off > sniIdx && off < sniIdx+len(sni) {
				cutInside = true
			}
		}
		if !cutInside {
			t.Fatalf("run %d: no cut inside the SNI span [%d,%d)", i, sniIdx, sniIdx+len(sni))
		}
	}
}

func TestSplitVariesBetweenRuns(t *testing.T) {
	sni := "bold-heart-a6e2.nedaymarg.workers.dev"
	rec := fakeClientHello(t, sni)
	seen := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		frags := SplitClientHello(rec, sni, true)
		var sig bytes.Buffer
		for _, f := range frags {
			sig.WriteString(string(rune(len(f))))
		}
		seen[sig.String()] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatal("fragmentation is deterministic across 20 runs; cuts should vary")
	}
}

func TestSplitLeavesInvalidInputAlone(t *testing.T) {
	short := []byte{0x16, 0x03, 0x01}
	if got := SplitClientHello(short, "example.com", true); len(got) != 1 || !bytes.Equal(got[0], short) {
		t.Fatal("short input was not returned unchanged")
	}
	notTLS := bytes.Repeat([]byte{0x00}, 100)
	if got := SplitClientHello(notTLS, "example.com", true); len(got) != 1 {
		t.Fatal("non-TLS input was not returned unchanged")
	}
}
