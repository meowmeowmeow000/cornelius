package tlshandshake

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"sort"
)

// randomInt returns a uniform random int in [lo, hi). Falls back to the
// midpoint when the crypto RNG is unavailable, so splitting never fails.
func randomInt(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	if err != nil {
		return (lo + hi) / 2
	}
	return lo + int(n.Int64())
}

func SplitClientHello(record []byte, sni string, micro bool) [][]byte {
	if len(record) < 48 || record[0] != 0x16 {
		return [][]byte{record}
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	if 5+recLen != len(record) {
		return [][]byte{record}
	}

	verMajor, verMinor := record[1], record[2]
	payload := record[5:]
	sniBytes := []byte(sni)
	sniIdx := bytes.Index(payload, sniBytes)

	// Randomized cuts: fixed cut points are a fingerprint — a DPI that
	// learns them can reassemble around them. Every split still cuts
	// through the SNI itself, so the hostname never appears whole in one
	// record, but where the cut falls is unpredictable per connection.
	cutSet := make(map[int]struct{})
	addCut := func(c int) {
		if c > 0 && c < len(payload) {
			cutSet[c] = struct{}{}
		}
	}
	if sniIdx > 0 && len(sniBytes) > 1 {
		// Mandatory cut strictly inside the SNI span: a cut exactly at its
		// start would leave the hostname whole in the next record.
		addCut(randomInt(sniIdx+1, sniIdx+len(sniBytes)))
	} else {
		// No SNI found: cut somewhere in the middle third.
		addCut(randomInt(len(payload)/3, 2*len(payload)/3))
	}
	if micro && len(payload) > 64 {
		// 1–2 extra cuts anywhere, for 3–4 fragments instead of a fixed 3.
		for i := 0; i < 1+randomInt(0, 2); i++ {
			addCut(randomInt(8, len(payload)-8))
		}
	}

	cuts := make([]int, 0, len(cutSet))
	for c := range cutSet {
		cuts = append(cuts, c)
	}
	sort.Ints(cuts)

	var chunks [][]byte
	prev := 0
	for _, c := range cuts {
		if c > prev && c < len(payload) {
			chunks = append(chunks, payload[prev:c])
			prev = c
		}
	}
	chunks = append(chunks, payload[prev:])

	out := make([][]byte, 0, len(chunks))
	for _, chunk := range chunks {
		if len(chunk) == 0 {
			continue
		}
		hdr := []byte{0x16, verMajor, verMinor, 0, 0}
		binary.BigEndian.PutUint16(hdr[3:5], uint16(len(chunk)))
		frag := make([]byte, 0, 5+len(chunk))
		frag = append(frag, hdr...)
		frag = append(frag, chunk...)
		out = append(out, frag)
	}
	return out
}

func BuildDecoyClientHello(realRecord []byte, realSNI, decoySNI string) []byte {
	decoy := make([]byte, len(realRecord))
	copy(decoy, realRecord)
	if len(realSNI) == 0 {
		return decoy
	}
	idx := bytes.Index(decoy, []byte(realSNI))
	if idx < 0 {
		return decoy
	}
	template := decoySNI
	if template == "" || template == realSNI {
		template = "www.cloudflare.com.cdn.cloudflare.net"
	}
	replacement := make([]byte, len(realSNI))
	for i := range replacement {
		replacement[i] = template[i%len(template)]
	}
	copy(decoy[idx:idx+len(realSNI)], replacement)
	return decoy
}
