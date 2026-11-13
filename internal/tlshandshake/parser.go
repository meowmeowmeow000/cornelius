package tlshandshake

import (
	"bytes"
	"encoding/binary"
)

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

	var cuts []int
	if micro && len(payload) > 64 {
		cut1 := 37
		cut2 := len(payload) / 2
		if sniIdx > cut1 {
			cut2 = sniIdx + (len(sniBytes) / 2)
		}
		if cut2 <= cut1 || cut2 >= len(payload) {
			cut2 = (cut1 + len(payload)) / 2
		}
		cuts = []int{cut1, cut2}
	} else {
		cut := len(payload) / 2
		if sniIdx > 0 {
			cut = sniIdx + (len(sniBytes) / 2)
		}
		if cut <= 0 || cut >= len(payload) {
			cut = len(payload) / 2
		}
		cuts = []int{cut}
	}

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
