package netraw

import (
	"encoding/binary"
	"net"
)

func BuildIPv4TCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, ttl uint8, payload []byte) []byte {
	s4 := srcIP.To4()
	d4 := dstIP.To4()
	if s4 == nil || d4 == nil {
		return nil
	}

	const ipHdrLen = 20
	const tcpHdrLen = 20
	totalLen := ipHdrLen + tcpHdrLen + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = (4 << 4) | (ipHdrLen / 4)
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x4210)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = ttl
	pkt[9] = 6
	pkt[10] = 0
	pkt[11] = 0
	copy(pkt[12:16], s4)
	copy(pkt[16:20], d4)
	binary.BigEndian.PutUint16(pkt[10:12], rfc1071Checksum(pkt[:ipHdrLen]))

	tcp := pkt[ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = (tcpHdrLen / 4) << 4
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	tcp[16] = 0
	tcp[17] = 0
	tcp[18] = 0
	tcp[19] = 0
	copy(tcp[tcpHdrLen:], payload)

	tcpLen := tcpHdrLen + len(payload)
	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo[0:4], s4)
	copy(pseudo[4:8], d4)
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:18], rfc1071Checksum(pseudo))

	return pkt
}

func rfc1071Checksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
