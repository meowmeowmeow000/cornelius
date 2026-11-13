//go:build linux

package netraw

import (
	"net"
	"sync"
	"syscall"
	"time"
)

type seqEntry struct {
	Seq       uint32
	Ack       uint32
	CreatedAt time.Time
}

type DecoyInjector struct {
	mu       sync.Mutex
	seqTable map[uint16]seqEntry
}

func NewDecoyInjector() *DecoyInjector {
	inj := &DecoyInjector{
		seqTable: make(map[uint16]seqEntry),
	}
	go inj.evictLoop()
	return inj
}

func (inj *DecoyInjector) evictLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		inj.mu.Lock()
		for port, entry := range inj.seqTable {
			if now.Sub(entry.CreatedAt) > 15*time.Second {
				delete(inj.seqTable, port)
			}
		}
		inj.mu.Unlock()
	}
}

func (inj *DecoyInjector) InjectOutOfWindowDecoy(localAddr, remoteAddr net.Addr, decoyPayload []byte, decoyTTL uint8) error {
	lTCP, ok1 := localAddr.(*net.TCPAddr)
	rTCP, ok2 := remoteAddr.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil
	}
	dst4 := rTCP.IP.To4()
	src4 := lTCP.IP.To4()
	if dst4 == nil || src4 == nil {
		return nil
	}
	if decoyTTL == 0 {
		decoyTTL = 3
	}

	pkt := BuildIPv4TCPPacket(
		src4,
		dst4,
		uint16(lTCP.Port),
		uint16(rTCP.Port),
		0x7FFF0001,
		0x00000001,
		decoyTTL,
		decoyPayload,
	)
	if len(pkt) == 0 {
		return nil
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	var addr syscall.SockaddrInet4
	addr.Port = rTCP.Port
	copy(addr.Addr[:], dst4)
	return syscall.Sendto(fd, pkt, 0, &addr)
}
