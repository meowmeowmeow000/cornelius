package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/unix"

	"cornelius/internal/bpf"
	"cornelius/internal/config"
	"cornelius/internal/proxy/factory"
)

var FingerprintMap = map[string]utls.ClientHelloID{
	"chrome_auto":  utls.HelloChrome_Auto,
	"ios_auto":     utls.HelloIOS_Auto,
	"firefox_auto": utls.HelloFirefox_Auto,
	"edge_auto":    utls.HelloEdge_Auto,
	"randomized":   utls.HelloRandomized,
}

func DialStealthProbe(ctx context.Context, task ProbeTask) (*ProbeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	port := task.Port
	if port <= 0 {
		port = 443
	}
	dir := task.Direction
	if dir == "" {
		if task.SpoofSNI != "" && task.SpoofSNI != task.TargetSNI {
			dir = config.SNISPFDirectionFronting
		} else {
			dir = config.SNISPFDirectionLegacy
		}
	}
	outerSNI := task.TargetSNI
	if dir == config.SNISPFDirectionFronting && task.SpoofSNI != "" {
		outerSNI = task.SpoofSNI
	}

	res := &ProbeResult{
		IP:          task.IP,
		Port:        port,
		Direction:   dir,
		SpoofSNI:    task.SpoofSNI,
		SNI:         task.TargetSNI,
		Fingerprint: task.Fingerprint,
		Mode:        task.Mode,
	}
	if net.ParseIP(task.IP) == nil {
		res.ErrStr = "target must be an IP address"
		return res, fmt.Errorf("%s", res.ErrStr)
	}
	if task.TargetSNI == "" {
		res.ErrStr = "target SNI is required"
		return res, fmt.Errorf("%s", res.ErrStr)
	}
	if task.Timeout <= 0 {
		task.Timeout = defaultTimeout
	}
	if task.Timeout > maxProbeTimeout {
		task.Timeout = maxProbeTimeout
	}

	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, task.Timeout)
	defer cancel()

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(task.IP, strconv.Itoa(port)))
	if err != nil {
		res.ErrStr = err.Error()
		return res, err
	}
	defer rawConn.Close()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	wireConn := newStealthFragmentConn(rawConn, outerSNI, task.Mode)

	// The probe verifies the WebSocket upgrade, so it needs the same
	// http/1.1-only ALPN as the tunnel dial: a fingerprint that offers
	// h2 negotiates h2, and the HTTP/1.1 upgrade over it dies with EOF.
	// See factory.NewStealthUConn — setting NextProtos alone does not
	// force it, the fingerprint's ALPN extension overwrites it.
	tlsConfig := &utls.Config{ServerName: outerSNI}
	uConn, err := factory.NewStealthUConn(wireConn, tlsConfig, task.ClientHello)
	if err != nil {
		res.ErrStr = fmt.Sprintf("could not build stealth connection: %v", err)
		return res, err
	}
	if err := uConn.HandshakeContext(dialCtx); err != nil {
		res.ErrStr = fmt.Sprintf("TLS handshake failed: %v", err)
		return res, err
	}

	res.Latency = time.Since(start)
	res.Success = true

	// A TLS handshake alone does not prove the tunnel works — verify the
	// WebSocket upgrade and the SMUX keepalive echo when we know the path.
	if task.WSPath != "" {
		ok, reason := verifyTunnel(dialCtx, uConn, task.TargetSNI, task.WSPath)
		res.WSVerified = ok
		res.VerifyErr = reason
	}

	if ttl := bpf.LookupFlowTTL(rawConn.LocalAddr(), rawConn.RemoteAddr()); ttl > 0 {
		res.ExpectedTTL = ttl
	} else {
		res.ExpectedTTL = probeSocketPeerTTL(rawConn, uConn)
	}

	return res, nil
}

func probeSocketPeerTTL(rawConn net.Conn, uConn *utls.UConn) uint8 {
	tcpConn, ok := rawConn.(*net.TCPConn)
	if !ok {
		return 0
	}
	sysConn, err := tcpConn.SyscallConn()
	if err != nil {
		return 0
	}

	isV6 := tcpConn.RemoteAddr().(*net.TCPAddr).IP.To4() == nil
	setMinTTL := func(minVal int) error {
		var sockErr error
		if err := sysConn.Control(func(fd uintptr) {
			if isV6 {
				const ipv6MinHopCnt = 73 // Linux uapi/linux/in6.h IPV6_MINHOPCNT
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, ipv6MinHopCnt, minVal)
			} else {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MINTTL, minVal)
			}
		}); err != nil {
			return err
		}
		return sockErr
	}

	low, high := 1, 255
	var detected uint8
	for low <= high {
		mid := (low + high) / 2
		if err := setMinTTL(mid); err != nil {
			break
		}
		_ = tcpConn.SetDeadline(time.Now().Add(120 * time.Millisecond))
		if _, err := uConn.Write([]byte{}); err != nil {
			high = mid - 1
			continue
		}
		var peekErr error
		_ = sysConn.Control(func(fd uintptr) {
			val, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
			if err != nil || val != 0 {
				peekErr = syscall.ECONNRESET
			}
		})
		if peekErr != nil {
			high = mid - 1
		} else {
			detected = uint8(mid)
			low = mid + 1
		}
	}
	_ = setMinTTL(1)
	return detected
}

type stealthFragmentConn struct {
	net.Conn
	sni        []byte
	mode       StealthMode
	firstWrite bool
}

func newStealthFragmentConn(c net.Conn, sni string, mode StealthMode) *stealthFragmentConn {
	return &stealthFragmentConn{
		Conn:       c,
		sni:        []byte(sni),
		mode:       mode,
		firstWrite: true,
	}
}

func (c *stealthFragmentConn) Write(p []byte) (int, error) {
	if !c.firstWrite || c.mode == "" {
		return c.Conn.Write(p)
	}
	c.firstWrite = false

	records := splitTLSClientHelloRecord(p, c.sni, c.mode)
	if len(records) <= 1 {
		return c.Conn.Write(p)
	}

	delay := 1 * time.Millisecond
	if c.mode == ModeTLSMicroFrag {
		delay = 3 * time.Millisecond
	}

	for i, rec := range records {
		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
		if i < len(records)-1 {
			time.Sleep(delay)
		}
	}
	return len(p), nil
}

func splitTLSClientHelloRecord(record []byte, sni []byte, mode StealthMode) [][]byte {
	if len(record) < 48 || record[0] != 0x16 {
		return [][]byte{record}
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	if 5+recLen != len(record) {
		return [][]byte{record}
	}

	verMajor, verMinor := record[1], record[2]
	payload := record[5:]

	sniIdx := bytes.Index(payload, sni)
	var cuts []int
	if mode == ModeTLSMicroFrag && len(payload) > 64 {
		cut1 := 37
		cut2 := len(payload) / 2
		if sniIdx > cut1 {
			cut2 = sniIdx + (len(sni) / 2)
		}
		if cut2 <= cut1 || cut2 >= len(payload) {
			cut2 = (cut1 + len(payload)) / 2
		}
		cuts = []int{cut1, cut2}
	} else {
		cut := len(payload) / 2
		if sniIdx > 0 {
			cut = sniIdx + (len(sni) / 2)
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
