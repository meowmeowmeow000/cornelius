//go:build linux

package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/unix"

	"cornelius/internal/bpf"
)

const (
	defaultMaxEchoHops  = 20
	defaultEchoStepWait = 350 * time.Millisecond
	defaultDecoyTTL     = 3
)

type HopObservation struct {
	TTL      uint8         `json:"ttl"`
	RouterIP string        `json:"router_ip,omitempty"`
	Event    string        `json:"event"`
	RTT      time.Duration `json:"rtt_ns"`
	Detail   string        `json:"detail,omitempty"`
}

type EcholocationReport struct {
	TargetIP            string           `json:"target_ip"`
	TargetPort          int              `json:"target_port"`
	ProbeSNI            string           `json:"probe_sni"`
	DPIIntercepted      bool             `json:"dpi_intercepted"`
	DPIDistanceHops     int              `json:"dpi_distance_hops"`
	ServerDistanceHops  int              `json:"server_distance_hops,omitempty"`
	RecommendedDecoyTTL uint8            `json:"recommended_decoy_ttl"`
	Hops                []HopObservation `json:"hops"`
}

func EcholocateDPI(ctx context.Context, targetIP string, port int, probeSNI string, maxHops int) (*EcholocationReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid target IP %q", targetIP)
	}
	if port <= 0 {
		port = 443
	}
	if probeSNI == "" {
		return nil, fmt.Errorf("probeSNI is required for DPI echolocation")
	}
	if maxHops <= 0 || maxHops > 64 {
		maxHops = defaultMaxEchoHops
	}

	report := &EcholocationReport{
		TargetIP:            ip.String(),
		TargetPort:          port,
		ProbeSNI:            probeSNI,
		RecommendedDecoyTTL: defaultDecoyTTL,
		Hops:                make([]HopObservation, 0, maxHops),
	}

	helloBytes, err := buildProbeClientHello(probeSNI)
	if err != nil {
		return nil, fmt.Errorf("build probe ClientHello: %w", err)
	}

	for hop := 1; hop <= maxHops; hop++ {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}

		obs := probeSingleHop(ctx, ip, port, uint8(hop), helloBytes)
		report.Hops = append(report.Hops, obs)

		switch obs.Event {
		case "dpi_rst":
			report.DPIIntercepted = true
			report.DPIDistanceHops = hop
			report.RecommendedDecoyTTL = uint8(hop)
			return report, nil

		case "server_hello":
			report.ServerDistanceHops = hop
			if !report.DPIIntercepted && hop > 1 {
				decoy := hop - 1
				if decoy > 6 {
					decoy = 6
				}
				report.RecommendedDecoyTTL = uint8(decoy)
			}
			return report, nil
		}
	}

	return report, nil
}

func probeSingleHop(ctx context.Context, targetIP net.IP, port int, hopTTL uint8, clientHello []byte) HopObservation {
	obs := HopObservation{
		TTL:   hopTTL,
		Event: "timeout",
	}

	isV6 := targetIP.To4() == nil
	network := "tcp4"
	if isV6 {
		network = "tcp6"
	}

	stepCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	rawConn, err := dialer.DialContext(stepCtx, network, net.JoinHostPort(targetIP.String(), strconv.Itoa(port)))
	if err != nil {
		obs.Detail = fmt.Sprintf("tcp dial failed: %v", err)
		return obs
	}
	defer rawConn.Close()

	tcpConn, ok := rawConn.(*net.TCPConn)
	if !ok {
		obs.Detail = "non-TCP connection returned"
		return obs
	}
	_ = tcpConn.SetNoDelay(true)

	sysConn, err := tcpConn.SyscallConn()
	if err != nil {
		obs.Detail = fmt.Sprintf("syscall conn unavailable: %v", err)
		return obs
	}

	var sockErr error
	if err := sysConn.Control(func(fd uintptr) {
		if isV6 {
			if e := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1); e != nil {
				sockErr = e
				return
			}
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, int(hopTTL))
		} else {
			if e := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1); e != nil {
				sockErr = e
				return
			}
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, int(hopTTL))
		}
	}); err != nil {
		obs.Detail = fmt.Sprintf("socket control failed: %v", err)
		return obs
	}
	if sockErr != nil {
		obs.Detail = fmt.Sprintf("setsockopt failed: %v", sockErr)
		return obs
	}

	dropsBefore := bpf.GetDropCount()
	start := time.Now()
	_ = tcpConn.SetDeadline(start.Add(defaultEchoStepWait))

	if _, err := tcpConn.Write(clientHello); err != nil {
		obs.RTT = time.Since(start)
		if isResetError(err) {
			obs.Event = "dpi_rst"
			obs.Detail = "TCP RST on ClientHello write"
			return obs
		}
		if routerIP, ok := readICMPTimeExceeded(sysConn, isV6); ok {
			obs.Event = "icmp_time_exceeded"
			obs.RouterIP = routerIP
			return obs
		}
		obs.Detail = err.Error()
		return obs
	}

	buf := make([]byte, 64)
	n, readErr := tcpConn.Read(buf)
	obs.RTT = time.Since(start)

	if routerIP, ok := readICMPTimeExceeded(sysConn, isV6); ok {
		obs.Event = "icmp_time_exceeded"
		obs.RouterIP = routerIP
		return obs
	}

	if bpf.GetDropCount() > dropsBefore {
		obs.Event = "dpi_rst"
		obs.Detail = "forged DPI RST caught by XDP shield"
		return obs
	}

	if n >= 3 && buf[0] == 0x16 && buf[1] == 0x03 {
		obs.Event = "server_hello"
		obs.Detail = "reached destination TLS endpoint"
		return obs
	}

	if readErr != nil {
		if isResetError(readErr) || errors.Is(readErr, net.ErrClosed) {
			obs.Event = "dpi_rst"
			obs.Detail = fmt.Sprintf("middlebox reset: %v", readErr)
			return obs
		}
		if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
			obs.Event = "timeout"
			obs.Detail = "no reply within step window"
			return obs
		}
		obs.Detail = readErr.Error()
	}

	return obs
}

func readICMPTimeExceeded(sysConn syscall.RawConn, isV6 bool) (string, bool) {
	var routerIP string
	var matched bool

	_ = sysConn.Control(func(fd uintptr) {
		var dataBuf [128]byte
		var oobBuf [512]byte

		for {
			_, oobn, _, _, err := unix.Recvmsg(int(fd), dataBuf[:], oobBuf[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			if err != nil || oobn <= 0 {
				break
			}

			scms, err := unix.ParseSocketControlMessage(oobBuf[:oobn])
			if err != nil {
				continue
			}

			for _, scm := range scms {
				if len(scm.Data) < 24 {
					continue
				}
				origin := scm.Data[4]
				icmpType := scm.Data[5]

				if !isV6 && scm.Header.Level == unix.SOL_IP && scm.Header.Type == unix.IP_RECVERR {
					if origin == unix.SO_EE_ORIGIN_ICMP && icmpType == 11 {
						routerIP = net.IP(scm.Data[20:24]).String()
						matched = true
						return
					}
				}
				if isV6 && scm.Header.Level == unix.SOL_IPV6 && scm.Header.Type == unix.IPV6_RECVERR {
					if origin == unix.SO_EE_ORIGIN_ICMP6 && icmpType == 3 && len(scm.Data) >= 40 {
						routerIP = net.IP(scm.Data[24:40]).String()
						matched = true
						return
					}
				}
			}
		}
	})

	return routerIP, matched
}

func isResetError(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE)
}

func buildProbeClientHello(sni string) ([]byte, error) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		uConn := utls.UClient(clientConn, &utls.Config{ServerName: sni}, utls.HelloChrome_Auto)
		errCh <- uConn.Handshake()
	}()

	_ = serverConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	hdr := make([]byte, 5)
	if _, err := serverConn.Read(hdr); err != nil {
		return nil, err
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	body := make([]byte, recLen)
	total := 0
	for total < recLen {
		n, err := serverConn.Read(body[total:])
		if err != nil {
			return nil, err
		}
		total += n
	}

	hello := make([]byte, 0, 5+recLen)
	hello = append(hello, hdr...)
	hello = append(hello, body...)
	return hello, nil
}
