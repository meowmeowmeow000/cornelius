package factory

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"cornelius/internal/config"
	"cornelius/internal/netraw"
	"cornelius/internal/tlshandshake"
)

const (
	ModeTLSFrag      = "tls_frag"
	ModeTLSMicroFrag = "tls_micro_frag"
	ModeTLSDisorder  = "tls_disorder"
	ModeSNIFront     = "sni_front"
)

var injector = netraw.NewDecoyInjector()

func ResolveFingerprint(fp string) utls.ClientHelloID {
	switch fp {
	case "ios_auto":
		return utls.HelloIOS_Auto
	case "firefox_auto":
		return utls.HelloFirefox_Auto
	case "edge_auto":
		return utls.HelloEdge_Auto
	case "randomized":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

func ResolveSNIDirection(route config.RouteCandidate) (direction, outerSNI, innerHost string) {
	innerHost = route.CleanSNI
	dir := route.SNISPFDirection
	if dir == "" {
		switch {
		case route.StealthMode == ModeSNIFront:
			dir = config.SNISPFDirectionFronting
		case route.SpoofSNI != "" && route.SpoofSNI != route.CleanSNI:
			dir = config.SNISPFDirectionFronting
		default:
			dir = config.SNISPFDirectionLegacy
		}
	}

	if dir == config.SNISPFDirectionFronting {
		if route.SpoofSNI != "" {
			return config.SNISPFDirectionFronting, route.SpoofSNI, innerHost
		}
		// Fronting without a distinct outer SNI is a no-op and can accidentally look
		// like legacy traffic while still claiming a fronting direction. Fall back to
		// legacy instead of silently treating an invalid fronting route as active.
		return config.SNISPFDirectionLegacy, innerHost, innerHost
	}
	return config.SNISPFDirectionLegacy, innerHost, innerHost
}

type StealthDialConfig struct {
	Route       config.RouteCandidate
	FragDelayMs int
	JitterMs    int
	AllowInsec  bool
	WSPath      string
}

func DialStealthTunnel(ctx context.Context, cfg StealthDialConfig) (net.Conn, error) {
	port := cfg.Route.TargetPort
	if port == 0 {
		port = 443
	}

	dir, outerSNI, innerHost := ResolveSNIDirection(cfg.Route)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	network := "tcp4"
	if ip := net.ParseIP(cfg.Route.TargetIP); ip != nil && ip.To4() == nil {
		network = "tcp6"
	}

	rawConn, err := dialer.DialContext(ctx, network, net.JoinHostPort(cfg.Route.TargetIP, strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}

	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}

	decoySNI := cfg.Route.SpoofSNI
	if dir == config.SNISPFDirectionFronting {
		decoySNI = "www.cloudflare.com.cdn.cloudflare.net"
	}

	wrapped := &fragmentingConn{
		Conn:        rawConn,
		sni:         outerSNI,
		decoySNI:    decoySNI,
		decoyTTL:    cfg.Route.DecoyTTL,
		mode:        cfg.Route.StealthMode,
		fragDelayMs: cfg.FragDelayMs,
		jitterMs:    cfg.JitterMs,
		firstWrite:  true,
	}

	tlsCfg := &utls.Config{
		ServerName: outerSNI,
		// Force HTTP/1.1 ALPN: the Chrome fingerprint advertises h2, but the
		// WebSocket upgrade below is a raw HTTP/1.1 request. Negotiating h2
		// makes Cloudflare reject the upgrade (200 OK / EOF).
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: cfg.AllowInsec,
	}
	uConn := utls.UClient(wrapped, tlsCfg, ResolveFingerprint(cfg.Route.Fingerprint))
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake failed (dir=%s outer=%s): %w", dir, outerSNI, err)
	}

	wsPath := cfg.WSPath
	if wsPath == "" {
		wsPath = cfg.Route.WSPath
	}
	if wsPath != "" {
		if err := upgradeWebSocket(uConn, innerHost, wsPath); err != nil {
			_ = uConn.Close()
			return nil, err
		}
	}

	return uConn, nil
}

type fragmentingConn struct {
	net.Conn
	sni         string
	decoySNI    string
	decoyTTL    uint8
	mode        string
	fragDelayMs int
	jitterMs    int
	firstWrite  bool
}

func (f *fragmentingConn) Write(p []byte) (int, error) {
	if !f.firstWrite {
		return f.Conn.Write(p)
	}
	f.firstWrite = false

	if f.mode == ModeTLSDisorder {
		ttl := f.decoyTTL
		if ttl == 0 {
			ttl = 3
		}
		decoy := tlshandshake.BuildDecoyClientHello(p, f.sni, f.decoySNI)
		_ = injector.InjectOutOfWindowDecoy(f.Conn.LocalAddr(), f.Conn.RemoteAddr(), decoy, ttl)
	}

	micro := f.mode == ModeTLSMicroFrag || f.mode == ModeTLSDisorder
	records := tlshandshake.SplitClientHello(p, f.sni, micro)
	baseDelay := f.fragDelayMs
	if baseDelay <= 0 {
		baseDelay = 2
	}

	for i, rec := range records {
		if _, err := f.Conn.Write(rec); err != nil {
			return 0, err
		}
		if i < len(records)-1 {
			sleepMs := baseDelay
			if f.jitterMs > 0 {
				if n, err := rand.Int(rand.Reader, big.NewInt(int64(f.jitterMs)+1)); err == nil {
					sleepMs += int(n.Int64())
				}
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
	}
	return len(p), nil
}

func upgradeWebSocket(conn net.Conn, host, path string) error {
	var keyBytes [16]byte
	_, _ = rand.Read(keyBytes[:])
	wsKey := base64.StdEncoding.EncodeToString(keyBytes[:])

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36\r\n\r\n",
		path, host, wsKey,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(statusLine, "101") {
		return fmt.Errorf("unexpected websocket upgrade status: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return nil
}
