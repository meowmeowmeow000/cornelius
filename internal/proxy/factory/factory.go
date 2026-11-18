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
	"cornelius/internal/telemetry"
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
	case "chrome_131":
		return utls.HelloChrome_131
	case "chrome_133":
		return utls.HelloChrome_133
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
	// ECHEnabled turns on Encrypted ClientHello when the Worker host
	// publishes an ECH config. Fetch failure or a server rejection falls
	// back to dialing without ECH — never a failed dial.
	ECHEnabled bool
	// ECHRequired is strict mode (fail closed): with no usable ECH config,
	// or a server that rejects ECH, DialStealthTunnel refuses to dial
	// instead of falling back to plain TLS. Needs ECHEnabled; the dialer
	// enforces that itself, so a profile that sets it without ECHEnabled
	// fails loudly instead of silently dialling plain.
	ECHRequired bool
	// ECHConfigB64 is a pasted ECHConfigList (base64) from the profile.
	// When set it replaces the DoH fetch.
	ECHConfigB64 string
	// ECHRejectionVerify, if set, verifies a server that rejects ECH (the
	// outer certificate, for the ECH public name). Nil means the default:
	// verify against the system roots, ignoring InsecureSkipVerify — that
	// is the point, a middlebox that strips ECH must not silently
	// downgrade the connection. The dialer retries without ECH only after
	// this verification passes; a failed verification aborts the dial.
	ECHRejectionVerify func(utls.ConnectionState) error
}

func DialStealthTunnel(ctx context.Context, cfg StealthDialConfig) (net.Conn, error) {
	if cfg.ECHRequired && !cfg.ECHEnabled {
		return nil, fmt.Errorf("strict ECH required but ECH is not enabled: refusing to dial plain")
	}

	var echList []byte
	var echPublic string
	if cfg.ECHEnabled && cfg.Route.CleanSNI != "" {
		if cfg.ECHConfigB64 != "" {
			// A pasted config replaces the DoH fetch: the networks
			// that need strict mode most are the ones where DoH
			// itself is blocked.
			list, err := DecodeECHConfigB64(cfg.ECHConfigB64)
			if err != nil {
				if cfg.ECHRequired {
					return nil, fmt.Errorf("strict ECH required but the pasted config is unusable: %w", err)
				}
				telemetry.Log.Warn("Pasted ECH config is unusable, fetching over DoH", "host", cfg.Route.CleanSNI, "err", err.Error())
			} else {
				echList = list
				echPublic, _ = ECHPublicName(list)
			}
		}
		if echList == nil {
			list, err := FetchECHConfigList(ctx, cfg.Route.CleanSNI)
			if err != nil {
				if cfg.ECHRequired {
					return nil, fmt.Errorf("strict ECH required but no config could be fetched: %w", err)
				}
				telemetry.Log.Warn("ECH config fetch failed, dialing without ECH", "host", cfg.Route.CleanSNI, "err", err.Error())
			} else {
				echList = list
				// The public name is the outer SNI the fragmenter
				// cuts through. A config that will not parse is
				// unusable in strict mode; without it, keep the old
				// lenient path.
				name, perr := ECHPublicName(list)
				if perr != nil {
					if cfg.ECHRequired {
						return nil, fmt.Errorf("strict ECH required but the fetched config does not parse: %w", perr)
					}
					telemetry.Log.Warn("ECH config does not parse, dialing without a public name", "host", cfg.Route.CleanSNI, "err", perr.Error())
				}
				echPublic = name
			}
		}
	}

	conn, err := dialOnce(ctx, cfg, echList, echPublic)
	if err == nil {
		return conn, nil
	}
	if echList != nil && isECHRejection(err) {
		if cfg.ECHRequired {
			// Fail closed: a server that strips ECH must not silently
			// downgrade the connection to a visible SNI.
			return nil, fmt.Errorf("strict ECH required: server rejected ECH: %w", err)
		}
		// The server rejected ECH: retry once without it. The next dial
		// re-fetches fresh configs from DoH, so a retry-config update is
		// picked up then instead of being chased here.
		telemetry.Log.Warn("Server rejected ECH, retrying without it", "host", cfg.Route.CleanSNI)
		return dialOnce(ctx, cfg, nil, "")
	}
	return nil, err
}

func dialOnce(ctx context.Context, cfg StealthDialConfig, echList []byte, echPublic string) (net.Conn, error) {
	port := cfg.Route.TargetPort
	if port == 0 {
		port = 443
	}

	dir, outerSNI, innerHost := ResolveSNIDirection(cfg.Route)

	// With ECH, the outer SNI is the ECH public name (from the config) and
	// the inner SNI — the one the certificate is verified against — is the
	// Worker host. Fronting is meaningless then: the config fixes the
	// outer name, so force legacy.
	serverName := outerSNI
	fragSNI := outerSNI
	if echList != nil {
		dir = config.SNISPFDirectionLegacy
		serverName = innerHost
		if echPublic != "" {
			fragSNI = echPublic
		} else {
			fragSNI = innerHost
		}
	}

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
		sni:         fragSNI,
		decoySNI:    decoySNI,
		decoyTTL:    cfg.Route.DecoyTTL,
		mode:        cfg.Route.StealthMode,
		fragDelayMs: cfg.FragDelayMs,
		jitterMs:    cfg.JitterMs,
		firstWrite:  true,
	}

	tlsCfg := &utls.Config{
		ServerName: serverName,
		// Force HTTP/1.1 ALPN: the Chrome fingerprint advertises h2, but the
		// WebSocket upgrade below is a raw HTTP/1.1 request. Negotiating h2
		// makes Cloudflare reject the upgrade (200 OK / EOF). Setting
		// NextProtos here alone does NOT force it — the fingerprint's ALPN
		// extension overwrites it — so NewStealthUConn rewrites the ALPN
		// extension inside the fingerprint spec itself. See alpn.go.
		NextProtos:                     []string{"http/1.1"},
		InsecureSkipVerify:             cfg.AllowInsec,
		EncryptedClientHelloConfigList: echList,
	}
	if cfg.ECHRejectionVerify != nil {
		tlsCfg.EncryptedClientHelloRejectionVerify = cfg.ECHRejectionVerify
	}
	uConn, err := NewStealthUConn(wrapped, tlsCfg, PickFingerprint(cfg.Route.Fingerprint))
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
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
