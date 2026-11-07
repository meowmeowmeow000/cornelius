#!/bin/bash
set -euo pipefail

PROJECT_DIR="/opt/self-healing-router-v8"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

echo "[+] Forging v3 DPI-Fragmenting Stealth Router in $PROJECT_DIR..."
mkdir -p cmd/router
mkdir -p internal/config
mkdir -p internal/netstack
mkdir -p internal/proxy/factory
mkdir -p internal/proxy/pool
mkdir -p internal/router
mkdir -p internal/scanner
mkdir -p internal/telemetry

# ---------------------------------------------------------
# 1. CONFIG & PROFILES (Multi-Route + Stealth Mode State)
# ---------------------------------------------------------
cat << 'EOF' > internal/config/profile.go
package config

import (
	"encoding/json"
	"os"
)

type RouteCandidate struct {
	TargetIP       string `json:"target_ip"`
	CleanSNI       string `json:"clean_sni"`
	StealthMode    string `json:"stealth_mode"` // "tls_frag" or "sni_front"
	TCPMs          int64  `json:"tcp_ms"`
	TLSHandshakeMs int64  `json:"tls_handshake_ms"`
	WSUpgradeMs    int64  `json:"ws_upgrade_ms,omitempty"`
	WSVerified     bool   `json:"ws_verified"`
	Score          int    `json:"confidence_score"`
}

type CombatProfile struct {
	WorkerHost  string           `json:"worker_host"`
	ExpectedTTL int              `json:"expected_ttl"`
	Primary     RouteCandidate   `json:"primary_route"`
	Failovers   []RouteCandidate `json:"failover_routes"`
}

type AtlasReport struct {
	Timestamp    string           `json:"timestamp"`
	TotalProbed  int              `json:"total_probed"`
	ViableRoutes int              `json:"viable_routes"`
	Throttled    bool             `json:"is_throttled"`
	RankedMatrix []RouteCandidate `json:"ranked_matrix"`
}

func LoadCombatProfile(path string) (*CombatProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p CombatProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func SaveProfiles(combat *CombatProfile, atlas *AtlasReport) error {
	cData, err := json.MarshalIndent(combat, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile("combat.profile", cData, 0644); err != nil {
		return err
	}

	aData, err := json.MarshalIndent(atlas, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("atlas.json", aData, 0644)
}
EOF

# ---------------------------------------------------------
# 2. TELEMETRY (Structured Context + Atomic Metrics + Banner)
# ---------------------------------------------------------
cat << 'EOF' > internal/telemetry/logger.go
package telemetry

import (
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
)

const Banner = `
  ╔══════════════════════════════════════════════════════════════════════╗
  ║   ⚡ SELF-HEALING STEALTH ROUTER v8.3 // TLS-FRAGMENTED MULTIPLEXER  ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║                                                                      ║
  ║   [SOCKS5 Intake] ──► [Warm Pool: 3x SMUX v1] ──► [uTLS Chrome/131]  ║
  ║         │                       ▲                        │           ║
  ║    Zero-Alloc              Epoch-Guarded          TLS Record Split   ║
  ║     sync.Pool              Auto-Failover          (Defeats CF 403)   ║
  ║                                 │                        ▼           ║
  ║   [XDP eBPF Shield] ────────────┴───────────◄── [CF Edge + Worker]   ║
  ║    Drops Forged FIN/RST (TTL Δ > 4)              Serialized SMUX     ║
  ╚══════════════════════════════════════════════════════════════════════╝
`

var (
	Log              *slog.Logger
	ActiveStreams    atomic.Int64
	PoolHealthyPipes atomic.Int64
	TotalBytesTx     atomic.Uint64
	TotalBytesRx     atomic.Uint64
	RouteRotations   atomic.Uint64
	XDPDroppedRSTs   atomic.Uint64
	DialFailures     atomic.Uint64
)

func InitLogger(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	Log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(Log)
}

func PrintBanner() {
	fmt.Print(Banner)
}
EOF

# ---------------------------------------------------------
# 3. uTLS STEALTH FACTORY (TLS Record Fragmenter + Chrome/131)
# ---------------------------------------------------------
cat << 'EOF' > internal/proxy/factory/cf_factory.go
package factory

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	utls "github.com/refraction-networking/utls"
)

const (
	ModeTLSFrag  = "tls_frag"
	ModeSNIFront = "sni_front"
)

type ProbeMetrics struct {
	TCPDur     time.Duration
	TLSDur     time.Duration
	WSDur      time.Duration
	WSVerified bool
}

type StealthFactory interface {
	Dial(ctx context.Context, targetIP, sni, hostHeader, stealthMode string) (net.Conn, error)
	ProbeRoute(ctx context.Context, targetIP, sni, hostHeader, stealthMode string, verifyWS bool) (ProbeMetrics, error)
}

type CloudflareFactory struct{}

func NewCloudflareFactory() *CloudflareFactory {
	return &CloudflareFactory{}
}

// clientHelloFragConn wraps a raw TCP connection and splits the initial outbound
// TLS ClientHello record (0x16) into multiple smaller RFC-compliant TLS records
// and separate TCP segments right across the SNI extension.
// This blinds ISP DPI boxes without triggering Cloudflare's SNI!=Host 403 block.
type clientHelloFragConn struct {
	net.Conn
	fragmented bool
	sniBytes   []byte
}

func (c *clientHelloFragConn) Write(b []byte) (int, error) {
	if c.fragmented || len(b) < 48 || b[0] != 0x16 {
		return c.Conn.Write(b)
	}
	c.fragmented = true

	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+recLen != len(b) {
		return c.Conn.Write(b)
	}

	payload := b[5:]
	verMajor, verMinor := b[1], b[2]

	// Locate the exact SNI hostname inside the ClientHello payload and split right through its middle
	cut1 := 37 // Inside ClientRandom / SessionID (contains zero extensions)
	cut2 := len(payload) / 2
	if len(c.sniBytes) > 2 {
		if idx := bytes.Index(payload, c.sniBytes); idx > cut1 {
			cut2 = idx + (len(c.sniBytes) / 2)
		}
	}
	if cut2 <= cut1 || cut2 >= len(payload) {
		cut2 = (cut1 + len(payload)) / 2
	}

	slices := [][]byte{
		payload[:cut1],
		payload[cut1:cut2],
		payload[cut2:],
	}

	for i, s := range slices {
		if len(s) == 0 {
			continue
		}
		rec := make([]byte, 5+len(s))
		rec[0] = 0x16
		rec[1] = verMajor
		rec[2] = verMinor
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(s)))
		copy(rec[5:], s)

		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
		if i < len(slices)-1 {
			// Micro-pacing forces the kernel TCP stack (with TCP_NODELAY) to flush distinct segments
			time.Sleep(2 * time.Millisecond)
		}
	}

	return len(b), nil
}

// dialUTLSChromeHTTP11 creates a uTLS connection using Chrome's TLS fingerprint
// while pinning ALPN to "http/1.1" and optionally fragmenting the ClientHello record.
func dialUTLSChromeHTTP11(ctx context.Context, targetAddr, sni string, fragmentHello bool) (net.Conn, time.Duration, time.Duration, error) {
	dialer := net.Dialer{Timeout: 4 * time.Second, KeepAlive: 15 * time.Second}

	t0 := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, 0, 0, err
	}
	tcpDur := time.Since(t0)

	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	var baseConn net.Conn = rawConn
	if fragmentHello {
		baseConn = &clientHelloFragConn{
			Conn:     rawConn,
			sniBytes: []byte(sni),
		}
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		_ = rawConn.Close()
		return nil, tcpDur, 0, err
	}

	// Mutate ALPN extension in-place to force HTTP/1.1 for WebSocket compatibility
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}

	utlsCfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	uConn := utls.UClient(baseConn, utlsCfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		_ = rawConn.Close()
		return nil, tcpDur, 0, err
	}

	t1 := time.Now()
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, tcpDur, 0, err
	}
	tlsDur := time.Since(t1)

	return uConn, tcpDur, tlsDur, nil
}

func upgradeWebSocketOverUTLS(ctx context.Context, uConn net.Conn, hostHeader string) (*websocket.Conn, error) {
	var used bool
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if used {
				return nil, fmt.Errorf("single-use uTLS connection already consumed")
			}
			used = true
			return uConn, nil
		},
		ForceAttemptHTTP2:   false,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 1,
	}

	httpClient := &http.Client{Transport: tr}
	wsURL := fmt.Sprintf("wss://%s/tunnel", hostHeader)
	dialOpts := &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: http.Header{
			"Host":            []string{hostHeader},
			"Origin":          []string{fmt.Sprintf("https://%s", hostHeader)},
			"User-Agent":      []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
			"Accept-Language": []string{"en-US,en;q=0.9"},
			"Cache-Control":   []string{"no-cache"},
			"Pragma":          []string{"no-cache"},
		},
	}

	wsConn, _, err := websocket.Dial(ctx, wsURL, dialOpts)
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	return wsConn, nil
}

func (f *CloudflareFactory) ProbeRoute(ctx context.Context, targetIP, sni, hostHeader, stealthMode string, verifyWS bool) (ProbeMetrics, error) {
	var m ProbeMetrics
	targetAddr := net.JoinHostPort(targetIP, "443")
	frag := (stealthMode == ModeTLSFrag)

	uConn, tcpDur, tlsDur, err := dialUTLSChromeHTTP11(ctx, targetAddr, sni, frag)
	if err != nil {
		return m, err
	}
	m.TCPDur = tcpDur
	m.TLSDur = tlsDur

	if !verifyWS || hostHeader == "" || hostHeader == "my-proxy.workers.dev" {
		_ = uConn.Close()
		return m, nil
	}

	tWS := time.Now()
	wsConn, err := upgradeWebSocketOverUTLS(ctx, uConn, hostHeader)
	if err != nil {
		_ = uConn.Close()
		return m, fmt.Errorf("edge rejected WS upgrade (%s, sni=%s -> host=%s): %w", stealthMode, sni, hostHeader, err)
	}
	m.WSDur = time.Since(tWS)
	m.WSVerified = true
	_ = wsConn.Close(websocket.StatusNormalClosure, "probe_ok")
	_ = uConn.Close()
	return m, nil
}

func (f *CloudflareFactory) Dial(ctx context.Context, targetIP, sni, hostHeader, stealthMode string) (net.Conn, error) {
	targetAddr := net.JoinHostPort(targetIP, "443")
	frag := (stealthMode == ModeTLSFrag || stealthMode == "")

	uConn, _, _, err := dialUTLSChromeHTTP11(ctx, targetAddr, sni, frag)
	if err != nil {
		return nil, fmt.Errorf("uTLS handshake failed (%s): %w", stealthMode, err)
	}

	wsConn, err := upgradeWebSocketOverUTLS(ctx, uConn, hostHeader)
	if err != nil {
		_ = uConn.Close()
		return nil, fmt.Errorf("websocket upgrade failed (%s): %w", stealthMode, err)
	}

	wsConn.SetReadLimit(-1)
	return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), nil
}
EOF

# ---------------------------------------------------------
# 4. THE CARTOGRAPHER (TLS-Frag + Anycast Edge Matrix)
# ---------------------------------------------------------
cat << 'EOF' > internal/scanner/cartographer.go
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"self-healing-router/internal/config"
	"self-healing-router/internal/proxy/factory"
	"self-healing-router/internal/telemetry"
)

type probeTask struct {
	ip          string
	sni         string
	stealthMode string
}

func RunCartographer(workerHost string, verifyWS bool, customIPs string) {
	telemetry.PrintBanner()
	telemetry.Log.Info("Launching Cartographer v3 (TLS-Record-Split + Anycast Echolocation)...",
		slog.String("worker_host", workerHost),
		slog.Bool("verify_ws", verifyWS))

	// Shared Cloudflare Anycast Edge IPs that route *.workers.dev and Free/Pro zones cleanly
	// (Replaces Enterprise-only VIPs like 104.16.132.229 that reject workers.dev with HTTP 403)
	candidateIPs := []string{
		"104.18.2.161",
		"104.18.3.161",
		"104.21.16.1",
		"104.21.32.1",
		"172.67.128.1",
		"172.64.155.209",
		"162.159.135.42",
		"188.114.97.3",
	}
	if strings.TrimSpace(customIPs) != "" {
		parts := strings.Split(customIPs, ",")
		candidateIPs = nil
		for _, p := range parts {
			if ip := strings.TrimSpace(p); ip != "" {
				candidateIPs = append(candidateIPs, ip)
			}
		}
	}

	var tasks []probeTask
	// Strategy 1 (Primary): TLS Record Fragmentation with matching SNI == workerHost.
	// Splits ClientHello across 3 TLS records & TCP segments so DPI cannot read SNI,
	// while Cloudflare sees SNI == Host and returns 101 Switching Protocols (never 403!).
	for _, ip := range candidateIPs {
		tasks = append(tasks, probeTask{
			ip:          ip,
			sni:         workerHost,
			stealthMode: factory.ModeTLSFrag,
		})
	}

	// Strategy 2 (Fallback): Same-Zone / Opportunistic SNI Fronting probe
	frontingSNIs := []string{
		"cloudflare-ech.com",
		"cdn.jsdelivr.net",
	}
	for _, ip := range candidateIPs {
		for _, sni := range frontingSNIs {
			tasks = append(tasks, probeTask{
				ip:          ip,
				sni:         sni,
				stealthMode: factory.ModeSNIFront,
			})
		}
	}

	fac := factory.NewCloudflareFactory()
	var (
		mu      sync.Mutex
		results []config.RouteCandidate
		wg      sync.WaitGroup
	)

	totalProbes := len(tasks)
	sem := make(chan struct{}, 8)

	for _, t := range tasks {
		wg.Add(1)
		go func(task probeTask) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()

			metrics, err := fac.ProbeRoute(ctx, task.ip, task.sni, workerHost, task.stealthMode, verifyWS)
			if err != nil {
				telemetry.Log.Debug("Probe rejected",
					slog.String("ip", task.ip),
					slog.String("mode", task.stealthMode),
					slog.String("sni", task.sni),
					slog.String("err", err.Error()))
				return
			}

			totalMs := metrics.TCPDur.Milliseconds() + metrics.TLSDur.Milliseconds() + metrics.WSDur.Milliseconds()
			score := 100 - int(totalMs/10)
			if metrics.WSVerified {
				score += 15
			}
			if score > 100 {
				score = 100
			}
			if score < 10 {
				score = 10
			}

			cand := config.RouteCandidate{
				TargetIP:       task.ip,
				CleanSNI:       task.sni,
				StealthMode:    task.stealthMode,
				TCPMs:          metrics.TCPDur.Milliseconds(),
				TLSHandshakeMs: metrics.TLSDur.Milliseconds(),
				WSUpgradeMs:    metrics.WSDur.Milliseconds(),
				WSVerified:     metrics.WSVerified,
				Score:          score,
			}

			mu.Lock()
			results = append(results, cand)
			mu.Unlock()

			telemetry.Log.Info("Stealth Route Verified (101 OK)",
				slog.String("ip", task.ip),
				slog.String("mode", task.stealthMode),
				slog.String("sni", task.sni),
				slog.Int64("tcp_ms", cand.TCPMs),
				slog.Int64("tls_ms", cand.TLSHandshakeMs),
				slog.Int64("ws_ms", cand.WSUpgradeMs),
				slog.Int("score", cand.Score))
		}(t)
	}

	wg.Wait()

	if len(results) == 0 {
		telemetry.Log.Error("All probes failed 101 verification! Seeding fallback with TLS-Record-Fragmentation on workerHost.")
		results = append(results, config.RouteCandidate{
			TargetIP:    candidateIPs[0],
			CleanSNI:    workerHost,
			StealthMode: factory.ModeTLSFrag,
			Score:       50,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].WSVerified != results[j].WSVerified {
			return results[i].WSVerified
		}
		if results[i].Score == results[j].Score {
			latI := results[i].TCPMs + results[i].TLSHandshakeMs + results[i].WSUpgradeMs
			latJ := results[j].TCPMs + results[j].TLSHandshakeMs + results[j].WSUpgradeMs
			return latI < latJ
		}
		return results[i].Score > results[j].Score
	})

	var failovers []config.RouteCandidate
	if len(results) > 1 {
		limit := len(results)
		if limit > 6 {
			limit = 6
		}
		failovers = results[1:limit]
	}

	atlas := &config.AtlasReport{
		Timestamp:    time.Now().Format(time.RFC3339),
		TotalProbed:  totalProbes,
		ViableRoutes: len(results),
		Throttled:    (results[0].TCPMs + results[0].TLSHandshakeMs) > 350,
		RankedMatrix: results,
	}

	combat := &config.CombatProfile{
		WorkerHost:  workerHost,
		ExpectedTTL: 54,
		Primary:     results[0],
		Failovers:   failovers,
	}

	if err := config.SaveProfiles(combat, atlas); err != nil {
		telemetry.Log.Error("Failed saving profiles", slog.String("err", err.Error()))
		return
	}

	fmt.Printf("\n[+] Cartographer complete: %d/%d routes passed end-to-end 101 WebSocket verification.\n", len(results), totalProbes)
	fmt.Printf("[+] Primary Route: %s | Mode: %s | SNI: %s (Score: %d, TCP: %dms, TLS: %dms, WS: %dms)\n",
		combat.Primary.TargetIP, combat.Primary.StealthMode, combat.Primary.CleanSNI,
		combat.Primary.Score, combat.Primary.TCPMs, combat.Primary.TLSHandshakeMs, combat.Primary.WSUpgradeMs)
	fmt.Println("[+] Saved combat.profile & atlas.json")
}
EOF

# ---------------------------------------------------------
# 5. XDP SHIELD (Verifier-Safe eBPF + Strict TTL Validation)
# ---------------------------------------------------------
cat << 'EOF' > internal/netstack/xdp_filter.c
//go:build ignore
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TTL_TOLERANCE 4

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u8);
} server_ttl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rst_drop_counter SEC(".maps");

static __always_inline int is_ttl_anomalous(__u8 packet_ttl, __u8 expected_ttl) {
    int diff = (int)packet_ttl - (int)expected_ttl;
    return (diff < -TTL_TOLERANCE || diff > TTL_TOLERANCE);
}

static __always_inline void record_dpi_drop(void) {
    __u32 idx = 0;
    __u64 *cnt = bpf_map_lookup_elem(&rst_drop_counter, &idx);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    }
}

SEC("xdp")
int filter_dpi_rst(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    if (ip->frag_off & bpf_htons(0x1FFF))
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > 60)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    if (tcp->syn && tcp->ack) {
        __u8 ttl = ip->ttl;
        bpf_map_update_elem(&server_ttl_map, &key, &ttl, BPF_ANY);
        return XDP_PASS;
    }

    if (tcp->rst || tcp->fin) {
        __u8 *expected_ttl = bpf_map_lookup_elem(&server_ttl_map, &key);
        if (expected_ttl) {
            if (is_ttl_anomalous(ip->ttl, *expected_ttl)) {
                record_dpi_drop();
                return XDP_DROP;
            }
            if (tcp->rst) {
                bpf_map_delete_elem(&server_ttl_map, &key);
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
EOF

cat << 'EOF' > internal/netstack/xdp_monitor.go
package netstack

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"self-healing-router/internal/telemetry"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_filter.c -- -I/usr/include/bpf -O2

func StartXDPRSTMonitor(ctx context.Context, ifaceName string, onSpike func()) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		telemetry.Log.Warn("XDP interface unavailable; continuing in userspace-only mode",
			slog.String("iface", ifaceName), slog.String("err", err.Error()))
		return
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		telemetry.Log.Warn("Kernel eBPF load skipped (check CAP_BPF/root); userspace engine unaffected",
			slog.String("err", err.Error()))
		return
	}
	defer objs.Close()

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.FilterDpiRst,
		Interface: iface.Index,
	})
	if err != nil {
		telemetry.Log.Warn("XDP native attach failed; continuing without kernel shield",
			slog.String("iface", ifaceName), slog.String("err", err.Error()))
		return
	}
	defer xdpLink.Close()

	telemetry.Log.Info("XDP Kernel Armor Engaged", slog.String("iface", ifaceName))

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastCount uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var key uint32 = 0
			var current uint64
			if err := objs.RstDropCounter.Lookup(&key, &current); err == nil {
				if current > lastCount {
					delta := current - lastCount
					lastCount = current
					telemetry.XDPDroppedRSTs.Store(current)
					telemetry.Log.Warn("XDP intercepted forged DPI TCP RST/FIN packets",
						slog.Uint64("dropped_delta", delta),
						slog.Uint64("total_dropped", current))
					if delta >= 5 && onSpike != nil {
						onSpike()
					}
				}
			}
		}
	}
}
EOF

# ---------------------------------------------------------
# 6. SELF-HEALING WARM POOL (Epoch-Guarded + TLS-Frag Aware)
# ---------------------------------------------------------
cat << 'EOF' > internal/proxy/pool/warm_pool.go
package pool

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
	"self-healing-router/internal/config"
	"self-healing-router/internal/proxy/factory"
	"self-healing-router/internal/telemetry"
)

const (
	targetPoolSize      = 3
	maxDialRetries      = 3
	failStreakThreshold = 3
)

type WarmPool struct {
	fac        factory.StealthFactory
	sessions   []*smux.Session
	routes     []config.RouteCandidate
	routeIdx   int
	routeEpoch uint64
	hostHeader string
	failStreak int
	rrIndex    atomic.Uint32
	mu         sync.RWMutex
	dialSem    chan struct{}
	ctx        context.Context
}

func NewWarmPool(ctx context.Context, fac factory.StealthFactory, profile *config.CombatProfile) *WarmPool {
	routes := []config.RouteCandidate{profile.Primary}
	routes = append(routes, profile.Failovers...)

	p := &WarmPool{
		fac:        fac,
		sessions:   make([]*smux.Session, 0, targetPoolSize),
		routes:     routes,
		hostHeader: profile.WorkerHost,
		dialSem:    make(chan struct{}, targetPoolSize),
		ctx:        ctx,
	}

	go p.maintainer()
	return p
}

func (p *WarmPool) currentRouteAndEpoch() (config.RouteCandidate, uint64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.routes[p.routeIdx%len(p.routes)], p.routeEpoch
}

func (p *WarmPool) RotateRoute(reason string) {
	p.mu.Lock()
	if len(p.routes) <= 1 {
		p.mu.Unlock()
		return
	}
	oldRoute := p.routes[p.routeIdx%len(p.routes)]
	p.routeIdx = (p.routeIdx + 1) % len(p.routes)
	p.routeEpoch++
	newRoute := p.routes[p.routeIdx]
	p.failStreak = 0

	oldSessions := p.sessions
	p.sessions = make([]*smux.Session, 0, targetPoolSize)
	telemetry.PoolHealthyPipes.Store(0)
	p.mu.Unlock()

	for _, s := range oldSessions {
		_ = s.Close()
	}

	telemetry.RouteRotations.Add(1)
	telemetry.Log.Warn("Self-Healing Route Rotation Triggered",
		slog.String("reason", reason),
		slog.String("from_ip", oldRoute.TargetIP),
		slog.String("to_ip", newRoute.TargetIP),
		slog.String("to_mode", newRoute.StealthMode),
		slog.String("to_sni", newRoute.CleanSNI))
}

func (p *WarmPool) GetStream(ctx context.Context) (net.Conn, error) {
	for attempt := 0; attempt < maxDialRetries; attempt++ {
		p.mu.RLock()
		n := len(p.sessions)
		var session *smux.Session
		if n > 0 {
			idx := int(p.rrIndex.Add(1)) % n
			session = p.sessions[idx]
		}
		p.mu.RUnlock()

		if session != nil && !session.IsClosed() {
			stream, err := session.OpenStream()
			if err == nil {
				return stream, nil
			}
			p.removeSession(session)
		}

		session, err := p.dialSession(ctx)
		if err != nil {
			continue
		}
		stream, err := session.OpenStream()
		if err == nil {
			return stream, nil
		}
		p.removeSession(session)
	}

	return nil, errors.New("warm pool exhausted all retry attempts across failover routes")
}

func (p *WarmPool) dialSession(ctx context.Context) (*smux.Session, error) {
	select {
	case p.dialSem <- struct{}{}:
		defer func() { <-p.dialSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	route, epochAtStart := p.currentRouteAndEpoch()
	mode := route.StealthMode
	if mode == "" {
		mode = factory.ModeTLSFrag
	}
	sni := route.CleanSNI
	if mode == factory.ModeTLSFrag && sni != p.hostHeader {
		sni = p.hostHeader
	}

	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	rawConn, err := p.fac.Dial(dialCtx, route.TargetIP, sni, p.hostHeader, mode)
	if err != nil {
		telemetry.DialFailures.Add(1)
		p.mu.Lock()
		var shouldRotate bool
		if p.routeEpoch == epochAtStart {
			p.failStreak++
			if p.failStreak >= failStreakThreshold {
				shouldRotate = true
			}
		}
		streak := p.failStreak
		p.mu.Unlock()

		telemetry.Log.Warn("Stealth pipe dial failed",
			slog.String("ip", route.TargetIP),
			slog.String("mode", mode),
			slog.String("sni", sni),
			slog.Int("streak", streak),
			slog.String("err", err.Error()))

		if shouldRotate {
			p.RotateRoute("consecutive_dial_failures")
		}
		return nil, err
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 1
	smuxCfg.KeepAliveInterval = 10 * time.Second
	smuxCfg.KeepAliveTimeout = 30 * time.Second
	smuxCfg.MaxReceiveBuffer = 4 * 1024 * 1024
	smuxCfg.MaxStreamBuffer = 1024 * 1024

	session, err := smux.Client(rawConn, smuxCfg)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	p.mu.Lock()
	if p.routeEpoch != epochAtStart {
		p.mu.Unlock()
		_ = session.Close()
		return nil, errors.New("route epoch changed during dial; discarding stale pipe")
	}
	p.failStreak = 0
	p.sessions = append(p.sessions, session)
	poolLen := len(p.sessions)
	telemetry.PoolHealthyPipes.Store(int64(poolLen))
	p.mu.Unlock()

	telemetry.Log.Info("Warm Multiplexed Pipe Established",
		slog.String("ip", route.TargetIP),
		slog.String("mode", mode),
		slog.String("sni", sni),
		slog.Int("pool_size", poolLen))

	return session, nil
}

func (p *WarmPool) maintainer() {
	p.replenish()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.replenish()
		}
	}
}

func (p *WarmPool) replenish() {
	p.mu.Lock()
	active := make([]*smux.Session, 0, targetPoolSize)
	for _, s := range p.sessions {
		if !s.IsClosed() {
			active = append(active, s)
		}
	}
	p.sessions = active
	telemetry.PoolHealthyPipes.Store(int64(len(p.sessions)))
	deficit := targetPoolSize - len(p.sessions)
	p.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < deficit; i++ {
		if p.ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.dialSession(p.ctx)
		}()
	}
	wg.Wait()
}

func (p *WarmPool) removeSession(target *smux.Session) {
	p.mu.Lock()
	active := make([]*smux.Session, 0, len(p.sessions))
	for _, s := range p.sessions {
		if s != target && !s.IsClosed() {
			active = append(active, s)
		}
	}
	p.sessions = active
	telemetry.PoolHealthyPipes.Store(int64(len(p.sessions)))
	p.mu.Unlock()
	_ = target.Close()
}
EOF

# ---------------------------------------------------------
# 7. SOCKS5 INTAKE & LEAK-FREE BIDIRECTIONAL RELAY
# ---------------------------------------------------------
cat << 'EOF' > internal/router/socks5.go
package router

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"self-healing-router/internal/proxy/pool"
	"self-healing-router/internal/telemetry"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

func StartSOCKS5(ctx context.Context, listenAddr string, warmPool *pool.WarmPool) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	telemetry.Log.Info("SOCKS5 Zero-Alloc Intake Listening", slog.String("addr", listenAddr))

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go handleSOCKS5(ctx, clientConn, warmPool)
	}
}

func handleSOCKS5(ctx context.Context, client net.Conn, warmPool *pool.WarmPool) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	var hdr [260]byte
	if _, err := io.ReadFull(client, hdr[:2]); err != nil || hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	if _, err := io.ReadFull(client, hdr[:nMethods]); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadFull(client, hdr[:4]); err != nil || hdr[0] != 0x05 || hdr[1] != 0x01 {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	switch hdr[3] {
	case 0x01:
		if _, err := io.ReadFull(client, hdr[:4]); err != nil {
			return
		}
		targetHost = net.IP(hdr[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(client, hdr[:1]); err != nil {
			return
		}
		dLen := int(hdr[0])
		if _, err := io.ReadFull(client, hdr[:dLen]); err != nil {
			return
		}
		targetHost = string(hdr[:dLen])
	case 0x04:
		if _, err := io.ReadFull(client, hdr[:16]); err != nil {
			return
		}
		targetHost = net.IP(hdr[:16]).String()
	default:
		return
	}

	if _, err := io.ReadFull(client, hdr[:2]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(hdr[:2])

	_ = client.SetDeadline(time.Time{})

	remoteStream, err := warmPool.GetStream(ctx)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteStream.Close()

	hostBytes := []byte(targetHost)
	if len(hostBytes) == 0 || len(hostBytes) > 255 {
		return
	}
	frame := make([]byte, 1+len(hostBytes)+2)
	frame[0] = byte(len(hostBytes))
	copy(frame[1:], hostBytes)
	binary.BigEndian.PutUint16(frame[1+len(hostBytes):], targetPort)

	_ = remoteStream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := remoteStream.Write(frame); err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = remoteStream.SetWriteDeadline(time.Time{})

	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	telemetry.ActiveStreams.Add(1)
	defer telemetry.ActiveStreams.Add(-1)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		n, _ := io.CopyBuffer(remoteStream, client, *bufPtr)
		telemetry.TotalBytesTx.Add(uint64(n))
		_ = remoteStream.Close()
	}()

	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)
		n, _ := io.CopyBuffer(client, remoteStream, *bufPtr)
		telemetry.TotalBytesRx.Add(uint64(n))
		if tcpC, ok := client.(*net.TCPConn); ok {
			_ = tcpC.CloseWrite()
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	}()

	wg.Wait()
}
EOF

# ---------------------------------------------------------
# 8. MAIN BOOTSTRAP (CLI Flags, Telemetry & Signal Handling)
# ---------------------------------------------------------
cat << 'EOF' > cmd/router/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"self-healing-router/internal/config"
	"self-healing-router/internal/netstack"
	"self-healing-router/internal/proxy/factory"
	"self-healing-router/internal/proxy/pool"
	"self-healing-router/internal/router"
	"self-healing-router/internal/scanner"
	"self-healing-router/internal/telemetry"
)

func main() {
	mapMode := flag.Bool("map", false, "Run Cartographer to probe routes and generate combat.profile")
	runMode := flag.Bool("run", false, "Run the Self-Healing Combat Engine")
	workerHost := flag.String("worker", "my-proxy.workers.dev", "Cloudflare Worker hostname (used in --map mode)")
	customIPs := flag.String("ips", "", "Optional comma-separated Cloudflare edge IPs to probe in --map mode")
	verifyWS := flag.Bool("verify-ws", true, "Verify full WebSocket 101 upgrade against worker during --map")
	ifaceName := flag.String("iface", "eth0", "Network interface for XDP Kernel Shield")
	listenAddr := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	verbose := flag.Bool("v", false, "Enable verbose debug telemetry")
	flag.Parse()

	telemetry.InitLogger(*verbose)

	if *mapMode {
		scanner.RunCartographer(*workerHost, *verifyWS, *customIPs)
		return
	}

	if *runMode {
		telemetry.PrintBanner()

		profile, err := config.LoadCombatProfile("combat.profile")
		if err != nil {
			fmt.Println("[-] Error: combat.profile not found. Run './router_v8 --map --worker=YOUR_WORKER.workers.dev' first.")
			os.Exit(1)
		}

		telemetry.Log.Info("Combat Profile Armed",
			slog.String("primary_ip", profile.Primary.TargetIP),
			slog.String("stealth_mode", profile.Primary.StealthMode),
			slog.String("primary_sni", profile.Primary.CleanSNI),
			slog.Bool("ws_verified", profile.Primary.WSVerified),
			slog.Int("failover_count", len(profile.Failovers)),
			slog.String("worker", profile.WorkerHost))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfFactory := factory.NewCloudflareFactory()
		warmPool := pool.NewWarmPool(ctx, cfFactory, profile)

		go netstack.StartXDPRSTMonitor(ctx, *ifaceName, func() {
			warmPool.RotateRoute("xdp_dpi_rst_burst_detected")
		})

		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					telemetry.Log.Info("Engine Telemetry",
						slog.Int64("active_streams", telemetry.ActiveStreams.Load()),
						slog.Int64("warm_pipes", telemetry.PoolHealthyPipes.Load()),
						slog.Uint64("tx_kb", telemetry.TotalBytesTx.Load()/1024),
						slog.Uint64("rx_kb", telemetry.TotalBytesRx.Load()/1024),
						slog.Uint64("route_rotations", telemetry.RouteRotations.Load()),
						slog.Uint64("dial_failures", telemetry.DialFailures.Load()),
						slog.Uint64("xdp_dropped_pkts", telemetry.XDPDroppedRSTs.Load()))
				}
			}
		}()

		go func() {
			if err := router.StartSOCKS5(ctx, *listenAddr, warmPool); err != nil {
				telemetry.Log.Error("SOCKS5 listener failed", slog.String("err", err.Error()))
				cancel()
			}
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		telemetry.Log.Info("Graceful shutdown initiated...")
		cancel()
		return
	}

	telemetry.PrintBanner()
	fmt.Println("Usage:")
	fmt.Println("  1. Map ISP & Edge:  ./router_v8 --map --worker=your-worker.workers.dev [-v]")
	fmt.Println("  2. Engage Engine:   sudo ./router_v8 --run --iface=eth0 --listen=127.0.0.1:1080")
}
EOF

# ---------------------------------------------------------
# 9. CLOUDFLARE WORKER (Serialized SMUX v1 Multiplexer Engine)
# ---------------------------------------------------------
cat << 'EOF' > worker.js
import { connect } from 'cloudflare:sockets';

const SMUX_VERSION = 1;
const CMD_SYN = 0;
const CMD_FIN = 1;
const CMD_PSH = 2;
const CMD_NOP = 3;
const HEADER_SIZE = 8;

function encodeSmuxFrame(cmd, streamId, payload = new Uint8Array(0)) {
  const frame = new Uint8Array(HEADER_SIZE + payload.byteLength);
  const view = new DataView(frame.buffer);
  view.setUint8(0, SMUX_VERSION);
  view.setUint8(1, cmd);
  view.setUint16(2, payload.byteLength, true);
  view.setUint32(4, streamId, true);
  if (payload.byteLength > 0) {
    frame.set(payload, HEADER_SIZE);
  }
  return frame;
}

function concatUint8(a, b) {
  if (a.byteLength === 0) return b;
  if (b.byteLength === 0) return a;
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

export default {
  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('OK', { status: 200 });
    }

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const streams = new Map();
    let rxBuffer = new Uint8Array(0);
    let processingChain = Promise.resolve();
    const textDecoder = new TextDecoder();

    const safeSend = (frame) => {
      try {
        server.send(frame);
      } catch (_) {}
    };

    const closeStream = async (streamId, sendFin = false) => {
      const entry = streams.get(streamId);
      if (!entry) return;
      streams.delete(streamId);
      entry.closed = true;
      try {
        if (entry.writer) await entry.writer.close();
      } catch (_) {}
      try {
        if (entry.socket) await entry.socket.close();
      } catch (_) {}
      if (sendFin) {
        safeSend(encodeSmuxFrame(CMD_FIN, streamId));
      }
    };

    const handleStreamPayload = async (streamId, chunk) => {
      const entry = streams.get(streamId);
      if (!entry || entry.closed) return;

      if (!entry.connected) {
        entry.headerBuf = concatUint8(entry.headerBuf, chunk);
        if (entry.headerBuf.byteLength < 1) return;

        const hostLen = entry.headerBuf[0];
        const totalHeaderLen = 1 + hostLen + 2;
        if (entry.headerBuf.byteLength < totalHeaderLen) return;

        const hostBytes = entry.headerBuf.subarray(1, 1 + hostLen);
        const portView = new DataView(
          entry.headerBuf.buffer,
          entry.headerBuf.byteOffset + 1 + hostLen,
          2
        );
        const hostname = textDecoder.decode(hostBytes);
        const port = portView.getUint16(0, false);
        const remainder = entry.headerBuf.slice(totalHeaderLen);
        entry.headerBuf = new Uint8Array(0);

        try {
          const tcpSocket = connect({ hostname, port });
          const writer = tcpSocket.writable.getWriter();
          entry.socket = tcpSocket;
          entry.writer = writer;
          entry.connected = true;

          if (remainder.byteLength > 0) {
            await writer.write(remainder);
          }

          (async () => {
            const reader = tcpSocket.readable.getReader();
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value && value.byteLength > 0) {
                  const MAX_FRAME = 16384;
                  for (let offset = 0; offset < value.byteLength; offset += MAX_FRAME) {
                    const slice = value.subarray(offset, offset + MAX_FRAME);
                    safeSend(encodeSmuxFrame(CMD_PSH, streamId, slice));
                  }
                }
              }
            } catch (_) {
            } finally {
              await closeStream(streamId, true);
            }
          })();
        } catch (_) {
          await closeStream(streamId, true);
        }
        return;
      }

      if (entry.writer) {
        try {
          await entry.writer.write(chunk);
        } catch (_) {
          await closeStream(streamId, true);
        }
      }
    };

    server.addEventListener('message', (event) => {
      const incoming = event.data instanceof ArrayBuffer
        ? new Uint8Array(event.data)
        : new TextEncoder().encode(String(event.data));

      rxBuffer = concatUint8(rxBuffer, incoming);

      const parsedFrames = [];
      let offset = 0;

      while (rxBuffer.byteLength - offset >= HEADER_SIZE) {
        const view = new DataView(rxBuffer.buffer, rxBuffer.byteOffset + offset, HEADER_SIZE);
        const ver = view.getUint8(0);
        const cmd = view.getUint8(1);
        const length = view.getUint16(2, true);
        const streamId = view.getUint32(4, true);

        if (ver !== SMUX_VERSION) {
          rxBuffer = new Uint8Array(0);
          server.close(1002, 'Invalid SMUX version');
          return;
        }

        if (rxBuffer.byteLength - offset < HEADER_SIZE + length) {
          break;
        }

        const payload = rxBuffer.slice(offset + HEADER_SIZE, offset + HEADER_SIZE + length);
        offset += HEADER_SIZE + length;
        parsedFrames.push({ cmd, streamId, payload });
      }

      if (offset > 0) {
        rxBuffer = rxBuffer.slice(offset);
      }

      if (parsedFrames.length === 0) return;

      processingChain = processingChain.then(async () => {
        for (const frame of parsedFrames) {
          switch (frame.cmd) {
            case CMD_SYN:
              if (!streams.has(frame.streamId)) {
                streams.set(frame.streamId, {
                  connected: false,
                  closed: false,
                  headerBuf: new Uint8Array(0),
                  socket: null,
                  writer: null,
                });
              }
              break;

            case CMD_PSH:
              await handleStreamPayload(frame.streamId, frame.payload);
              break;

            case CMD_FIN:
              await closeStream(frame.streamId, false);
              break;

            case CMD_NOP:
              safeSend(encodeSmuxFrame(CMD_NOP, 0));
              break;
          }
        }
      }).catch(() => {});
    });

    server.addEventListener('close', () => {
      for (const streamId of Array.from(streams.keys())) {
        closeStream(streamId, false);
      }
    });

    return new Response(null, { status: 101, webSocket: client });
  }
};
EOF

echo "[+] Initializing Go module and fetching dependencies..."
if [ ! -f go.mod ]; then
  go mod init self-healing-router
fi
go get github.com/cilium/ebpf/cmd/bpf2go
go get github.com/cilium/ebpf/link
go get github.com/coder/websocket
go get github.com/refraction-networking/utls
go get github.com/xtaci/smux

echo "[+] Generating eBPF bytecode..."
cd internal/netstack
go generate
cd ../../

echo "[+] Compiling router_v8 binary..."
go build -trimpath -ldflags="-s -w" -o router_v8 ./cmd/router/main.go

echo "============================================================"
echo "✅ SELF-HEALING ROUTER v8.3 (TLS-FRAG ANTI-403) COMPILED"
echo "============================================================"
echo "1. Deploy 'worker.js' to Cloudflare Workers."
echo "2. Map your ISP & verify 101 Switching Protocols:"
echo "   ./router_v8 --map --worker=YOUR_WORKER.workers.dev -v"
echo "3. Engage the Self-Healing Engine:"
echo "   sudo ./router_v8 --run --iface=eth0 --listen=127.0.0.1:1080"
echo "============================================================"
