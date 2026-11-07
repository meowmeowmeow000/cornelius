#!/bin/bash
set -euo pipefail

PROJECT_DIR="/opt/self-healing-router-v9"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

echo "[+] Forging Autonomous Self-Healing Stealth Router v9 in $PROJECT_DIR..."
mkdir -p cmd/router
mkdir -p internal/config
mkdir -p internal/coordinator
mkdir -p internal/ipc
mkdir -p internal/netstack
mkdir -p internal/proxy/factory
mkdir -p internal/proxy/pool
mkdir -p internal/router
mkdir -p internal/scanner
mkdir -p internal/telemetry

# ---------------------------------------------------------
# 1. STRATEGIC DOCTRINE & CONFIG (internal/config/profile.go)
# ---------------------------------------------------------
cat << 'EOF' > internal/config/profile.go
package config

import (
	"encoding/json"
	"os"
	"time"
)

type OperationalDoctrine struct {
	TelemetryPollingMs     int `json:"telemetry_polling_ms"`
	MaxAcceptableLatencyMs int `json:"max_acceptable_latency_ms"`
	FallbackThresholdStreak int `json:"fallback_threshold_streak"`
}

type XDPDirective struct {
	Mode              string `json:"mode"` // "adaptive" or "lockdown"
	ExpectedTTL       uint8  `json:"expected_ttl"`
	TTLTolerance      uint8  `json:"ttl_tolerance"`
	RSTBurstThreshold uint64 `json:"rst_burst_threshold"`
}

type StealthDirective struct {
	PrimaryMode          string `json:"primary_mode"`  // "tls_frag", "tls_micro_frag", "sni_front"
	FallbackMode         string `json:"fallback_mode"` // "tls_micro_frag"
	FragmentationDelayMs int    `json:"fragmentation_delay_ms"`
	JitterMs             int    `json:"jitter_ms"`
}

type PoolDirective struct {
	TargetCapacity    int `json:"target_capacity"`
	KeepAliveInterval int `json:"keepalive_interval_sec"`
}

type ModuleDirectives struct {
	XDPShield      XDPDirective     `json:"xdp_shield"`
	StealthFactory StealthDirective `json:"stealth_factory"`
	WarmPool       PoolDirective    `json:"warm_pool"`
}

type ContingencyRule struct {
	Condition string `json:"condition"` // "http_403_forbidden", "dpi_tls_reset", "dial_timeout", "tcp_rst_storm"
	Action    string `json:"action"`    // "escalate_stealth_mode", "engage_xdp_lockdown", "flush_pool_and_rotate_ip"
}

type RouteCandidate struct {
	TargetIP       string `json:"target_ip"`
	CleanSNI       string `json:"clean_sni"`
	StealthMode    string `json:"stealth_mode"` // "tls_frag", "tls_micro_frag", "sni_front"
	ExpectedTTL    uint8  `json:"expected_ttl,omitempty"`
	DPIDistance    int    `json:"dpi_distance_hops,omitempty"`
	TCPMs          int64  `json:"tcp_ms"`
	TLSHandshakeMs int64  `json:"tls_handshake_ms"`
	WSUpgradeMs    int64  `json:"ws_upgrade_ms,omitempty"`
	WSVerified     bool   `json:"ws_verified"`
	Score          int    `json:"confidence_score"`
}

type CombatProfile struct {
	Version           string              `json:"version"`
	WorkerHost        string              `json:"worker_host"`
	ExpectedTTL       int                 `json:"expected_ttl"`
	Doctrine          OperationalDoctrine `json:"operational_doctrine"`
	Modules           ModuleDirectives    `json:"modules"`
	ContingencyMatrix []ContingencyRule   `json:"contingency_matrix"`
	Primary           RouteCandidate      `json:"primary_route"`
	Failovers         []RouteCandidate    `json:"failover_routes"`
}

type AtlasReport struct {
	Timestamp    string           `json:"timestamp"`
	TotalProbed  int              `json:"total_probed"`
	ViableRoutes int              `json:"viable_routes"`
	Throttled    bool             `json:"is_throttled"`
	RankedMatrix []RouteCandidate `json:"ranked_matrix"`
}

func DefaultCombatProfile(workerHost string, primary RouteCandidate, failovers []RouteCandidate) *CombatProfile {
	expTTL := int(primary.ExpectedTTL)
	if expTTL == 0 {
		expTTL = 54
	}
	return &CombatProfile{
		Version:     "9.0-autonomous",
		WorkerHost:  workerHost,
		ExpectedTTL: expTTL,
		Doctrine: OperationalDoctrine{
			TelemetryPollingMs:      3000,
			MaxAcceptableLatencyMs:  800,
			FallbackThresholdStreak: 3,
		},
		Modules: ModuleDirectives{
			XDPShield: XDPDirective{
				Mode:              "adaptive",
				ExpectedTTL:       uint8(expTTL),
				TTLTolerance:      4,
				RSTBurstThreshold: 5,
			},
			StealthFactory: StealthDirective{
				PrimaryMode:          "tls_frag",
				FallbackMode:         "tls_micro_frag",
				FragmentationDelayMs: 2,
				JitterMs:             3,
			},
			WarmPool: PoolDirective{
				TargetCapacity:    3,
				KeepAliveInterval: 10,
			},
		},
		ContingencyMatrix: []ContingencyRule{
			{Condition: "http_403_forbidden", Action: "escalate_stealth_mode"},
			{Condition: "dpi_tls_reset", Action: "escalate_stealth_mode"},
			{Condition: "dial_timeout", Action: "flush_pool_and_rotate_ip"},
			{Condition: "tcp_rst_storm", Action: "engage_xdp_lockdown"},
		},
		Primary:   primary,
		Failovers: failovers,
	}
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
	if p.Doctrine.FallbackThresholdStreak <= 0 {
		p.Doctrine.FallbackThresholdStreak = 3
	}
	if p.Modules.XDPShield.TTLTolerance == 0 {
		p.Modules.XDPShield.TTLTolerance = 4
	}
	if p.Modules.XDPShield.ExpectedTTL == 0 && p.ExpectedTTL > 0 {
		p.Modules.XDPShield.ExpectedTTL = uint8(p.ExpectedTTL)
	}
	if p.Modules.StealthFactory.FragmentationDelayMs <= 0 {
		p.Modules.StealthFactory.FragmentationDelayMs = 2
	}
	if len(p.ContingencyMatrix) == 0 {
		p.ContingencyMatrix = []ContingencyRule{
			{Condition: "http_403_forbidden", Action: "escalate_stealth_mode"},
			{Condition: "dpi_tls_reset", Action: "escalate_stealth_mode"},
			{Condition: "dial_timeout", Action: "flush_pool_and_rotate_ip"},
			{Condition: "tcp_rst_storm", Action: "engage_xdp_lockdown"},
		}
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

	if atlas != nil {
		if atlas.Timestamp == "" {
			atlas.Timestamp = time.Now().Format(time.RFC3339)
		}
		aData, err := json.MarshalIndent(atlas, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile("atlas.json", aData, 0644)
	}
	return nil
}
EOF

# ---------------------------------------------------------
# 2. TELEMETRY & VITAL SIGNS (internal/telemetry/logger.go)
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
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║   ⚡ SELF-HEALING STEALTH ROUTER v9.0 // AUTONOMOUS KERNEL MULTIPLEXER   ║
  ╠══════════════════════════════════════════════════════════════════════════╣
  ║                                                                          ║
  ║   [Scapy Sculptor] ──(Unix IPC)──► [Strategic Coordinator]               ║
  ║         │                                 │                              ║
  ║    Live Hop/TTL                     Hot-Swaps Maps &                     ║
  ║    Echolocation                     Escalates Frag Mode                  ║
  ║         ▼                                 ▼                              ║
  ║   [XDP eBPF Shield] ◄────────────► [Warm Pool: 3x SMUX v1] ──► [uTLS]    ║
  ║    Dynamic TTL Lockdown             3-Slice / 5-Slice SNI Split          ║
  ╚══════════════════════════════════════════════════════════════════════════╝
`

var (
	Log                 *slog.Logger
	ActiveStreams       atomic.Int64
	PoolHealthyPipes    atomic.Int64
	TotalBytesTx        atomic.Uint64
	TotalBytesRx        atomic.Uint64
	RouteRotations      atomic.Uint64
	ModeEscalations     atomic.Uint64
	XDPDroppedRSTs      atomic.Uint64
	IPCOverrides        atomic.Uint64
	DialFailures        atomic.Uint64
	CurrentExpectedTTL  atomic.Uint32
	CurrentTTLTolerance atomic.Uint32
	CurrentLockdownMode atomic.Uint32
)

type VitalSnapshot struct {
	ActiveStreams    int64  `json:"active_streams"`
	WarmPipes        int64  `json:"warm_pipes"`
	TxKB             uint64 `json:"tx_kb"`
	RxKB             uint64 `json:"rx_kb"`
	RouteRotations   uint64 `json:"route_rotations"`
	ModeEscalations  uint64 `json:"mode_escalations"`
	XDPDroppedPkts   uint64 `json:"xdp_dropped_pkts"`
	IPCOverrides     uint64 `json:"ipc_overrides"`
	DialFailures     uint64 `json:"dial_failures"`
	ExpectedTTL      uint32 `json:"xdp_expected_ttl"`
	TTLTolerance     uint32 `json:"xdp_ttl_tolerance"`
	XDPLockdown      bool   `json:"xdp_lockdown_active"`
	ActiveRouteIP    string `json:"active_route_ip"`
	ActiveStealth    string `json:"active_stealth_mode"`
}

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
# 3. DYNAMIC eBPF XDP SHIELD (internal/netstack/xdp_filter.c)
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

#define CFG_IDX_EXPECTED_TTL  0
#define CFG_IDX_TTL_TOLERANCE 1
#define CFG_IDX_LOCKDOWN_MODE 2

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

// Runtime configuration map hot-swapped from Go Coordinator / Scapy IPC:
// [0] = fallback expected_ttl (from Scapy Cartographer)
// [1] = ttl_tolerance (default 4, lockdown 2)
// [2] = lockdown_mode (0 = adaptive, 1 = strict lockdown)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} xdp_config_map SEC(".maps");

static __always_inline __u32 get_cfg(__u32 idx, __u32 default_val) {
    __u32 *val = bpf_map_lookup_elem(&xdp_config_map, &idx);
    if (!val || *val == 0)
        return default_val;
    return *val;
}

static __always_inline int is_ttl_anomalous(__u8 packet_ttl, __u8 expected_ttl, __u32 tolerance) {
    int diff = (int)packet_ttl - (int)expected_ttl;
    int tol = (int)tolerance;
    return (diff < -tol || diff > tol);
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

    // Ignore non-first IPv4 fragments
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

    // Lock in true server TTL on legitimate SYN+ACK
    if (tcp->syn && tcp->ack) {
        __u8 ttl = ip->ttl;
        bpf_map_update_elem(&server_ttl_map, &key, &ttl, BPF_ANY);
        return XDP_PASS;
    }

    if (tcp->rst || tcp->fin) {
        __u32 tolerance = get_cfg(CFG_IDX_TTL_TOLERANCE, 4);
        __u8 *flow_ttl  = bpf_map_lookup_elem(&server_ttl_map, &key);

        if (flow_ttl) {
            if (is_ttl_anomalous(ip->ttl, *flow_ttl, tolerance)) {
                record_dpi_drop();
                return XDP_DROP;
            }
            if (tcp->rst) {
                bpf_map_delete_elem(&server_ttl_map, &key);
            }
            return XDP_PASS;
        }

        // If flow was not in LRU map (or during lockdown mode), compare against Scapy baseline TTL
        __u32 baseline_ttl = get_cfg(CFG_IDX_EXPECTED_TTL, 0);
        __u32 lockdown     = get_cfg(CFG_IDX_LOCKDOWN_MODE, 0);
        if (baseline_ttl > 0 && lockdown == 1 && bpf_ntohs(tcp->source) == 443) {
            if (is_ttl_anomalous(ip->ttl, (__u8)baseline_ttl, tolerance)) {
                record_dpi_drop();
                return XDP_DROP;
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
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"self-healing-router/internal/telemetry"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_filter.c -- -I/usr/include/bpf -O2

const (
	cfgIdxExpectedTTL  uint32 = 0
	cfgIdxTTLTolerance uint32 = 1
	cfgIdxLockdownMode uint32 = 2
)

var (
	activeConfigMap *ebpf.Map
	mapMu           sync.RWMutex
)

// UpdateXDPConfig dynamically rewrites the kernel eBPF configuration map at runtime
// without detaching the XDP program or dropping active connections.
func UpdateXDPConfig(expectedTTL, tolerance uint8, lockdown bool) {
	if tolerance == 0 {
		tolerance = 4
	}
	var lockVal uint32
	if lockdown {
		lockVal = 1
	}

	telemetry.CurrentExpectedTTL.Store(uint32(expectedTTL))
	telemetry.CurrentTTLTolerance.Store(uint32(tolerance))
	telemetry.CurrentLockdownMode.Store(lockVal)

	mapMu.RLock()
	m := activeConfigMap
	mapMu.RUnlock()

	if m == nil {
		return
	}

	expVal := uint32(expectedTTL)
	tolVal := uint32(tolerance)

	_ = m.Put(cfgIdxExpectedTTL, expVal)
	_ = m.Put(cfgIdxTTLTolerance, tolVal)
	_ = m.Put(cfgIdxLockdownMode, lockVal)

	telemetry.Log.Info("Kernel eBPF Map Hot-Swapped",
		slog.Uint64("expected_ttl", uint64(expVal)),
		slog.Uint64("ttl_tolerance", uint64(tolVal)),
		slog.Bool("lockdown_mode", lockdown))
}

func StartXDPRSTMonitor(ctx context.Context, ifaceName string, initialTTL, initialTol uint8, burstThreshold uint64, onSpike func()) {
	UpdateXDPConfig(initialTTL, initialTol, false)

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
	defer func() {
		mapMu.Lock()
		activeConfigMap = nil
		mapMu.Unlock()
		objs.Close()
	}()

	mapMu.Lock()
	activeConfigMap = objs.XdpConfigMap
	mapMu.Unlock()

	// Seed runtime config map immediately after load
	UpdateXDPConfig(
		uint8(telemetry.CurrentExpectedTTL.Load()),
		uint8(telemetry.CurrentTTLTolerance.Load()),
		telemetry.CurrentLockdownMode.Load() == 1,
	)

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

	telemetry.Log.Info("XDP v9 Dynamic Kernel Armor Engaged",
		slog.String("iface", ifaceName),
		slog.Uint64("expected_ttl", uint64(initialTTL)),
		slog.Uint64("tolerance", uint64(initialTol)))

	if burstThreshold == 0 {
		burstThreshold = 5
	}

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
					if delta >= burstThreshold && onSpike != nil {
						onSpike()
					}
				}
			}
		}
	}
}
EOF

# ---------------------------------------------------------
# 4. MULTI-MODE STEALTH FACTORY (internal/proxy/factory/cf_factory.go)
# ---------------------------------------------------------
cat << 'EOF' > internal/proxy/factory/cf_factory.go
package factory

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	utls "github.com/refraction-networking/utls"
)

const (
	ModeTLSFrag      = "tls_frag"       // 3-record ClientHello split bisecting SNI
	ModeTLSMicroFrag = "tls_micro_frag" // 5-record surgical micro-split with random jitter
	ModeSNIFront     = "sni_front"      // Opportunistic same-zone fronting
)

// Structured error condition classifications for the Strategic Coordinator
const (
	CondHTTP403     = "http_403_forbidden"
	CondDPITLSReset = "dpi_tls_reset"
	CondDialTimeout = "dial_timeout"
)

type ProbeMetrics struct {
	TCPDur     time.Duration
	TLSDur     time.Duration
	WSDur      time.Duration
	WSVerified bool
}

type StealthFactory interface {
	Dial(ctx context.Context, targetIP, sni, hostHeader, stealthMode string) (net.Conn, string, error)
	ProbeRoute(ctx context.Context, targetIP, sni, hostHeader, stealthMode string, verifyWS bool) (ProbeMetrics, error)
	SetPacing(delayMs, jitterMs int)
}

type CloudflareFactory struct {
	fragDelayMs atomic.Int64
	jitterMs    atomic.Int64
}

func NewCloudflareFactory(delayMs, jitterMs int) *CloudflareFactory {
	if delayMs <= 0 {
		delayMs = 2
	}
	if jitterMs < 0 {
		jitterMs = 2
	}
	f := &CloudflareFactory{}
	f.fragDelayMs.Store(int64(delayMs))
	f.jitterMs.Store(int64(jitterMs))
	return f
}

func (f *CloudflareFactory) SetPacing(delayMs, jitterMs int) {
	if delayMs > 0 {
		f.fragDelayMs.Store(int64(delayMs))
	}
	if jitterMs >= 0 {
		f.jitterMs.Store(int64(jitterMs))
	}
}

// clientHelloFragConn wraps a raw TCP connection and slices the outbound TLS
// ClientHello (0x16) into either 3 (ModeTLSFrag) or 5 (ModeTLSMicroFrag) separate
// RFC-compliant TLS records flushed across paced TCP segments.
type clientHelloFragConn struct {
	net.Conn
	fragmented bool
	microMode  bool
	sniBytes   []byte
	delayMs    int
	jitterMs   int
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

	var slices [][]byte
	sniIdx := -1
	if len(c.sniBytes) > 2 {
		sniIdx = bytes.Index(payload, c.sniBytes)
	}

	if c.microMode && sniIdx > 37 && sniIdx+len(c.sniBytes) < len(payload) {
		// 5-Slice Surgical Micro-Fragmentation:
		// 1: TLS Header + ClientRandom
		// 2: Extensions up to SNI start + first 3 bytes of SNI
		// 3: Middle of SNI hostname
		// 4: Remainder of SNI hostname
		// 5: Trailing TLS extensions (ALPN, KeyShare, Padding)
		c1 := 37
		c2 := sniIdx + (len(c.sniBytes) / 3)
		c3 := sniIdx + ((len(c.sniBytes) * 2) / 3)
		c4 := sniIdx + len(c.sniBytes)
		if c2 > c1 && c3 > c2 && c4 > c3 && c4 < len(payload) {
			slices = [][]byte{
				payload[:c1],
				payload[c1:c2],
				payload[c2:c3],
				payload[c3:c4],
				payload[c4:],
			}
		}
	}

	if len(slices) == 0 {
		// 3-Slice Standard TLS Record Guillotine
		cut1 := 37
		cut2 := len(payload) / 2
		if sniIdx > cut1 {
			cut2 = sniIdx + (len(c.sniBytes) / 2)
		}
		if cut2 <= cut1 || cut2 >= len(payload) {
			cut2 = (cut1 + len(payload)) / 2
		}
		slices = [][]byte{
			payload[:cut1],
			payload[cut1:cut2],
			payload[cut2:],
		}
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
			sleepMs := c.delayMs
			if c.jitterMs > 0 {
				sleepMs += rand.Intn(c.jitterMs + 1)
			}
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
	}

	return len(b), nil
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "403") || strings.Contains(msg, "forbidden") {
		return CondHTTP403
	}
	if strings.Contains(msg, "reset by peer") || strings.Contains(msg, "eof") || strings.Contains(msg, "alert") {
		return CondDPITLSReset
	}
	return CondDialTimeout
}

func (f *CloudflareFactory) dialUTLSChromeHTTP11(ctx context.Context, targetAddr, sni, stealthMode string) (net.Conn, time.Duration, time.Duration, error) {
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
	if stealthMode == ModeTLSFrag || stealthMode == ModeTLSMicroFrag || stealthMode == "" {
		baseConn = &clientHelloFragConn{
			Conn:      rawConn,
			microMode: stealthMode == ModeTLSMicroFrag,
			sniBytes:  []byte(sni),
			delayMs:   int(f.fragDelayMs.Load()),
			jitterMs:  int(f.jitterMs.Load()),
		}
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		_ = rawConn.Close()
		return nil, tcpDur, 0, err
	}

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

	uConn, tcpDur, tlsDur, err := f.dialUTLSChromeHTTP11(ctx, targetAddr, sni, stealthMode)
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

func (f *CloudflareFactory) Dial(ctx context.Context, targetIP, sni, hostHeader, stealthMode string) (net.Conn, string, error) {
	targetAddr := net.JoinHostPort(targetIP, "443")

	uConn, _, _, err := f.dialUTLSChromeHTTP11(ctx, targetAddr, sni, stealthMode)
	if err != nil {
		cond := classifyError(err)
		return nil, cond, fmt.Errorf("uTLS handshake failed (%s): %w", stealthMode, err)
	}

	wsConn, err := upgradeWebSocketOverUTLS(ctx, uConn, hostHeader)
	if err != nil {
		_ = uConn.Close()
		cond := classifyError(err)
		return nil, cond, fmt.Errorf("websocket upgrade failed (%s): %w", stealthMode, err)
	}

	wsConn.SetReadLimit(-1)
	return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), "", nil
}
EOF

# ---------------------------------------------------------
# 5. SELF-HEALING WARM POOL (internal/proxy/pool/warm_pool.go)
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

const maxDialRetries = 3

type FailureObserver func(condition string, streak int, activeRoute config.RouteCandidate)

type WarmPool struct {
	fac            factory.StealthFactory
	sessions       []*smux.Session
	routes         []config.RouteCandidate
	routeIdx       int
	routeEpoch     uint64
	hostHeader     string
	targetCap      int
	keepAliveSec   int
	failThreshold  int
	failStreak     int
	rrIndex        atomic.Uint32
	onFailureEvent FailureObserver
	mu             sync.RWMutex
	dialSem        chan struct{}
	ctx            context.Context
}

func NewWarmPool(ctx context.Context, fac factory.StealthFactory, profile *config.CombatProfile, observer FailureObserver) *WarmPool {
	routes := []config.RouteCandidate{profile.Primary}
	routes = append(routes, profile.Failovers...)

	capSize := profile.Modules.WarmPool.TargetCapacity
	if capSize <= 0 {
		capSize = 3
	}
	kaSec := profile.Modules.WarmPool.KeepAliveInterval
	if kaSec <= 0 {
		kaSec = 10
	}
	thresh := profile.Doctrine.FallbackThresholdStreak
	if thresh <= 0 {
		thresh = 3
	}

	p := &WarmPool{
		fac:            fac,
		sessions:       make([]*smux.Session, 0, capSize),
		routes:         routes,
		hostHeader:     profile.WorkerHost,
		targetCap:      capSize,
		keepAliveSec:   kaSec,
		failThreshold:  thresh,
		onFailureEvent: observer,
		dialSem:        make(chan struct{}, capSize),
		ctx:            ctx,
	}

	go p.maintainer()
	return p
}

func (p *WarmPool) ActiveRoute() config.RouteCandidate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.routes[p.routeIdx%len(p.routes)]
}

func (p *WarmPool) currentRouteAndEpoch() (config.RouteCandidate, uint64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.routes[p.routeIdx%len(p.routes)], p.routeEpoch
}

// EscalateStealthMode upgrades the active route's handshake strategy in-place
// (e.g. sni_front -> tls_frag -> tls_micro_frag) as ordered by the Coordinator.
func (p *WarmPool) EscalateStealthMode(newMode string, delayMs, jitterMs int) {
	p.fac.SetPacing(delayMs, jitterMs)

	p.mu.Lock()
	idx := p.routeIdx % len(p.routes)
	oldMode := p.routes[idx].StealthMode
	if oldMode == newMode {
		p.mu.Unlock()
		return
	}
	p.routes[idx].StealthMode = newMode
	if newMode == factory.ModeTLSFrag || newMode == factory.ModeTLSMicroFrag {
		p.routes[idx].CleanSNI = p.hostHeader
	}
	p.routeEpoch++
	p.failStreak = 0
	oldSessions := p.sessions
	p.sessions = make([]*smux.Session, 0, p.targetCap)
	telemetry.PoolHealthyPipes.Store(0)
	ip := p.routes[idx].TargetIP
	p.mu.Unlock()

	for _, s := range oldSessions {
		_ = s.Close()
	}

	telemetry.ModeEscalations.Add(1)
	telemetry.Log.Warn("Strategic Handshake Escalation Executed",
		slog.String("ip", ip),
		slog.String("from_mode", oldMode),
		slog.String("to_mode", newMode),
		slog.Int("frag_delay_ms", delayMs))
}

// InjectEmergencyRoute hot-swaps a Scapy-verified route into slot 0 and immediately
// rotates the pool to it without dropping the SOCKS5 intake listener.
func (p *WarmPool) InjectEmergencyRoute(cand config.RouteCandidate) {
	p.mu.Lock()
	if cand.StealthMode == "" {
		cand.StealthMode = factory.ModeTLSFrag
	}
	if cand.CleanSNI == "" {
		cand.CleanSNI = p.hostHeader
	}

	// Prepend or promote candidate to index 0
	filtered := []config.RouteCandidate{cand}
	for _, r := range p.routes {
		if r.TargetIP != cand.TargetIP {
			filtered = append(filtered, r)
		}
	}
	p.routes = filtered
	p.routeIdx = 0
	p.routeEpoch++
	p.failStreak = 0

	oldSessions := p.sessions
	p.sessions = make([]*smux.Session, 0, p.targetCap)
	telemetry.PoolHealthyPipes.Store(0)
	p.mu.Unlock()

	for _, s := range oldSessions {
		_ = s.Close()
	}

	telemetry.IPCOverrides.Add(1)
	telemetry.RouteRotations.Add(1)
	telemetry.Log.Warn("Live IPC Route Injected & Armed",
		slog.String("target_ip", cand.TargetIP),
		slog.String("stealth_mode", cand.StealthMode),
		slog.Uint64("expected_ttl", uint64(cand.ExpectedTTL)))
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
	p.sessions = make([]*smux.Session, 0, p.targetCap)
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
	if (mode == factory.ModeTLSFrag || mode == factory.ModeTLSMicroFrag) && sni != p.hostHeader {
		sni = p.hostHeader
	}

	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	rawConn, cond, err := p.fac.Dial(dialCtx, route.TargetIP, sni, p.hostHeader, mode)
	if err != nil {
		telemetry.DialFailures.Add(1)
		p.mu.Lock()
		var streak int
		var epochMatch bool
		if p.routeEpoch == epochAtStart {
			p.failStreak++
			streak = p.failStreak
			epochMatch = true
		}
		p.mu.Unlock()

		telemetry.Log.Warn("Stealth pipe dial failed",
			slog.String("ip", route.TargetIP),
			slog.String("mode", mode),
			slog.String("condition", cond),
			slog.Int("streak", streak),
			slog.String("err", err.Error()))

		if epochMatch && p.onFailureEvent != nil {
			p.onFailureEvent(cond, streak, route)
		} else if epochMatch && streak >= p.failThreshold {
			p.RotateRoute("consecutive_dial_failures")
		}
		return nil, err
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 1
	smuxCfg.KeepAliveInterval = time.Duration(p.keepAliveSec) * time.Second
	smuxCfg.KeepAliveTimeout = time.Duration(p.keepAliveSec*3) * time.Second
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
	active := make([]*smux.Session, 0, p.targetCap)
	for _, s := range p.sessions {
		if !s.IsClosed() {
			active = append(active, s)
		}
	}
	p.sessions = active
	telemetry.PoolHealthyPipes.Store(int64(len(p.sessions)))
	deficit := p.targetCap - len(p.sessions)
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
# 6. STRATEGIC COORDINATOR (internal/coordinator/strategist.go)
# ---------------------------------------------------------
cat << 'EOF' > internal/coordinator/strategist.go
package coordinator

import (
	"log/slog"
	"sync"

	"self-healing-router/internal/config"
	"self-healing-router/internal/netstack"
	"self-healing-router/internal/proxy/factory"
	"self-healing-router/internal/proxy/pool"
	"self-healing-router/internal/telemetry"
)

type Strategist struct {
	mu       sync.Mutex
	profile  *config.CombatProfile
	warmPool *pool.WarmPool
	rules    map[string]string
}

func NewStrategist(profile *config.CombatProfile) *Strategist {
	rules := make(map[string]string)
	for _, r := range profile.ContingencyMatrix {
		rules[r.Condition] = r.Action
	}
	return &Strategist{
		profile: profile,
		rules:   rules,
	}
}

func (s *Strategist) AttachPool(wp *pool.WarmPool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warmPool = wp
}

// HandleCondition evaluates real-time network failure conditions against the
// combat.profile Contingency Matrix and executes surgical countermeasures.
func (s *Strategist) HandleCondition(condition string, streak int, activeRoute config.RouteCandidate) {
	s.mu.Lock()
	wp := s.warmPool
	action, exists := s.rules[condition]
	threshold := s.profile.Doctrine.FallbackThresholdStreak
	if threshold <= 0 {
		threshold = 3
	}
	s.mu.Unlock()

	if wp == nil {
		return
	}

	if !exists {
		if streak >= threshold {
			wp.RotateRoute("unmapped_condition_" + condition)
		}
		return
	}

	switch action {
	case "escalate_stealth_mode":
		// Progressive escalation ladder: sni_front -> tls_frag -> tls_micro_frag -> rotate IP
		switch activeRoute.StealthMode {
		case factory.ModeSNIFront:
			wp.EscalateStealthMode(factory.ModeTLSFrag, 2, 2)
		case factory.ModeTLSFrag, "":
			wp.EscalateStealthMode(factory.ModeTLSMicroFrag, 3, 4)
		default:
			if streak >= threshold {
				wp.RotateRoute("micro_frag_exhausted_" + condition)
			}
		}

	case "engage_xdp_lockdown":
		expTTL := activeRoute.ExpectedTTL
		if expTTL == 0 {
			expTTL = s.profile.Modules.XDPShield.ExpectedTTL
		}
		// Tighten eBPF kernel tolerance to ±2 hops and activate strict baseline lockdown
		netstack.UpdateXDPConfig(expTTL, 2, true)
		wp.RotateRoute("tcp_rst_storm_xdp_lockdown")

	case "flush_pool_and_rotate_ip":
		if streak >= threshold {
			wp.RotateRoute(condition)
		}
	}

	telemetry.Log.Info("Strategic Doctrine Order Executed",
		slog.String("condition", condition),
		slog.String("action", action),
		slog.Int("streak", streak))
}
EOF

# ---------------------------------------------------------
# 7. UNIX SOCKET IPC CONTROL PLANE (internal/ipc/control_plane.go)
# ---------------------------------------------------------
cat << 'EOF' > internal/ipc/control_plane.go
package ipc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"

	"self-healing-router/internal/config"
	"self-healing-router/internal/coordinator"
	"self-healing-router/internal/netstack"
	"self-healing-router/internal/proxy/pool"
	"self-healing-router/internal/telemetry"
)

const SockAddr = "/tmp/stealth_router_v9.sock"

type IPCCommand struct {
	Action       string                `json:"action"` // "inject_route", "lockdown_xdp", "escalate_stealth", "status"
	Route        config.RouteCandidate `json:"route,omitempty"`
	ExpectedTTL  uint8                 `json:"expected_ttl,omitempty"`
	TTLTolerance uint8                 `json:"ttl_tolerance,omitempty"`
	Lockdown     bool                  `json:"lockdown,omitempty"`
	StealthMode  string                `json:"stealth_mode,omitempty"`
	FragDelayMs  int                   `json:"frag_delay_ms,omitempty"`
	JitterMs     int                   `json:"jitter_ms,omitempty"`
}

type IPCResponse struct {
	Status   string                   `json:"status"`
	Message  string                   `json:"message,omitempty"`
	Snapshot *telemetry.VitalSnapshot `json:"snapshot,omitempty"`
}

func StartControlPlane(ctx context.Context, warmPool *pool.WarmPool, strat *coordinator.Strategist) {
	_ = os.RemoveAll(SockAddr)

	listener, err := net.Listen("unix", SockAddr)
	if err != nil {
		telemetry.Log.Error("IPC Unix socket failed to bind", slog.String("err", err.Error()))
		return
	}
	// Restrict socket permissions to owner/root (0600)
	_ = os.Chmod(SockAddr, 0600)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
		_ = os.RemoveAll(SockAddr)
	}()

	telemetry.Log.Info("v9 IPC Control Plane Listening", slog.String("socket", SockAddr))

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleIPCConn(conn, warmPool, strat)
	}
}

func handleIPCConn(conn net.Conn, warmPool *pool.WarmPool, strat *coordinator.Strategist) {
	defer conn.Close()

	var cmd IPCCommand
	if err := json.NewDecoder(conn).Decode(&cmd); err != nil {
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: err.Error()})
		return
	}

	switch cmd.Action {
	case "inject_route":
		if cmd.Route.ExpectedTTL > 0 {
			tol := cmd.TTLTolerance
			if tol == 0 {
				tol = 3
			}
			netstack.UpdateXDPConfig(cmd.Route.ExpectedTTL, tol, cmd.Lockdown)
		}
		warmPool.InjectEmergencyRoute(cmd.Route)
		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:  "ok",
			Message: "route injected and eBPF TTL map updated live",
		})

	case "lockdown_xdp":
		netstack.UpdateXDPConfig(cmd.ExpectedTTL, cmd.TTLTolerance, cmd.Lockdown)
		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:  "ok",
			Message: "kernel eBPF XDP lockdown parameters updated",
		})

	case "escalate_stealth":
		warmPool.EscalateStealthMode(cmd.StealthMode, cmd.FragDelayMs, cmd.JitterMs)
		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:  "ok",
			Message: "stealth handshake fragmentation mode updated",
		})

	case "status":
		active := warmPool.ActiveRoute()
		snap := &telemetry.VitalSnapshot{
			ActiveStreams:   telemetry.ActiveStreams.Load(),
			WarmPipes:       telemetry.PoolHealthyPipes.Load(),
			TxKB:            telemetry.TotalBytesTx.Load() / 1024,
			RxKB:            telemetry.TotalBytesRx.Load() / 1024,
			RouteRotations:  telemetry.RouteRotations.Load(),
			ModeEscalations: telemetry.ModeEscalations.Load(),
			XDPDroppedPkts:  telemetry.XDPDroppedRSTs.Load(),
			IPCOverrides:    telemetry.IPCOverrides.Load(),
			DialFailures:    telemetry.DialFailures.Load(),
			ExpectedTTL:     telemetry.CurrentExpectedTTL.Load(),
			TTLTolerance:    telemetry.CurrentTTLTolerance.Load(),
			XDPLockdown:     telemetry.CurrentLockdownMode.Load() == 1,
			ActiveRouteIP:   active.TargetIP,
			ActiveStealth:   active.StealthMode,
		}
		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:   "ok",
			Snapshot: snap,
		})

	default:
		_ = json.NewEncoder(conn).Encode(IPCResponse{
			Status:  "error",
			Message: "unknown IPC action: " + cmd.Action,
		})
	}
}
EOF

# ---------------------------------------------------------
# 8. GO CARTOGRAPHER (internal/scanner/cartographer.go)
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
	telemetry.Log.Info("Launching Cartographer v9 (Multi-Mode TLS-Frag + Anycast Echolocation)...",
		slog.String("worker_host", workerHost),
		slog.Bool("verify_ws", verifyWS))

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
	// Primary Strategy: 3-Record TLS Fragmentation (SNI == workerHost)
	for _, ip := range candidateIPs {
		tasks = append(tasks, probeTask{
			ip:          ip,
			sni:         workerHost,
			stealthMode: factory.ModeTLSFrag,
		})
	}
	// Escalated Strategy: 5-Record Surgical Micro-Fragmentation
	for _, ip := range candidateIPs {
		tasks = append(tasks, probeTask{
			ip:          ip,
			sni:         workerHost,
			stealthMode: factory.ModeTLSMicroFrag,
		})
	}

	fac := factory.NewCloudflareFactory(2, 2)
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
				ExpectedTTL:    54,
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
				slog.Int64("tcp_ms", cand.TCPMs),
				slog.Int64("tls_ms", cand.TLSHandshakeMs),
				slog.Int64("ws_ms", cand.WSUpgradeMs),
				slog.Int("score", cand.Score))
		}(t)
	}

	wg.Wait()

	if len(results) == 0 {
		telemetry.Log.Error("All probes failed 101 verification! Seeding fallback with 5-slice micro-fragmentation.")
		results = append(results, config.RouteCandidate{
			TargetIP:    candidateIPs[0],
			CleanSNI:    workerHost,
			StealthMode: factory.ModeTLSMicroFrag,
			ExpectedTTL: 54,
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

	// Deduplicate by TargetIP so failover routes span distinct Anycast edges
	seenIPs := make(map[string]bool)
	var uniqueRoutes []config.RouteCandidate
	for _, r := range results {
		if !seenIPs[r.TargetIP] {
			seenIPs[r.TargetIP] = true
			uniqueRoutes = append(uniqueRoutes, r)
		}
	}

	var failovers []config.RouteCandidate
	if len(uniqueRoutes) > 1 {
		limit := len(uniqueRoutes)
		if limit > 6 {
			limit = 6
		}
		failovers = uniqueRoutes[1:limit]
	}

	atlas := &config.AtlasReport{
		Timestamp:    time.Now().Format(time.RFC3339),
		TotalProbed:  totalProbes,
		ViableRoutes: len(results),
		Throttled:    (uniqueRoutes[0].TCPMs + uniqueRoutes[0].TLSHandshakeMs) > 350,
		RankedMatrix: results,
	}

	combat := config.DefaultCombatProfile(workerHost, uniqueRoutes[0], failovers)

	if err := config.SaveProfiles(combat, atlas); err != nil {
		telemetry.Log.Error("Failed saving strategic profiles", slog.String("err", err.Error()))
		return
	}

	fmt.Printf("\n[+] Cartographer v9 complete: %d/%d probes verified (%d unique Anycast edges).\n",
		len(results), totalProbes, len(uniqueRoutes))
	fmt.Printf("[+] Primary Route: %s | Mode: %s | SNI: %s (Score: %d, TCP: %dms, TLS: %dms, WS: %dms)\n",
		combat.Primary.TargetIP, combat.Primary.StealthMode, combat.Primary.CleanSNI,
		combat.Primary.Score, combat.Primary.TCPMs, combat.Primary.TLSHandshakeMs, combat.Primary.WSUpgradeMs)
	fmt.Println("[+] Saved Strategic combat.profile & atlas.json")
}
EOF

# ---------------------------------------------------------
# 9. SOCKS5 INTAKE & RELAY (internal/router/socks5.go)
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
# 10. MAIN BOOTSTRAP & IPC STATUS CLI (cmd/router/main.go)
# ---------------------------------------------------------
cat << 'EOF' > cmd/router/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"self-healing-router/internal/config"
	"self-healing-router/internal/coordinator"
	"self-healing-router/internal/ipc"
	"self-healing-router/internal/netstack"
	"self-healing-router/internal/proxy/factory"
	"self-healing-router/internal/proxy/pool"
	"self-healing-router/internal/router"
	"self-healing-router/internal/scanner"
	"self-healing-router/internal/telemetry"
)

func queryIPCStatus() {
	conn, err := net.DialTimeout("unix", ipc.SockAddr, 2*time.Second)
	if err != nil {
		fmt.Printf("[-] Engine IPC unreachable at %s: %v\n", ipc.SockAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	_ = json.NewEncoder(conn).Encode(ipc.IPCCommand{Action: "status"})
	var resp ipc.IPCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		fmt.Printf("[-] Failed decoding IPC status: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(out))
}

func main() {
	mapMode := flag.Bool("map", false, "Run Go Cartographer to probe routes and generate Strategic combat.profile")
	runMode := flag.Bool("run", false, "Run the Autonomous Self-Healing v9 Engine")
	statusMode := flag.Bool("status", false, "Query live engine telemetry over Unix IPC socket")
	workerHost := flag.String("worker", "my-proxy.workers.dev", "Cloudflare Worker hostname (used in --map mode)")
	customIPs := flag.String("ips", "", "Optional comma-separated Cloudflare edge IPs to probe in --map mode")
	verifyWS := flag.Bool("verify-ws", true, "Verify full WebSocket 101 upgrade against worker during --map")
	ifaceName := flag.String("iface", "eth0", "Network interface for XDP Kernel Shield")
	listenAddr := flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	verbose := flag.Bool("v", false, "Enable verbose debug telemetry")
	flag.Parse()

	telemetry.InitLogger(*verbose)

	if *statusMode {
		queryIPCStatus()
		return
	}

	if *mapMode {
		scanner.RunCartographer(*workerHost, *verifyWS, *customIPs)
		return
	}

	if *runMode {
		telemetry.PrintBanner()

		profile, err := config.LoadCombatProfile("combat.profile")
		if err != nil {
			fmt.Println("[-] Error: combat.profile not found. Run './router_v9 --map --worker=YOUR_WORKER.workers.dev' or 'sudo python3 scapy_cartographer.py' first.")
			os.Exit(1)
		}

		telemetry.Log.Info("Strategic Combat Doctrine Armed",
			slog.String("version", profile.Version),
			slog.String("primary_ip", profile.Primary.TargetIP),
			slog.String("stealth_mode", profile.Primary.StealthMode),
			slog.Uint64("expected_ttl", uint64(profile.Modules.XDPShield.ExpectedTTL)),
			slog.Uint64("ttl_tolerance", uint64(profile.Modules.XDPShield.TTLTolerance)),
			slog.Int("failover_count", len(profile.Failovers)),
			slog.String("worker", profile.WorkerHost))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfFactory := factory.NewCloudflareFactory(
			profile.Modules.StealthFactory.FragmentationDelayMs,
			profile.Modules.StealthFactory.JitterMs,
		)

		strategist := coordinator.NewStrategist(profile)
		warmPool := pool.NewWarmPool(ctx, cfFactory, profile, strategist.HandleCondition)
		strategist.AttachPool(warmPool)

		// 1. Engage Dynamic XDP Shield; route RST bursts through the Strategic Coordinator
		go netstack.StartXDPRSTMonitor(
			ctx,
			*ifaceName,
			profile.Modules.XDPShield.ExpectedTTL,
			profile.Modules.XDPShield.TTLTolerance,
			profile.Modules.XDPShield.RSTBurstThreshold,
			func() {
				strategist.HandleCondition("tcp_rst_storm", 1, warmPool.ActiveRoute())
			},
		)

		// 2. Start Unix Domain Socket IPC Control Plane (/tmp/stealth_router_v9.sock)
		go ipc.StartControlPlane(ctx, warmPool, strategist)

		// 3. Start Periodic Vital Signs Logger
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					active := warmPool.ActiveRoute()
					telemetry.Log.Info("v9 Engine Vital Signs",
						slog.String("route_ip", active.TargetIP),
						slog.String("stealth", active.StealthMode),
						slog.Int64("active_streams", telemetry.ActiveStreams.Load()),
						slog.Int64("warm_pipes", telemetry.PoolHealthyPipes.Load()),
						slog.Uint64("tx_kb", telemetry.TotalBytesTx.Load()/1024),
						slog.Uint64("rx_kb", telemetry.TotalBytesRx.Load()/1024),
						slog.Uint64("rotations", telemetry.RouteRotations.Load()),
						slog.Uint64("escalations", telemetry.ModeEscalations.Load()),
						slog.Uint64("ipc_overrides", telemetry.IPCOverrides.Load()),
						slog.Uint64("xdp_drops", telemetry.XDPDroppedRSTs.Load()))
				}
			}
		}()

		// 4. Start SOCKS5 Intake
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
	fmt.Println("  1. Map ISP (Go):     ./router_v9 --map --worker=your-worker.workers.dev [-v]")
	fmt.Println("  2. Map ISP (Scapy):  sudo python3 scapy_cartographer.py your-worker.workers.dev 104.18.2.161")
	fmt.Println("  3. Engage v9 Engine: sudo ./router_v9 --run --iface=eth0 --listen=127.0.0.1:1080")
	fmt.Println("  4. Live IPC Vitals:  sudo ./router_v9 --status")
}
EOF

# ---------------------------------------------------------
# 11. SCAPY TOPOLOGICAL SCULPTOR & IPC INJECTOR (scapy_cartographer.py)
# ---------------------------------------------------------
cat << 'EOF' > scapy_cartographer.py
#!/usr/bin/env python3
"""
Self-Healing Stealth Router v9 // Scapy Topological Packet Sculptor & Live IPC Injector
- Phase 1: Locks in True Server SYN+ACK TTL via baseline handshake.
- Phase 2: Provokes ISP DPI to capture forged RST/FIN TTLs and compute exact hop distance.
- Phase 3: Uses OpenSSL MemoryBIO to surgically split the TLS ClientHello record across 3 TCP
           segments right through the SNI midpoint and verifies a real 101 WebSocket upgrade.
- Phase 4: Compiles the Strategic combat.profile AND hot-injects the route + eBPF TTL parameters
           directly into the running Go engine over /tmp/stealth_router_v9.sock.
"""
import base64
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from scapy.all import IP, TCP, conf, sniff

conf.verb = 0
IPC_SOCK_PATH = "/tmp/stealth_router_v9.sock"

DEFAULT_CANDIDATE_IPS = [
    "104.18.2.161",
    "104.18.3.161",
    "104.21.16.1",
    "172.67.128.1",
    "162.159.135.42",
    "188.114.97.3",
]


def split_tls_client_hello(record_bytes: bytes, sni_bytes: bytes) -> list[bytes]:
    """
    Slices a single RFC 8446 / 5246 TLS ClientHello record (0x16) into 3 valid
    TLS Handshake records bisecting the SNI hostname string.
    """
    if len(record_bytes) < 48 or record_bytes[0] != 0x16:
        return [record_bytes]

    ver_major, ver_minor = record_bytes[1], record_bytes[2]
    rec_len = struct.unpack("!H", record_bytes[3:5])[0]
    if 5 + rec_len != len(record_bytes):
        return [record_bytes]

    payload = record_bytes[5:]
    cut1 = 37
    cut2 = len(payload) // 2
    idx = payload.find(sni_bytes)
    if idx > cut1:
        cut2 = idx + (len(sni_bytes) // 2)

    if cut2 <= cut1 or cut2 >= len(payload):
        cut2 = (cut1 + len(payload)) // 2

    chunks = [payload[:cut1], payload[cut1:cut2], payload[cut2:]]
    records = []
    for c in chunks:
        if not c:
            continue
        # Pack exact 5-byte TLS record header: [0x16, major, minor, len_hi, len_lo]
        hdr = struct.pack("!BBBH", 0x16, ver_major, ver_minor, len(c))
        records.append(hdr + c)
    return records


class DPISculptor:
    def __init__(self, target_ip: str, worker_sni: str):
        self.target_ip = target_ip
        self.worker_sni = worker_sni
        self.clean_sni = "www.cloudflare.com"
        self.packets = []
        self.pcap_lock = threading.Lock()

    def _sniffer_thread(self, duration: float = 3.5):
        pkts = sniff(filter=f"host {self.target_ip} and tcp", timeout=duration)
        with self.pcap_lock:
            self.packets.extend(pkts)

    def _standard_tls_probe(self, sni: str):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(2.5)
        try:
            s.connect((self.target_ip, 443))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname=sni)
            ss.do_handshake()
            ss.close()
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _verify_fragmented_ws_101(self) -> tuple[bool, int, int, int]:
        """
        Executes a real TLS-Record-Fragmented handshake + RFC 6455 WebSocket Upgrade
        using OpenSSL MemoryBIO so the ClientHello is split across 3 TCP segments.
        Returns: (ws_verified, tcp_ms, tls_ms, ws_ms)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(4.0)

        t0 = time.monotonic()
        try:
            s.connect((self.target_ip, 443))
            tcp_ms = int((time.monotonic() - t0) * 1000)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["http/1.1"])

            in_bio = ssl.MemoryBIO()
            out_bio = ssl.MemoryBIO()
            ssl_obj = ctx.wrap_bio(in_bio, out_bio, server_hostname=self.worker_sni)

            t_tls = time.monotonic()
            first_flight = True
            sni_bytes = self.worker_sni.encode("utf-8")

            while True:
                try:
                    ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    outgoing = out_bio.read()
                    if outgoing:
                        if first_flight:
                            first_flight = False
                            records = split_tls_client_hello(outgoing, sni_bytes)
                            for i, rec in enumerate(records):
                                s.sendall(rec)
                                if i < len(records) - 1:
                                    time.sleep(0.002)
                        else:
                            s.sendall(outgoing)
                    incoming = s.recv(16384)
                    if not incoming:
                        return False, tcp_ms, 0, 0
                    in_bio.write(incoming)

            # Flush any final handshake ack bytes
            rem = out_bio.read()
            if rem:
                s.sendall(rem)
            tls_ms = int((time.monotonic() - t_tls) * 1000)

            # Test RFC 6455 WebSocket 101 Upgrade inside the fragmented TLS tunnel
            t_ws = time.monotonic()
            ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
            req = (
                f"GET /tunnel HTTP/1.1\r\n"
                f"Host: {self.worker_sni}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Origin: https://{self.worker_sni}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\r\n"
            ).encode("utf-8")

            ssl_obj.write(req)
            s.sendall(out_bio.read())

            while True:
                try:
                    resp = ssl_obj.read(4096)
                    break
                except ssl.SSLWantReadError:
                    enc_in = s.recv(16384)
                    if not enc_in:
                        return False, tcp_ms, tls_ms, 0
                    in_bio.write(enc_in)

            ws_ms = int((time.monotonic() - t_ws) * 1000)
            status_line = resp.split(b"\r\n", 1)[0].decode("latin1", errors="ignore")
            ws_ok = "101" in status_line
            return ws_ok, tcp_ms, tls_ms, ws_ms
        except Exception:
            return False, 0, 0, 0
        finally:
            try:
                s.close()
            except Exception:
                pass

    def map_route(self):
        print(f"\n[+] Sculpting & Echolocating Route: {self.target_ip} -> {self.worker_sni}")

        # Phase 1: Baseline SYN+ACK TTL lock
        self.packets = []
        sniffer = threading.Thread(target=self._sniffer_thread, args=(3.0,))
        sniffer.start()
        time.sleep(0.15)
        self._standard_tls_probe(self.clean_sni)
        sniffer.join()

        server_ttl = None
        for pkt in self.packets:
            if IP in pkt and TCP in pkt and pkt[IP].src == self.target_ip:
                if pkt[TCP].flags == "SA" or int(pkt[TCP].flags) == 0x12:
                    server_ttl = int(pkt[IP].ttl)
                    break

        if not server_ttl:
            print("    └─ [-] Unroutable IP or TCP SYN blocked.")
            return None

        print(f"    ├─ Phase 1 (Baseline): True Edge SYN-ACK TTL = {server_ttl}")

        # Phase 2: Unfragmented Provocation to detect DPI middlebox hop distance
        self.packets = []
        sniffer = threading.Thread(target=self._sniffer_thread, args=(3.0,))
        sniffer.start()
        time.sleep(0.15)
        self._standard_tls_probe(self.worker_sni)
        sniffer.join()

        forged_ttls = []
        for pkt in self.packets:
            if IP in pkt and TCP in pkt and pkt[IP].src == self.target_ip:
                flags_str = str(pkt[TCP].flags)
                if "R" in flags_str or "F" in flags_str:
                    if abs(int(pkt[IP].ttl) - server_ttl) > 4:
                        forged_ttls.append(int(pkt[IP].ttl))

        dpi_active = len(forged_ttls) > 0
        hops_to_dpi = 0
        if dpi_active:
            dpi_ttl = forged_ttls[0]
            start_ttl = 64 if dpi_ttl <= 64 else (128 if dpi_ttl <= 128 else 255)
            hops_to_dpi = start_ttl - dpi_ttl
            print(f"    ├─ Phase 2 (DPI Provocation): Forged RST/FIN TTL={dpi_ttl} (DPI Middlebox @ {hops_to_dpi} hops)")
        else:
            print("    ├─ Phase 2 (DPI Provocation): No forged TCP resets observed.")

        # Phase 3: Surgical 3-Record TLS Split + WebSocket 101 Verification
        ws_ok, tcp_ms, tls_ms, ws_ms = self._verify_fragmented_ws_101()
        stealth_mode = "tls_micro_frag" if dpi_active else "tls_frag"
        total_ms = tcp_ms + tls_ms + ws_ms
        score = max(10, min(100, 100 - (total_ms // 10) + (15 if ws_ok else -25)))

        print(
            f"    └─ Phase 3 (Surgical TLS-Split WS): 101_Verified={ws_ok} | "
            f"TCP={tcp_ms}ms TLS={tls_ms}ms WS={ws_ms}ms | Mode={stealth_mode} | Score={score}"
        )

        return {
            "target_ip": self.target_ip,
            "clean_sni": self.worker_sni,
            "stealth_mode": stealth_mode,
            "expected_ttl": server_ttl,
            "dpi_distance_hops": hops_to_dpi,
            "tcp_ms": tcp_ms,
            "tls_handshake_ms": tls_ms,
            "ws_upgrade_ms": ws_ms,
            "ws_verified": ws_ok,
            "confidence_score": score,
            "dpi_active": dpi_active,
        }


def inject_live_ipc(primary_route: dict, ttl_tolerance: int, lockdown: bool):
    if not os.path.exists(IPC_SOCK_PATH):
        print(f"[i] IPC socket {IPC_SOCK_PATH} not present (Go engine offline); saved combat.profile for boot.")
        return

    payload = {
        "action": "inject_route",
        "route": primary_route,
        "expected_ttl": primary_route["expected_ttl"],
        "ttl_tolerance": ttl_tolerance,
        "lockdown": lockdown,
    }
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(IPC_SOCK_PATH)
        sock.sendall(json.dumps(payload).encode("utf-8"))
        resp_raw = sock.recv(4096)
        sock.close()
        resp = json.loads(resp_raw.decode("utf-8"))
        print(f"[⚡] Live IPC Injection -> {resp.get('status')}: {resp.get('message')}")
    except Exception as exc:
        print(f"[-] Live IPC injection failed: {exc}")


def main():
    if os.geteuid() != 0:
        print("[-] Error: Scapy packet sniffing requires root privileges. Run with sudo.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: sudo python3 scapy_cartographer.py <WORKER_HOST> [IP1 IP2 ...]")
        sys.exit(1)

    worker_sni = sys.argv[1]
    ips = sys.argv[2:] if len(sys.argv) > 2 else DEFAULT_CANDIDATE_IPS

    print("========================================================================")
    print(" ⚡ SCAPY CARTOGRAPHER v9 // TOPOLOGICAL PACKET SCULPTOR & IPC INJECTOR")
    print("========================================================================")

    routes = []
    for ip in ips:
        sculptor = DPISculptor(ip, worker_sni)
        res = sculptor.map_route()
        if res:
            routes.append(res)

    if not routes:
        print("[-] No routable Cloudflare edges found.")
        sys.exit(1)

    routes.sort(
        key=lambda r: (
            r["ws_verified"],
            r["confidence_score"],
            -(r["tcp_ms"] + r["tls_handshake_ms"] + r["ws_upgrade_ms"]),
        ),
        reverse=True,
    )

    primary = routes[0]
    failovers = routes[1:6]
    any_dpi = any(r.get("dpi_active") for r in routes)
    tol = 2 if any_dpi else 4

    combat_profile = {
        "version": "9.0-autonomous",
        "worker_host": worker_sni,
        "expected_ttl": primary["expected_ttl"],
        "operational_doctrine": {
            "telemetry_polling_ms": 3000,
            "max_acceptable_latency_ms": 800,
            "fallback_threshold_streak": 3,
        },
        "modules": {
            "xdp_shield": {
                "mode": "lockdown" if any_dpi else "adaptive",
                "expected_ttl": primary["expected_ttl"],
                "ttl_tolerance": tol,
                "rst_burst_threshold": 5,
            },
            "stealth_factory": {
                "primary_mode": primary["stealth_mode"],
                "fallback_mode": "tls_micro_frag",
                "fragmentation_delay_ms": 3 if any_dpi else 2,
                "jitter_ms": 3,
            },
            "warm_pool": {
                "target_capacity": 3,
                "keepalive_interval_sec": 10,
            },
        },
        "contingency_matrix": [
            {"condition": "http_403_forbidden", "action": "escalate_stealth_mode"},
            {"condition": "dpi_tls_reset", "action": "escalate_stealth_mode"},
            {"condition": "dial_timeout", "action": "flush_pool_and_rotate_ip"},
            {"condition": "tcp_rst_storm", "action": "engage_xdp_lockdown"},
        ],
        "primary_route": primary,
        "failover_routes": failovers,
    }

    with open("combat.profile", "w", encoding="utf-8") as f:
        json.dump(combat_profile, f, indent=2)

    print(f"\n[✓] Strategic combat.profile compiled (Primary: {primary['target_ip']} | TTL={primary['expected_ttl']} ±{tol}).")
    inject_live_ipc(primary, tol, any_dpi)


if __name__ == "__main__":
    main()
EOF
chmod +x scapy_cartographer.py

# ---------------------------------------------------------
# 12. CLOUDFLARE WORKER (worker.js) & WRANGLER AUTOMATOR (deploy_v9.sh)
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

cat << 'EOF' > deploy_v9.sh
#!/bin/bash
set -euo pipefail

WORKER_NAME="${1:-stealth-router-v9}"

cat << TOML > wrangler.toml
name = "$WORKER_NAME"
main = "worker.js"
compatibility_date = "2026-11-07"
TOML

echo "[+] Deploying SMUX v1 Worker ($WORKER_NAME) via Cloudflare Wrangler..."
npx wrangler deploy
EOF
chmod +x deploy_v9.sh

echo "[+] Initializing Go module and fetching dependencies..."
if [ ! -f go.mod ]; then
  go mod init self-healing-router
fi
go get github.com/cilium/ebpf
go get github.com/cilium/ebpf/cmd/bpf2go
go get github.com/cilium/ebpf/link
go get github.com/coder/websocket
go get github.com/refraction-networking/utls
go get github.com/xtaci/smux

echo "[+] Generating eBPF bytecode..."
cd internal/netstack
go generate
cd ../../

echo "[+] Compiling router_v9 binary..."
go build -trimpath -ldflags="-s -w" -o router_v9 ./cmd/router/main.go

echo "========================================================================"
echo "✅ SELF-HEALING STEALTH ROUTER v9.0 (AUTONOMOUS MASTERPIECE) COMPILED"
echo "========================================================================"
echo "1. Deploy Worker:     ./deploy_v9.sh (or upload worker.js to Cloudflare)"
echo "2. Map via Scapy:     sudo python3 scapy_cartographer.py YOUR_WORKER.workers.dev"
echo "   (or via Go):       ./router_v9 --map --worker=YOUR_WORKER.workers.dev -v"
echo "3. Engage v9 Engine:  sudo ./router_v9 --run --iface=eth0 --listen=127.0.0.1:1080"
echo "4. Live IPC Vitals:   sudo ./router_v9 --status"
echo "========================================================================"
