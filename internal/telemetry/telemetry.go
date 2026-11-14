package telemetry

import (
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"cornelius/internal/config"
)

var (
	Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ActiveStreams       atomic.Uint64
	PoolHealthyPipes    atomic.Uint64
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

type EventEntry struct {
	Time    string `json:"time"`
	Source  string `json:"source"`
	Level   string `json:"level"` // "info", "warn", "crit"
	Message string `json:"message"`
}

type EchoHopSummary struct {
	TTL      uint8  `json:"ttl"`
	RouterIP string `json:"router_ip,omitempty"`
	Event    string `json:"event"`
	RTTMs    int64  `json:"rtt_ms"`
}

type EchoSummary struct {
	TargetIP            string           `json:"target_ip"`
	DPIIntercepted      bool             `json:"dpi_intercepted"`
	DPIDistanceHops     int              `json:"dpi_distance_hops"`
	ServerDistanceHops  int              `json:"server_distance_hops,omitempty"`
	RecommendedDecoyTTL uint8            `json:"recommended_decoy_ttl"`
	Hops                []EchoHopSummary `json:"hops"`
}

var (
	stateMu     sync.RWMutex
	eventRing   []EventEntry
	latestEcho  *EchoSummary
	scanRunning bool
	echoRunning bool
)

const maxEventRing = 24

func RecordEvent(source, level, message string) {
	entry := EventEntry{
		Time:    time.Now().Format("15:04:05"),
		Source:  source,
		Level:   level,
		Message: message,
	}
	stateMu.Lock()
	if len(eventRing) >= maxEventRing {
		copy(eventRing, eventRing[1:])
		eventRing[len(eventRing)-1] = entry
	} else {
		eventRing = append(eventRing, entry)
	}
	stateMu.Unlock()
}

func RecentEvents(limit int) []EventEntry {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if len(eventRing) == 0 {
		return nil
	}
	if limit <= 0 || limit >= len(eventRing) {
		out := make([]EventEntry, len(eventRing))
		copy(out, eventRing)
		return out
	}
	out := make([]EventEntry, limit)
	copy(out, eventRing[len(eventRing)-limit:])
	return out
}

func SetEchoSummary(s *EchoSummary) {
	stateMu.Lock()
	latestEcho = s
	stateMu.Unlock()
}

func GetEchoSummary() *EchoSummary {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return latestEcho
}

func SetBackgroundBusy(echoBusy, scanBusy *bool) {
	stateMu.Lock()
	if echoBusy != nil {
		echoRunning = *echoBusy
	}
	if scanBusy != nil {
		scanRunning = *scanBusy
	}
	stateMu.Unlock()
}

func GetBackgroundBusy() (echoBusy bool, scanBusy bool) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return echoRunning, scanRunning
}

type VitalSnapshot struct {
	ActiveStreams   uint64                  `json:"active_streams"`
	WarmPipes       uint64                  `json:"warm_pipes"`
	PoolCapacity    uint64                  `json:"pool_capacity"`
	TxKB            uint64                  `json:"tx_kb"`
	RxKB            uint64                  `json:"rx_kb"`
	RouteRotations  uint64                  `json:"route_rotations"`
	ModeEscalations uint64                  `json:"mode_escalations"`
	XDPDroppedPkts  uint64                  `json:"xdp_dropped_pkts"`
	IPCOverrides    uint64                  `json:"ipc_overrides"`
	DialFailures    uint64                  `json:"dial_failures"`
	ExpectedTTL     uint32                  `json:"expected_ttl"`
	TTLTolerance    uint32                  `json:"ttl_tolerance"`
	XDPLockdown     bool                    `json:"xdp_lockdown"`
	ActiveRouteIP   string                  `json:"active_route_ip"`
	SNISPFDirection string                  `json:"snispf_direction"`
	ActiveSpoofSNI  string                  `json:"active_spoof_sni"`
	ActiveSNI       string                  `json:"active_sni"`
	ActiveStealth   string                  `json:"active_stealth"`
	FailoverRoutes  []config.RouteCandidate `json:"failover_routes,omitempty"`
	RecentEvents    []EventEntry            `json:"recent_events,omitempty"`
	Echo            *EchoSummary            `json:"echo,omitempty"`
	EchoBusy        bool                    `json:"echo_busy,omitempty"`
	ScanBusy        bool                    `json:"scan_busy,omitempty"`
}

func InitLogger(level slog.Level) {
	Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
