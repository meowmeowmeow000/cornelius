package main

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	tea "charm.land/bubbletea/v2"
)

const defaultSockPath = "/run/cornelius/ipc.sock"

type RouteCandidate struct {
	TargetIP        string `json:"target_ip"`
	TargetPort      uint16 `json:"target_port,omitempty"`
	SNISPFDirection string `json:"snispf_direction,omitempty"`
	SpoofSNI        string `json:"spoof_sni,omitempty"`
	CleanSNI        string `json:"clean_sni"`
	WSPath          string `json:"ws_path,omitempty"`
	StealthMode     string `json:"stealth_mode"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	ExpectedTTL     uint8  `json:"expected_ttl,omitempty"`
	DPIDistance     int    `json:"dpi_distance_hops,omitempty"`
	DecoyTTL        uint8  `json:"decoy_ttl,omitempty"`
	TLSHandshakeMs  int64  `json:"tls_handshake_ms,omitempty"`
	WSVerified      bool   `json:"ws_verified,omitempty"`
	Score           int    `json:"confidence_score,omitempty"`
}

type EventEntry struct {
	Time    string `json:"time"`
	Source  string `json:"source"`
	Level   string `json:"level"`
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

type IPCCommand struct {
	Action          string         `json:"action"`
	Route           RouteCandidate `json:"route,omitempty"`
	SNISPFDirection string         `json:"snispf_direction,omitempty"`
	SpoofSNI        string         `json:"spoof_sni,omitempty"`
	CIDR            string         `json:"cidr,omitempty"`
	ExpectedTTL     uint8          `json:"expected_ttl,omitempty"`
	TTLTolerance    uint8          `json:"ttl_tolerance,omitempty"`
	Lockdown        bool           `json:"lockdown,omitempty"`
	StealthMode     string         `json:"stealth_mode,omitempty"`
	FragDelayMs     int            `json:"frag_delay_ms,omitempty"`
	JitterMs        int            `json:"jitter_ms,omitempty"`
}

type VitalSnapshot struct {
	ActiveStreams   uint64           `json:"active_streams"`
	WarmPipes       uint64           `json:"warm_pipes"`
	PoolCapacity    uint64           `json:"pool_capacity"`
	TxKB            uint64           `json:"tx_kb"`
	RxKB            uint64           `json:"rx_kb"`
	RouteRotations  uint64           `json:"route_rotations"`
	ModeEscalations uint64           `json:"mode_escalations"`
	XDPDroppedPkts  uint64           `json:"xdp_dropped_pkts"`
	IPCOverrides    uint64           `json:"ipc_overrides"`
	DialFailures    uint64           `json:"dial_failures"`
	ExpectedTTL     uint32           `json:"expected_ttl"`
	TTLTolerance    uint32           `json:"ttl_tolerance"`
	XDPLockdown     bool             `json:"xdp_lockdown"`
	ActiveRouteIP   string           `json:"active_route_ip"`
	SNISPFDirection string           `json:"snispf_direction"`
	ActiveSpoofSNI  string           `json:"active_spoof_sni"`
	ActiveSNI       string           `json:"active_sni"`
	ActiveStealth   string           `json:"active_stealth"`
	FailoverRoutes  []RouteCandidate `json:"failover_routes,omitempty"`
	RecentEvents    []EventEntry     `json:"recent_events,omitempty"`
	Echo            *EchoSummary     `json:"echo,omitempty"`
	EchoBusy        bool             `json:"echo_busy,omitempty"`
	ScanBusy        bool             `json:"scan_busy,omitempty"`
}

type HealthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "ok", "warn" or "fail"
	Detail string `json:"detail,omitempty"`
}

type IPCResponse struct {
	Status   string         `json:"status"`
	Message  string         `json:"message,omitempty"`
	Snapshot *VitalSnapshot `json:"snapshot,omitempty"`
	Checks   []HealthCheck  `json:"checks,omitempty"`
}

type statusMsg struct {
	snap *VitalSnapshot
	err  error
	at   time.Time
}

type doctorMsg struct {
	checks []HealthCheck
	err    error
	at     time.Time
}

type actionResultMsg struct {
	label string
	err   error
}

func sendIPC(sockPath string, cmd IPCCommand) (IPCResponse, error) {
	conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond)
	if err != nil {
		return IPCResponse{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(850 * time.Millisecond))
	if err := json.NewEncoder(conn).Encode(cmd); err != nil {
		return IPCResponse{}, err
	}

	var resp IPCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return IPCResponse{}, err
	}
	if resp.Status != "ok" {
		return resp, fmt.Errorf("daemon rejected: %s", resp.Message)
	}
	return resp, nil
}

func fetchStatusCmd(sockPath string) tea.Cmd {
	return func() tea.Msg {
		resp, err := sendIPC(sockPath, IPCCommand{Action: "status"})
		if err != nil {
			return statusMsg{err: err, at: time.Now()}
		}
		if resp.Snapshot == nil {
			return statusMsg{err: fmt.Errorf("empty snapshot"), at: time.Now()}
		}
		return statusMsg{snap: resp.Snapshot, at: time.Now()}
	}
}

func fetchDoctorCmd(sockPath string) tea.Cmd {
	return func() tea.Msg {
		resp, err := sendIPC(sockPath, IPCCommand{Action: "doctor"})
		if err != nil {
			return doctorMsg{err: err, at: time.Now()}
		}
		return doctorMsg{checks: resp.Checks, at: time.Now()}
	}
}

func dispatchControlCmd(sockPath, label string, cmd IPCCommand) tea.Cmd {
	return func() tea.Msg {
		_, err := sendIPC(sockPath, cmd)
		return actionResultMsg{label: label, err: err}
	}
}
