package config

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	SNISPFDirectionLegacy   = "legacy"   // Outer TLS SNI == Inner Host (CleanSNI); SpoofSNI used only for decoys
	SNISPFDirectionFronting = "fronting" // Outer TLS SNI == SpoofSNI; Inner encrypted Host == CleanSNI
)

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
	TCPMs           int64  `json:"tcp_ms,omitempty"`
	TLSHandshakeMs  int64  `json:"tls_handshake_ms,omitempty"`
	WSUpgradeMs     int64  `json:"ws_upgrade_ms,omitempty"`
	WSVerified      bool   `json:"ws_verified"`
	Score           int    `json:"confidence_score"`
	DPIActive       bool   `json:"dpi_active,omitempty"`
}

type OperationalDoctrine struct {
	TelemetryPollingMs     int `json:"telemetry_polling_ms"`
	MaxAcceptableLatencyMs int `json:"max_acceptable_latency_ms"`
	FallbackThreshold      int `json:"fallback_threshold_streak"`
}

type XDPShieldConfig struct {
	Mode              string `json:"mode"`
	ExpectedTTL       uint8  `json:"expected_ttl"`
	TTLTolerance      uint8  `json:"ttl_tolerance"`
	RSTBurstThreshold uint64 `json:"rst_burst_threshold"`
}

type StealthFactoryConfig struct {
	SNISPFDirection      string `json:"snispf_direction"`
	DefaultSpoofSNI      string `json:"default_spoof_sni,omitempty"`
	DefaultWSPath        string `json:"default_ws_path,omitempty"`
	PrimaryMode          string `json:"primary_mode"`
	FallbackMode         string `json:"fallback_mode"`
	FragmentationDelayMs int    `json:"fragmentation_delay_ms"`
	JitterMs             int    `json:"jitter_ms"`
	AllowInsecureCerts   bool   `json:"allow_insecure_certs"`
}

type WarmPoolConfig struct {
	TargetCapacity       int `json:"target_capacity"`
	KeepaliveIntervalSec int `json:"keepalive_interval_sec"`
}

type ModulesConfig struct {
	XDPShield      XDPShieldConfig      `json:"xdp_shield"`
	StealthFactory StealthFactoryConfig `json:"stealth_factory"`
	WarmPool       WarmPoolConfig       `json:"warm_pool"`
}

type ContingencyRule struct {
	Condition string `json:"condition"`
	Action    string `json:"action"`
}

type CombatProfile struct {
	Version             string              `json:"version"`
	WorkerHost          string              `json:"worker_host"`
	ExpectedTTL         uint8               `json:"expected_ttl"`
	OperationalDoctrine OperationalDoctrine `json:"operational_doctrine"`
	Modules             ModulesConfig       `json:"modules"`
	ContingencyMatrix   []ContingencyRule   `json:"contingency_matrix"`
	PrimaryRoute        RouteCandidate      `json:"primary_route"`
	FailoverRoutes      []RouteCandidate    `json:"failover_routes"`
}

func NormalizeRoute(r *RouteCandidate, defaultDir, defaultSpoof, defaultWS string) {
	if r == nil {
		return
	}
	if r.TargetPort == 0 {
		r.TargetPort = 443
	}
	if r.SpoofSNI == "" {
		r.SpoofSNI = defaultSpoof
	}
	if r.WSPath == "" {
		r.WSPath = defaultWS
	}
	if r.SNISPFDirection == "" {
		if defaultDir != "" {
			r.SNISPFDirection = defaultDir
		} else if r.SpoofSNI != "" && r.SpoofSNI != r.CleanSNI {
			r.SNISPFDirection = SNISPFDirectionFronting
		} else {
			r.SNISPFDirection = SNISPFDirectionLegacy
		}
	}
}

func LoadCombatProfile(path string) (*CombatProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read combat profile: %w", err)
	}
	var prof CombatProfile
	if err := json.Unmarshal(data, &prof); err != nil {
		return nil, fmt.Errorf("unmarshal combat profile: %w", err)
	}
	sf := prof.Modules.StealthFactory
	NormalizeRoute(&prof.PrimaryRoute, sf.SNISPFDirection, sf.DefaultSpoofSNI, sf.DefaultWSPath)
	for i := range prof.FailoverRoutes {
		NormalizeRoute(&prof.FailoverRoutes[i], sf.SNISPFDirection, sf.DefaultSpoofSNI, sf.DefaultWSPath)
	}
	return &prof, nil
}

func DefaultCombatProfile(workerHost string, primary RouteCandidate, failovers []RouteCandidate) *CombatProfile {
	NormalizeRoute(&primary, "", "", "")
	for i := range failovers {
		NormalizeRoute(&failovers[i], primary.SNISPFDirection, primary.SpoofSNI, primary.WSPath)
	}

	tol := uint8(4)
	mode := "adaptive"
	if primary.DPIActive {
		tol = 2
		mode = "lockdown"
	}
	return &CombatProfile{
		Version:     "1.2-cornelius",
		WorkerHost:  workerHost,
		ExpectedTTL: primary.ExpectedTTL,
		OperationalDoctrine: OperationalDoctrine{
			TelemetryPollingMs:     3000,
			MaxAcceptableLatencyMs: 800,
			FallbackThreshold:      3,
		},
		Modules: ModulesConfig{
			XDPShield: XDPShieldConfig{
				Mode:              mode,
				ExpectedTTL:       primary.ExpectedTTL,
				TTLTolerance:      tol,
				RSTBurstThreshold: 5,
			},
			StealthFactory: StealthFactoryConfig{
				SNISPFDirection:      primary.SNISPFDirection,
				DefaultSpoofSNI:      primary.SpoofSNI,
				DefaultWSPath:        primary.WSPath,
				PrimaryMode:          primary.StealthMode,
				FallbackMode:         "tls_micro_frag",
				FragmentationDelayMs: 2,
				JitterMs:             2,
				AllowInsecureCerts:   false,
			},
			WarmPool: WarmPoolConfig{
				TargetCapacity:       3,
				KeepaliveIntervalSec: 10,
			},
		},
		ContingencyMatrix: []ContingencyRule{
			{Condition: "http_403_forbidden", Action: "escalate_stealth_mode"},
			{Condition: "dpi_tls_reset", Action: "escalate_stealth_mode"},
			{Condition: "dial_timeout", Action: "flush_pool_and_rotate_ip"},
			{Condition: "dial_unreachable", Action: "flush_pool_and_rotate_ip"},
			{Condition: "tcp_rst_storm", Action: "engage_xdp_lockdown"},
		},
		PrimaryRoute:   primary,
		FailoverRoutes: failovers,
	}
}
