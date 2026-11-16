package scanner

import (
	"time"

	utls "github.com/refraction-networking/utls"
)

type StealthMode string

const (
	ModeTLSFrag      StealthMode = "tls_frag"
	ModeTLSMicroFrag StealthMode = "tls_micro_frag"
	ModeTLSDisorder  StealthMode = "tls_disorder"
)

type ProbeTask struct {
	IP          string
	Port        int
	Direction   string
	SpoofSNI    string
	TargetSNI   string
	Fingerprint string
	ClientHello utls.ClientHelloID
	Mode        StealthMode
	WSPath      string // secret WebSocket path to verify; empty skips the check
	Timeout     time.Duration
}

type ProbeResult struct {
	IP          string        `json:"ip"`
	Port        int           `json:"port,omitempty"`
	Direction   string        `json:"snispf_direction,omitempty"`
	SpoofSNI    string        `json:"spoof_sni,omitempty"`
	SNI         string        `json:"sni"`
	Fingerprint string        `json:"fingerprint"`
	Mode        StealthMode   `json:"mode"`
	ExpectedTTL uint8         `json:"expected_ttl,omitempty"`
	Success     bool          `json:"tls_verified"`
	WSVerified  bool          `json:"ws_verified"`
	Latency     time.Duration `json:"latency_ns"`
	ErrStr      string        `json:"error,omitempty"`
	// VerifyErr names why the tunnel verification failed, when it did:
	// "" (ok), "upgrade" (no WebSocket 101), "no-traffic" (upgraded but
	// no SMUX echo before the deadline — handshake ok, no traffic),
	// "closed" (connection error after the upgrade). Empty when the probe
	// did not attempt verification (no WSPath).
	VerifyErr string `json:"verify_error,omitempty"`
}

type IntelligenceReport struct {
	Timestamp     time.Time     `json:"timestamp"`
	WorkerHost    string        `json:"worker_host"`
	SpoofHost     string        `json:"spoof_host,omitempty"`
	ScanMode      string        `json:"scan_mode,omitempty"`
	TotalScanned  int           `json:"completed_probes"`
	SuccessfulTLS int           `json:"successful_tls_handshakes"`
	CleanEdges    []ProbeResult `json:"verified_tls_endpoints"`
}
