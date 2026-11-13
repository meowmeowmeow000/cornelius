//go:build !linux

package scanner

import (
	"context"
	"fmt"
	"time"
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

func EcholocateDPI(_ context.Context, _ string, _ int, _ string, _ int) (*EcholocationReport, error) {
	return nil, fmt.Errorf("DPI echolocation is only supported on Linux")
}
