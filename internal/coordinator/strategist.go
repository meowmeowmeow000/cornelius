package coordinator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"cornelius/internal/bpf"
	"cornelius/internal/config"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/proxy/pool"
	"cornelius/internal/telemetry"
)

type Strategist struct {
	pool    *pool.WarmPool
	profile *config.CombatProfile
}

func NewStrategist(warmPool *pool.WarmPool, profile *config.CombatProfile) *Strategist {
	return &Strategist{
		pool:    warmPool,
		profile: profile,
	}
}

func (s *Strategist) Start(ctx context.Context) {
	pollMs := 3000
	var rstBurst uint64 = 5
	var failThreshold uint64 = 3
	if s.profile != nil {
		if s.profile.OperationalDoctrine.TelemetryPollingMs >= 500 {
			pollMs = s.profile.OperationalDoctrine.TelemetryPollingMs
		}
		if s.profile.Modules.XDPShield.RSTBurstThreshold > 0 {
			rstBurst = s.profile.Modules.XDPShield.RSTBurstThreshold
		}
		if s.profile.OperationalDoctrine.FallbackThreshold > 0 {
			failThreshold = uint64(s.profile.OperationalDoctrine.FallbackThreshold)
		}
	}

	ticker := time.NewTicker(time.Duration(pollMs) * time.Millisecond)
	defer ticker.Stop()

	var prevDrops uint64
	var prevFails uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			curDrops := telemetry.XDPDroppedRSTs.Load()
			curFails := telemetry.DialFailures.Load()

			if curDrops > prevDrops && (curDrops-prevDrops) >= rstBurst {
				if telemetry.CurrentLockdownMode.Load() == 0 {
					active := s.pool.ActiveRoute()
					ttl := uint8(telemetry.CurrentExpectedTTL.Load())
					tol := uint8(telemetry.CurrentTTLTolerance.Load())
					if tol == 0 {
						tol = 2
					}
					_ = bpf.UpdateXDPConfig(ttl, tol, true, active.TargetPort)
					telemetry.RecordEvent("STRAT", "crit", fmt.Sprintf("RST burst (+%d) -> XDP LOCKDOWN", curDrops-prevDrops))
					telemetry.Log.Warn("RST storm detected; Strategist engaged XDP Lockdown",
						slog.Uint64("burst_drops", curDrops-prevDrops))
				}
			}

			if curFails > prevFails && (curFails-prevFails) >= failThreshold {
				active := s.pool.ActiveRoute()
				if active.StealthMode == factory.ModeTLSFrag {
					s.pool.EscalateStealthMode(factory.ModeTLSMicroFrag, 3, 3)
					telemetry.RecordEvent("STRAT", "warn", "Dial streak -> escalated tls_micro_frag")
					telemetry.Log.Warn("Dial failure streak; Strategist escalated to tls_micro_frag")
				} else if next, ok := s.pool.RotateToNextFailover(); ok {
					if next.ExpectedTTL > 0 {
						tol := uint8(telemetry.CurrentTTLTolerance.Load())
						lock := telemetry.CurrentLockdownMode.Load() == 1
						_ = bpf.UpdateXDPConfig(next.ExpectedTTL, tol, lock, next.TargetPort)
					}
					telemetry.RecordEvent("STRAT", "crit", fmt.Sprintf("Dial streak -> failover %s", next.TargetIP))
					telemetry.Log.Warn("Dial failure streak; Strategist rotated to failover route",
						slog.String("new_ip", next.TargetIP))
				}
			}

			prevDrops = curDrops
			prevFails = curFails
		}
	}
}
