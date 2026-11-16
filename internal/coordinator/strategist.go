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

// resolveStrategistThresholds derives the polling interval and the two
// trip thresholds from the profile, with the production defaults when
// the profile is absent or a value is unset. Pure function, unit-tested.
func resolveStrategistThresholds(p *config.CombatProfile) (pollMs int, rstBurst, failThreshold uint64) {
	pollMs = 3000
	rstBurst = 5
	failThreshold = 3
	if p == nil {
		return pollMs, rstBurst, failThreshold
	}
	if p.OperationalDoctrine.TelemetryPollingMs >= 500 {
		pollMs = p.OperationalDoctrine.TelemetryPollingMs
	}
	if p.Modules.XDPShield.RSTBurstThreshold > 0 {
		rstBurst = p.Modules.XDPShield.RSTBurstThreshold
	}
	if p.OperationalDoctrine.FallbackThreshold > 0 {
		failThreshold = uint64(p.OperationalDoctrine.FallbackThreshold)
	}
	return pollMs, rstBurst, failThreshold
}

// decideRSTBurst reports whether a burst of XDP-dropped RSTs should
// engage the lockdown, given the drop delta since the last poll, the
// burst threshold, and whether lockdown is already on. Pure function.
func decideRSTBurst(dropDelta, rstBurst uint64, lockdown bool) bool {
	return dropDelta >= rstBurst && !lockdown
}

type dialFailureAction int

const (
	dialActionNone dialFailureAction = iota
	// dialActionEscalate switches the active route to a harder stealth
	// mode (tls_frag -> tls_micro_frag).
	dialActionEscalate
	// dialActionRotate moves the active route to the next failover.
	dialActionRotate
)

// decideDialFailure picks the response to a dial-failure streak from the
// active route's stealth mode and the failover ring alone — no network,
// no pool mutation. Escalation comes first: a route still on the basic
// mode is hardened before the ring is spent. Pure function.
func decideDialFailure(mode string, failoverCount int) dialFailureAction {
	if mode == factory.ModeTLSFrag {
		return dialActionEscalate
	}
	if failoverCount > 0 {
		return dialActionRotate
	}
	return dialActionNone
}

func (s *Strategist) Start(ctx context.Context) {
	pollMs, rstBurst, failThreshold := resolveStrategistThresholds(s.profile)

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

			if curDrops > prevDrops && decideRSTBurst(curDrops-prevDrops, rstBurst, telemetry.CurrentLockdownMode.Load() != 0) {
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

			if curFails > prevFails && (curFails-prevFails) >= failThreshold {
				active := s.pool.ActiveRoute()
				switch decideDialFailure(active.StealthMode, s.pool.FailoverCount()) {
				case dialActionEscalate:
					s.pool.EscalateStealthMode(factory.ModeTLSMicroFrag, 3, 3)
					telemetry.RecordEvent("STRAT", "warn", "Dial streak -> escalated tls_micro_frag")
					telemetry.Log.Warn("Dial failure streak; Strategist escalated to tls_micro_frag")
				case dialActionRotate:
					if next, ok := s.pool.RotateToNextFailover(); ok {
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
			}

			prevDrops = curDrops
			prevFails = curFails
		}
	}
}
