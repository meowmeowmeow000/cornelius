package coordinator

import (
	"context"
	"strings"
	"testing"
	"time"

	"cornelius/internal/config"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/proxy/pool"
	"cornelius/internal/telemetry"
)

func TestResolveStrategistThresholds(t *testing.T) {
	poll, burst, fail := resolveStrategistThresholds(nil)
	if poll != 3000 || burst != 5 || fail != 3 {
		t.Fatalf("nil profile = %d/%d/%d, want 3000/5/3", poll, burst, fail)
	}

	p := &config.CombatProfile{}
	p.OperationalDoctrine.TelemetryPollingMs = 500
	p.OperationalDoctrine.FallbackThreshold = 7
	p.Modules.XDPShield.RSTBurstThreshold = 9
	poll, burst, fail = resolveStrategistThresholds(p)
	if poll != 500 || burst != 9 || fail != 7 {
		t.Fatalf("custom profile = %d/%d/%d, want 500/9/7", poll, burst, fail)
	}

	// Values below the floors fall back to the defaults, never to a
	// zero or sub-second poll that would spin the loop.
	p.OperationalDoctrine.TelemetryPollingMs = 100
	p.OperationalDoctrine.FallbackThreshold = 0
	p.Modules.XDPShield.RSTBurstThreshold = 0
	poll, burst, fail = resolveStrategistThresholds(p)
	if poll != 3000 || burst != 5 || fail != 3 {
		t.Fatalf("below-floor profile = %d/%d/%d, want 3000/5/3", poll, burst, fail)
	}
}

func TestDecideRSTBurst(t *testing.T) {
	cases := []struct {
		delta, burst uint64
		lockdown     bool
		want         bool
	}{
		{5, 5, false, true},  // at the threshold: lockdown
		{6, 5, false, true},  // above it: lockdown
		{4, 5, false, false}, // one short: no lockdown
		{0, 5, false, false}, // no new drops: nothing to do
		{99, 5, true, false}, // already locked down: do not re-fire
		{5, 5, true, false},
	}
	for _, tc := range cases {
		if got := decideRSTBurst(tc.delta, tc.burst, tc.lockdown); got != tc.want {
			t.Errorf("decideRSTBurst(%d, %d, %v) = %v, want %v", tc.delta, tc.burst, tc.lockdown, got, tc.want)
		}
	}
}

func TestDecideDialFailure(t *testing.T) {
	cases := []struct {
		mode      string
		failovers int
		want      dialFailureAction
	}{
		{factory.ModeTLSFrag, 0, dialActionEscalate},    // harden first, even with no ring
		{factory.ModeTLSFrag, 2, dialActionEscalate},    // escalation beats rotation
		{factory.ModeTLSMicroFrag, 1, dialActionRotate}, // already hard: rotate
		{factory.ModeTLSDisorder, 1, dialActionRotate},  // any non-frag mode rotates
		{factory.ModeSNIFront, 3, dialActionRotate},     // fronting rotates too
		{factory.ModeTLSMicroFrag, 0, dialActionNone},   // hard mode, empty ring: stuck, do nothing
		{"", 0, dialActionNone},                         // unknown mode, no ring: nothing to do
		{"", 1, dialActionRotate},                       // unknown mode with a ring: rotate
	}
	for _, tc := range cases {
		if got := decideDialFailure(tc.mode, tc.failovers); got != tc.want {
			t.Errorf("decideDialFailure(%q, %d) = %v, want %v", tc.mode, tc.failovers, got, tc.want)
		}
	}
}

func TestShouldAnswerDialStreak(t *testing.T) {
	cases := []struct {
		name                       string
		curFails, prevFails        uint64
		curRotations, prevRotation uint64
		threshold                  uint64
		want                       bool
	}{
		{"streak, ring untouched", 3, 0, 0, 0, 3, true},
		{"streak already answered by a rotation", 3, 0, 2, 0, 3, false},
		{"bigger streak, still already answered", 5, 0, 1, 0, 3, false},
		{"below threshold", 2, 0, 0, 0, 3, false},
		{"no new failures", 3, 3, 0, 0, 3, false},
		{"rotation from an earlier tick is not a veto", 6, 3, 2, 2, 3, true},
	}
	for _, tc := range cases {
		if got := shouldAnswerDialStreak(tc.curFails, tc.prevFails, tc.curRotations, tc.prevRotation, tc.threshold); got != tc.want {
			t.Errorf("%s: shouldAnswerDialStreak(%d, %d, %d, %d, %d) = %v, want %v",
				tc.name, tc.curFails, tc.prevFails, tc.curRotations, tc.prevRotation, tc.threshold, got, tc.want)
		}
	}
}

// resetStrategistCounters zeroes the process-global telemetry the
// strategist reads. These tests share the globals with each other (never
// with other packages: each test binary is its own process), so every
// integration test resets before and after itself.
func resetStrategistCounters() {
	telemetry.DialFailures.Store(0)
	telemetry.XDPDroppedRSTs.Store(0)
	telemetry.CurrentLockdownMode.Store(0)
	telemetry.CurrentExpectedTTL.Store(0)
	telemetry.CurrentTTLTolerance.Store(0)
}

func fastProfile() *config.CombatProfile {
	p := &config.CombatProfile{}
	p.OperationalDoctrine.TelemetryPollingMs = 500
	return p
}

func testStrategistRoute(ip, mode string) config.RouteCandidate {
	return config.RouteCandidate{
		TargetIP:    ip,
		TargetPort:  443,
		CleanSNI:    "worker.test",
		StealthMode: mode,
		ExpectedTTL: 55,
	}
}

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestStrategistEscalatesOnDialStreak(t *testing.T) {
	resetStrategistCounters()
	defer resetStrategistCounters()
	p := pool.NewWarmPool(&config.CombatProfile{
		PrimaryRoute:   testStrategistRoute("10.0.0.1", factory.ModeTLSFrag),
		FailoverRoutes: []config.RouteCandidate{testStrategistRoute("10.0.0.2", factory.ModeTLSFrag)},
	})
	// A streak of 3 dial failures (the default threshold) on a tls_frag
	// route escalates the mode instead of spending the failover ring.
	telemetry.DialFailures.Store(3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewStrategist(p, fastProfile()).Start(ctx)
	waitFor(t, "escalation to tls_micro_frag", func() bool {
		return p.ActiveRoute().StealthMode == factory.ModeTLSMicroFrag
	})
	if got := p.ActiveRoute().TargetIP; got != "10.0.0.1" {
		t.Fatalf("escalation must not rotate the route, active = %s", got)
	}
}

func TestStrategistRotatesOnDialStreak(t *testing.T) {
	resetStrategistCounters()
	defer resetStrategistCounters()
	p := pool.NewWarmPool(&config.CombatProfile{
		PrimaryRoute:   testStrategistRoute("10.0.0.1", factory.ModeTLSMicroFrag),
		FailoverRoutes: []config.RouteCandidate{testStrategistRoute("10.0.0.2", factory.ModeTLSMicroFrag)},
	})
	// Already on the hard mode: the same streak rotates to the failover.
	telemetry.DialFailures.Store(3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewStrategist(p, fastProfile()).Start(ctx)
	waitFor(t, "rotation to 10.0.0.2", func() bool {
		return p.ActiveRoute().TargetIP == "10.0.0.2"
	})
}

func TestStrategistIgnoresSubThresholdStreaks(t *testing.T) {
	resetStrategistCounters()
	defer resetStrategistCounters()
	p := pool.NewWarmPool(&config.CombatProfile{
		PrimaryRoute:   testStrategistRoute("10.0.0.1", factory.ModeTLSFrag),
		FailoverRoutes: []config.RouteCandidate{testStrategistRoute("10.0.0.2", factory.ModeTLSFrag)},
	})
	telemetry.DialFailures.Store(2) // below the threshold of 3
	telemetry.XDPDroppedRSTs.Store(4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewStrategist(p, fastProfile()).Start(ctx)
	time.Sleep(1200 * time.Millisecond) // two polls at 500ms
	if got := p.ActiveRoute(); got.StealthMode != factory.ModeTLSFrag || got.TargetIP != "10.0.0.1" {
		t.Fatalf("sub-threshold streaks must change nothing, active = %+v", got)
	}
	if telemetry.CurrentLockdownMode.Load() != 0 {
		t.Fatal("sub-threshold RST drops must not engage lockdown")
	}
}

func TestStrategistLocksDownOnRSTBurst(t *testing.T) {
	resetStrategistCounters()
	defer resetStrategistCounters()
	p := pool.NewWarmPool(&config.CombatProfile{
		PrimaryRoute: testStrategistRoute("10.0.0.1", factory.ModeTLSFrag),
	})
	telemetry.XDPDroppedRSTs.Store(5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewStrategist(p, fastProfile()).Start(ctx)
	waitFor(t, "XDP lockdown", func() bool {
		return telemetry.CurrentLockdownMode.Load() == 1
	})
	// A second burst while locked down must not re-fire the lockdown
	// action: count the LOCKDOWN events before and after.
	countLockdowns := func() int {
		n := 0
		for _, e := range telemetry.RecentEvents(24) {
			if strings.Contains(e.Message, "XDP LOCKDOWN") {
				n++
			}
		}
		return n
	}
	before := countLockdowns()
	telemetry.XDPDroppedRSTs.Add(5)
	time.Sleep(1200 * time.Millisecond)
	if got := countLockdowns(); got != before {
		t.Fatalf("lockdown re-fired while already locked down (%d -> %d events)", before, got)
	}
}
