package proxy

import (
	"fmt"
	"strings"

	"cornelius/internal/config"
)

// ValidateStartupProfile runs the pure profile checks (no I/O) and
// returns one error per failing check, or nil when the profile is safe
// to start with. Warnings never block startup.
//
// The daemon calls this after a profile file loads successfully. A
// profile that fails to load at all is a different path: the daemon
// starts empty and waits for routes to be injected over IPC, so that
// path deliberately does not go through this function.
func ValidateStartupProfile(p *config.CombatProfile) error {
	var fails []string
	for _, c := range CheckProfileHealth(p) {
		if c.Status == "fail" {
			fails = append(fails, c.String())
		}
	}
	if len(fails) == 0 {
		return nil
	}
	return fmt.Errorf("refusing to start with a broken profile:\n  - %s", strings.Join(fails, "\n  - "))
}

// StartupWarnings returns the non-blocking warnings for a profile, so
// the daemon can log them at boot without refusing to start.
func StartupWarnings(p *config.CombatProfile) []HealthCheck {
	var out []HealthCheck
	for _, c := range CheckProfileHealth(p) {
		if c.Status == "warn" {
			out = append(out, c)
		}
	}
	return out
}
