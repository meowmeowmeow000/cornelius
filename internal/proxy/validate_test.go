package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cornelius/internal/config"
)

func TestValidateStartupProfile(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*config.CombatProfile)
		wantErr string // substring of the error, "" means no error
	}{
		{"valid profile", func(*config.CombatProfile) {}, ""},
		{"empty worker host", func(p *config.CombatProfile) { p.WorkerHost = "" }, "worker host is set"},
		{"empty WebSocket path", func(p *config.CombatProfile) { p.Modules.StealthFactory.DefaultWSPath = "" }, "WebSocket path is configured"},
		{"root WebSocket path", func(p *config.CombatProfile) { p.Modules.StealthFactory.DefaultWSPath = "/" }, "WebSocket path is configured"},
		{"unknown direction", func(p *config.CombatProfile) { p.Modules.StealthFactory.SNISPFDirection = "sideways" }, "SNI direction is legacy"},
		{"no primary target", func(p *config.CombatProfile) { p.PrimaryRoute.TargetIP = "" }, "primary route has a target"},
		{"no clean SNI", func(p *config.CombatProfile) { p.PrimaryRoute.CleanSNI = "" }, "route knows the Worker host"},
		// An empty profile (the IPC-injection path) must never pass
		// validation: the daemon only skips this check when no profile
		// file loaded at all.
		{"empty profile", func(p *config.CombatProfile) { *p = config.CombatProfile{} }, "worker host is set"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProfile()
			tc.mutate(p)
			err := ValidateStartupProfile(p)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestStartupWarningsDoNotBlock(t *testing.T) {
	p := testProfile()
	// Fronting direction and ECH off are warnings, never failures.
	p.Modules.StealthFactory.SNISPFDirection = config.SNISPFDirectionFronting
	p.Modules.StealthFactory.ECHEnabled = false
	if err := ValidateStartupProfile(p); err != nil {
		t.Fatalf("warnings must not block startup, got: %v", err)
	}
	if got := StartupWarnings(p); len(got) == 0 {
		t.Fatal("expected at least the fronting and ECH warnings")
	}
}

// TestShippedProfilesPassStartupValidation guards the profiles the repo
// actually ships: a future edit that breaks one must fail here, not on
// a user's machine at boot.
func TestShippedProfilesPassStartupValidation(t *testing.T) {
	for _, rel := range []string{"../../combat.profile", "../../configs/combat.profile"} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			abs, err := filepath.Abs(rel)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(abs); err != nil {
				t.Skipf("profile not present at %s", abs)
			}
			p, err := config.LoadCombatProfile(abs)
			if err != nil {
				t.Fatalf("load %s: %v", abs, err)
			}
			if err := ValidateStartupProfile(p); err != nil {
				t.Fatalf("shipped profile %s fails startup validation: %v", abs, err)
			}
		})
	}
}
