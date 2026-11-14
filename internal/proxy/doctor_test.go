package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"cornelius/internal/config"
)

func testProfile() *config.CombatProfile {
	return &config.CombatProfile{
		WorkerHost: "bold-heart-a6e2.nedaymarg.workers.dev",
		Modules: config.ModulesConfig{
			StealthFactory: config.StealthFactoryConfig{
				SNISPFDirection: config.SNISPFDirectionLegacy,
				DefaultSpoofSNI: "www.speedtest.net",
				DefaultWSPath:   "/secret-knock-99",
			},
		},
		PrimaryRoute: config.RouteCandidate{
			TargetIP:        "104.18.2.161",
			TargetPort:      443,
			SNISPFDirection: config.SNISPFDirectionLegacy,
			CleanSNI:        "bold-heart-a6e2.nedaymarg.workers.dev",
			StealthMode:     "tls_frag",
		},
	}
}

func countStatus(checks []HealthCheck, want string) int {
	n := 0
	for _, c := range checks {
		if c.Status == want {
			n++
		}
	}
	return n
}

func TestValidateProfileHealthy(t *testing.T) {
	if fails := countStatus(CheckProfileHealth(testProfile()), "fail"); fails != 0 {
		t.Fatalf("healthy profile reported %d failures", fails)
	}
}

// ECH is off in the test profile, so exactly one warning (the ECH line)
// is expected and nothing fails.
func TestCheckProfileHealthReportsECHOff(t *testing.T) {
	checks := CheckProfileHealth(testProfile())
	if warns := countStatus(checks, "warn"); warns != 1 {
		t.Fatalf("expected 1 warning (ECH off), got %d", warns)
	}
	enabled := testProfile()
	enabled.Modules.StealthFactory.ECHEnabled = true
	if warns := countStatus(CheckProfileHealth(enabled), "warn"); warns != 0 {
		t.Fatalf("expected 0 warnings with ECH on, got %d", warns)
	}
}

func TestProxyEnvSet(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	if proxyEnvSet() {
		t.Fatal("proxyEnvSet() true with no proxy vars set")
	}
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	if !proxyEnvSet() {
		t.Fatal("proxyEnvSet() false with HTTPS_PROXY set")
	}
}

func TestValidateProfileCatchesKnownBreakage(t *testing.T) {
	// Empty ws_path: the daemon skips the WebSocket upgrade entirely.
	p := testProfile()
	p.Modules.StealthFactory.DefaultWSPath = ""
	if countStatus(CheckProfileHealth(p), "fail") == 0 {
		t.Fatal("empty default_ws_path was not flagged as a failure")
	}

	// ws_path "/": the upgrade goes to the wrong path.
	p = testProfile()
	p.Modules.StealthFactory.DefaultWSPath = "/"
	if countStatus(CheckProfileHealth(p), "fail") == 0 {
		t.Fatal("default_ws_path \"/\" was not flagged as a failure")
	}

	// Fronting: Cloudflare 403s on SNI/Host mismatch.
	p = testProfile()
	p.Modules.StealthFactory.SNISPFDirection = config.SNISPFDirectionFronting
	if countStatus(CheckProfileHealth(p), "warn") == 0 {
		t.Fatal("fronting direction was not flagged as a warning")
	}

	// No worker host, no target: nothing to dial.
	p = testProfile()
	p.WorkerHost = ""
	p.PrimaryRoute.TargetIP = ""
	if countStatus(CheckProfileHealth(p), "fail") < 2 {
		t.Fatal("missing worker host / target were not both flagged")
	}
}

func TestCheckProfileAgreement(t *testing.T) {
	dir := t.TempDir()
	// Repo layout: <dir>/combat.profile and <dir>/configs/combat.profile.
	if err := os.MkdirAll(filepath.Join(dir, "configs"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := `{"worker_host":"w.example.workers.dev","modules":{"stealth_factory":{"snispf_direction":"legacy","default_ws_path":"/secret-knock-99"}},"primary_route":{"target_ip":"1.2.3.4","target_port":443,"clean_sni":"w.example.workers.dev"}}`
	bad := `{"worker_host":"w.example.workers.dev","modules":{"stealth_factory":{"snispf_direction":"fronting","default_ws_path":"/"}},"primary_route":{"target_ip":"1.2.3.4","target_port":443,"clean_sni":"w.example.workers.dev"}}`
	if err := os.WriteFile(filepath.Join(dir, "combat.profile"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "configs", "combat.profile")
	if err := os.WriteFile(profilePath, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := config.LoadCombatProfile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	warns := checkProfileAgreement(profilePath, profile)
	if countStatus(warns, "warn") < 2 {
		t.Fatalf("expected disagreement warnings, got %v", warns)
	}
}
