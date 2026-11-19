package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cornelius/internal/config"
)

// TestCompileCombatProfilePreservesECH proves a rescan does not silently
// turn ECH off: the ranked routes carry no ECH settings, so the compiled
// profile must keep ech_enabled / ech_required / ech_config_b64 (and the
// WebSocket path) from the profile it overwrites. The report uses a
// loopback target so the echolocation dials fail fast (connection
// refused) instead of touching the network.
func TestCompileCombatProfilePreservesECH(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "combat.profile")

	// Existing profile with ECH on (strict, pasted config) and a WS path.
	existing := config.DefaultCombatProfile("worker.example",
		config.RouteCandidate{
			TargetIP: "203.0.113.1", TargetPort: 443, CleanSNI: "worker.example",
			StealthMode: "tls_frag", Fingerprint: "chrome_auto",
		}, nil)
	existing.Modules.StealthFactory.DefaultWSPath = "/secret-knock-99"
	existing.Modules.StealthFactory.ECHEnabled = true
	existing.Modules.StealthFactory.ECHRequired = true
	existing.Modules.StealthFactory.ECHConfigB64 = "cGFzdGVk"
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	report := &IntelligenceReport{
		Timestamp:  time.Now(),
		WorkerHost: "worker.example",
		CleanEdges: []ProbeResult{{
			IP: "127.0.0.1", Port: 443, Success: true,
			Mode: ModeTLSFrag, Fingerprint: "chrome_auto",
			Latency: 10 * time.Millisecond,
		}},
	}

	compiled, err := CompileCombatProfile(report, path)
	if err != nil {
		t.Fatalf("CompileCombatProfile() error: %v", err)
	}
	if compiled.PrimaryRoute.TargetIP != "127.0.0.1" {
		t.Fatalf("primary route = %s, want 127.0.0.1 (the rescan winner)", compiled.PrimaryRoute.TargetIP)
	}
	sf := compiled.Modules.StealthFactory
	if !sf.ECHEnabled || !sf.ECHRequired || sf.ECHConfigB64 != "cGFzdGVk" {
		t.Fatalf("ECH settings lost in rescan: enabled=%v required=%v config_b64=%q",
			sf.ECHEnabled, sf.ECHRequired, sf.ECHConfigB64)
	}
	if sf.DefaultWSPath != "/secret-knock-99" {
		t.Fatalf("WS path lost in rescan: %q", sf.DefaultWSPath)
	}

	// And the file on disk — the one the daemon will actually load —
	// must carry the same settings.
	reloaded, err := config.LoadCombatProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	rsf := reloaded.Modules.StealthFactory
	if !rsf.ECHEnabled || !rsf.ECHRequired || rsf.ECHConfigB64 != "cGFzdGVk" {
		t.Fatalf("ECH settings lost on disk: %+v", rsf)
	}
}

// TestCompileCombatProfilePreservesUserSettings proves a rescan keeps the
// user's non-route tuning (warm pool, timing, fallback mode, doctrine, XDP
// shield burst threshold, contingency matrix) instead of resetting it to the
// defaults, while the scan-derived XDP Mode/TTL fields follow the rescan.
func TestCompileCombatProfilePreservesUserSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "combat.profile")

	existing := config.DefaultCombatProfile("worker.example",
		config.RouteCandidate{
			TargetIP: "203.0.113.1", TargetPort: 443, CleanSNI: "worker.example",
			StealthMode: "tls_frag", Fingerprint: "chrome_auto",
		}, nil)
	existing.OperationalDoctrine = config.OperationalDoctrine{
		TelemetryPollingMs: 1234, MaxAcceptableLatencyMs: 4321, FallbackThreshold: 9,
	}
	existing.Modules.WarmPool = config.WarmPoolConfig{TargetCapacity: 17, KeepaliveIntervalSec: 41}
	existing.Modules.XDPShield = config.XDPShieldConfig{
		Mode: "adaptive", ExpectedTTL: 77, TTLTolerance: 7, RSTBurstThreshold: 23,
	}
	existing.Modules.StealthFactory.FallbackMode = "custom_fallback"
	existing.Modules.StealthFactory.FragmentationDelayMs = 11
	existing.Modules.StealthFactory.JitterMs = 13
	existing.ContingencyMatrix = []config.ContingencyRule{{Condition: "custom_cond", Action: "custom_action"}}
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	report := &IntelligenceReport{
		Timestamp:  time.Now(),
		WorkerHost: "worker.example",
		CleanEdges: []ProbeResult{{
			IP: "127.0.0.1", Port: 443, Success: true,
			// micro-frag marks the route DPIActive (see the route builder).
			Mode: ModeTLSMicroFrag, Fingerprint: "chrome_auto",
			ExpectedTTL: 55,
			Latency:     10 * time.Millisecond,
		}},
	}
	compiled, err := CompileCombatProfile(report, path)
	if err != nil {
		t.Fatalf("CompileCombatProfile() error: %v", err)
	}
	if compiled.PrimaryRoute.TargetIP != "127.0.0.1" {
		t.Fatalf("primary route = %s, want 127.0.0.1", compiled.PrimaryRoute.TargetIP)
	}
	if !compiled.PrimaryRoute.DPIActive {
		t.Fatal("test setup: primary route should be DPIActive")
	}

	check := func(name string, p *config.CombatProfile) {
		t.Helper()
		sf := p.Modules.StealthFactory
		if p.OperationalDoctrine != existing.OperationalDoctrine {
			t.Errorf("%s: doctrine = %+v", name, p.OperationalDoctrine)
		}
		if p.Modules.WarmPool != existing.Modules.WarmPool {
			t.Errorf("%s: warm pool = %+v", name, p.Modules.WarmPool)
		}
		x := p.Modules.XDPShield
		// Scan-derived fields follow the fresh DPI-active scan; only the
		// burst threshold is the user's.
		if x.Mode != "lockdown" || x.TTLTolerance != 2 || x.ExpectedTTL != 55 || x.RSTBurstThreshold != 23 {
			t.Errorf("%s: xdp shield = %+v, want lockdown/tol 2/ttl 55/burst 23", name, x)
		}
		if sf.FallbackMode != "custom_fallback" || sf.FragmentationDelayMs != 11 || sf.JitterMs != 13 {
			t.Errorf("%s: stealth factory = %+v", name, sf)
		}
		if len(p.ContingencyMatrix) != 1 || p.ContingencyMatrix[0] != existing.ContingencyMatrix[0] {
			t.Errorf("%s: contingency matrix = %+v", name, p.ContingencyMatrix)
		}
	}
	check("compiled", compiled)

	reloaded, err := config.LoadCombatProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	check("on disk", reloaded)
}
