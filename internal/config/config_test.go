package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testProfileJSON = `{
  "version": "1.2-cornelius",
  "worker_host": "worker.test",
  "expected_ttl": 55,
  "operational_doctrine": {"telemetry_polling_ms": 3000, "max_acceptable_latency_ms": 800, "fallback_threshold_streak": 3},
  "modules": {
    "xdp_shield": {"mode": "adaptive", "expected_ttl": 55, "ttl_tolerance": 4, "rst_burst_threshold": 5},
    "stealth_factory": {"snispf_direction": "legacy", "default_spoof_sni": "cdn.test", "default_ws_path": "/secret-knock-99", "primary_mode": "tls_frag", "fallback_mode": "tls_micro_frag", "fragmentation_delay_ms": 2, "jitter_ms": 2, "allow_insecure_certs": false},
    "warm_pool": {"target_capacity": 3, "keepalive_interval_sec": 10}
  },
  "contingency_matrix": [],
  "primary_route": {"target_ip": "10.0.0.1", "clean_sni": "worker.test", "stealth_mode": "tls_frag"},
  "failover_routes": [{"target_ip": "10.0.0.2", "clean_sni": "worker.test", "stealth_mode": "tls_frag"}]
}`

func writeProfile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "combat.profile")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCombatProfileValid(t *testing.T) {
	p, err := LoadCombatProfile(writeProfile(t, testProfileJSON))
	if err != nil {
		t.Fatal(err)
	}
	if p.WorkerHost != "worker.test" || p.Version != "1.2-cornelius" {
		t.Fatalf("profile = %+v", p)
	}
	// Normalization fills the blanks the file left out.
	primary := p.PrimaryRoute
	if primary.TargetPort != 443 {
		t.Fatalf("port = %d, want 443", primary.TargetPort)
	}
	if primary.SpoofSNI != "cdn.test" || primary.WSPath != "/secret-knock-99" {
		t.Fatalf("spoof/ws = %q/%q, want cdn.test//secret-knock-99", primary.SpoofSNI, primary.WSPath)
	}
	if primary.SNISPFDirection != SNISPFDirectionLegacy {
		t.Fatalf("direction = %q, want legacy", primary.SNISPFDirection)
	}
	if fo := p.FailoverRoutes[0]; fo.TargetPort != 443 || fo.SpoofSNI != "cdn.test" {
		t.Fatalf("failover not normalized: %+v", fo)
	}
}

func TestLoadCombatProfileMissingFile(t *testing.T) {
	if _, err := LoadCombatProfile(filepath.Join(t.TempDir(), "nope.profile")); err == nil {
		t.Fatal("missing file must fail")
	} else if !strings.Contains(err.Error(), "read combat profile") {
		t.Fatalf("error = %v, want a read error", err)
	}
}

func TestLoadCombatProfileRejectsTrailingComma(t *testing.T) {
	// The round-8 bug: a trailing comma made the shipped profile
	// unparseable JSON. The loader must fail loudly, never start on a
	// half-loaded profile.
	broken := strings.Replace(testProfileJSON, `"worker_host": "worker.test",`, `"worker_host": "worker.test",,`, 1)
	if _, err := LoadCombatProfile(writeProfile(t, broken)); err == nil {
		t.Fatal("malformed JSON must fail")
	} else if !strings.Contains(err.Error(), "unmarshal combat profile") {
		t.Fatalf("error = %v, want an unmarshal error", err)
	}
}

func TestLoadCombatProfileRejectsNonObject(t *testing.T) {
	if _, err := LoadCombatProfile(writeProfile(t, `[1, 2, 3]`)); err == nil {
		t.Fatal("a JSON array is not a profile")
	}
}

func TestLoadCombatProfileECHFields(t *testing.T) {
	withECH := strings.Replace(testProfileJSON,
		`"allow_insecure_certs": false`,
		`"allow_insecure_certs": false, "ech_enabled": true, "ech_required": true, "ech_config_b64": "cGFzdGVk"`, 1)
	p, err := LoadCombatProfile(writeProfile(t, withECH))
	if err != nil {
		t.Fatal(err)
	}
	sf := p.Modules.StealthFactory
	if !sf.ECHEnabled || !sf.ECHRequired || sf.ECHConfigB64 != "cGFzdGVk" {
		t.Fatalf("ECH fields lost: %+v", sf)
	}
}

func TestShippedProfilesLoad(t *testing.T) {
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
			p, err := LoadCombatProfile(abs)
			if err != nil {
				t.Fatalf("load %s: %v", abs, err)
			}
			if p.PrimaryRoute.TargetPort != 443 {
				t.Fatalf("primary port = %d, want 443", p.PrimaryRoute.TargetPort)
			}
		})
	}
}

func TestNormalizeRoute(t *testing.T) {
	// Nil is a no-op, never a panic (the loader calls it on pointers
	// that are always non-nil, but callers must not fear a nil).
	NormalizeRoute(nil, "", "", "")

	cases := []struct {
		name      string
		route     RouteCandidate
		defDir    string
		defSpoof  string
		defWS     string
		wantDir   string
		wantSpoof string
		wantWS    string
		wantPort  uint16
	}{
		{
			name:    "port default and legacy when spoof equals clean",
			route:   RouteCandidate{TargetIP: "10.0.0.1", CleanSNI: "worker.test", SpoofSNI: "worker.test"},
			wantDir: SNISPFDirectionLegacy, wantSpoof: "worker.test", wantPort: 443,
		},
		{
			name:    "distinct spoof infers fronting",
			route:   RouteCandidate{TargetIP: "10.0.0.1", CleanSNI: "worker.test", SpoofSNI: "cdn.test"},
			wantDir: SNISPFDirectionFronting, wantSpoof: "cdn.test", wantPort: 443,
		},
		{
			name:    "explicit direction wins over inference",
			route:   RouteCandidate{TargetIP: "10.0.0.1", CleanSNI: "worker.test", SpoofSNI: "cdn.test", SNISPFDirection: SNISPFDirectionLegacy},
			wantDir: SNISPFDirectionLegacy, wantSpoof: "cdn.test", wantPort: 443,
		},
		{
			name:   "defaults fill blanks",
			route:  RouteCandidate{TargetIP: "10.0.0.1", CleanSNI: "worker.test"},
			defDir: "fronting", defSpoof: "cdn.test", defWS: "/secret-knock-99",
			wantDir: "fronting", wantSpoof: "cdn.test", wantWS: "/secret-knock-99", wantPort: 443,
		},
		{
			name:   "explicit values beat defaults",
			route:  RouteCandidate{TargetIP: "10.0.0.1", TargetPort: 8443, CleanSNI: "worker.test", SpoofSNI: "x.test", WSPath: "/other", SNISPFDirection: SNISPFDirectionLegacy},
			defDir: "fronting", defSpoof: "cdn.test", defWS: "/secret-knock-99",
			wantDir: SNISPFDirectionLegacy, wantSpoof: "x.test", wantWS: "/other", wantPort: 8443,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			NormalizeRoute(&tc.route, tc.defDir, tc.defSpoof, tc.defWS)
			if tc.route.SNISPFDirection != tc.wantDir {
				t.Errorf("direction = %q, want %q", tc.route.SNISPFDirection, tc.wantDir)
			}
			if tc.route.SpoofSNI != tc.wantSpoof {
				t.Errorf("spoof = %q, want %q", tc.route.SpoofSNI, tc.wantSpoof)
			}
			if tc.route.WSPath != tc.wantWS {
				t.Errorf("ws_path = %q, want %q", tc.route.WSPath, tc.wantWS)
			}
			if tc.route.TargetPort != tc.wantPort {
				t.Errorf("port = %d, want %d", tc.route.TargetPort, tc.wantPort)
			}
		})
	}
}

func TestDefaultCombatProfile(t *testing.T) {
	primary := RouteCandidate{TargetIP: "10.0.0.1", CleanSNI: "worker.test", StealthMode: "tls_frag", ExpectedTTL: 55}
	failovers := []RouteCandidate{{TargetIP: "10.0.0.2", CleanSNI: "worker.test", StealthMode: "tls_frag"}}
	p := DefaultCombatProfile("worker.test", primary, failovers)

	if p.Version != "1.2-cornelius" || p.WorkerHost != "worker.test" {
		t.Fatalf("profile = %+v", p)
	}
	if d := p.OperationalDoctrine; d.TelemetryPollingMs != 3000 || d.MaxAcceptableLatencyMs != 800 || d.FallbackThreshold != 3 {
		t.Fatalf("doctrine = %+v", d)
	}
	if p.Modules.WarmPool.TargetCapacity != 3 || p.Modules.WarmPool.KeepaliveIntervalSec != 10 {
		t.Fatalf("warm pool = %+v", p.Modules.WarmPool)
	}
	if p.Modules.XDPShield.Mode != "adaptive" || p.Modules.XDPShield.TTLTolerance != 4 {
		t.Fatalf("XDP shield = %+v (want adaptive/tol 4)", p.Modules.XDPShield)
	}
	if p.Modules.StealthFactory.PrimaryMode != "tls_frag" || p.Modules.StealthFactory.FallbackMode != "tls_micro_frag" {
		t.Fatalf("stealth factory = %+v", p.Modules.StealthFactory)
	}
	if len(p.ContingencyMatrix) != 5 {
		t.Fatalf("contingency matrix = %d rules, want 5", len(p.ContingencyMatrix))
	}
	// Failovers inherit the primary's direction/spoof/ws path.
	if fo := p.FailoverRoutes[0]; fo.SNISPFDirection != p.PrimaryRoute.SNISPFDirection {
		t.Fatalf("failover direction = %q, want %q", fo.SNISPFDirection, p.PrimaryRoute.SNISPFDirection)
	}
	if p.PrimaryRoute.TargetPort != 443 {
		t.Fatalf("primary port = %d, want 443", p.PrimaryRoute.TargetPort)
	}
}

func TestDefaultCombatProfileLockdownWhenDPIActive(t *testing.T) {
	primary := RouteCandidate{TargetIP: "10.0.0.1", CleanSNI: "worker.test", StealthMode: "tls_frag", ExpectedTTL: 55, DPIActive: true}
	p := DefaultCombatProfile("worker.test", primary, nil)
	if p.Modules.XDPShield.Mode != "lockdown" || p.Modules.XDPShield.TTLTolerance != 2 {
		t.Fatalf("XDP shield = %+v (want lockdown/tol 2)", p.Modules.XDPShield)
	}
}
