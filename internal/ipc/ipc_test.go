package ipc

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"cornelius/internal/config"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/proxy/pool"
	"cornelius/internal/telemetry"
)

// doIPC sends one JSON command through handleIPCConn over a net.Pipe and
// returns the decoded response. It mirrors how the TUI client talks to
// the control plane, minus the socket file itself (StartControlPlane
// binds the fixed /run/cornelius/ipc.sock path, which needs root and is
// not exercised here).
func doIPC(t *testing.T, p *pool.WarmPool, cmd string) IPCResponse {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go handleIPCConn(server, p)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte(cmd)); err != nil {
		t.Fatalf("write command: %v", err)
	}
	var resp IPCResponse
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func testIPCPool() *pool.WarmPool {
	prof := &config.CombatProfile{
		WorkerHost: "worker.test",
		Modules: config.ModulesConfig{
			StealthFactory: config.StealthFactoryConfig{
				SNISPFDirection: config.SNISPFDirectionLegacy,
				DefaultWSPath:   "/secret-knock-99",
			},
			WarmPool: config.WarmPoolConfig{TargetCapacity: 3},
		},
		PrimaryRoute: config.RouteCandidate{
			TargetIP:    "10.0.0.1",
			TargetPort:  443,
			CleanSNI:    "worker.test",
			StealthMode: factory.ModeTLSFrag,
			WSPath:      "/secret-knock-99",
		},
	}
	return pool.NewWarmPool(prof)
}

func TestIPCNilPool(t *testing.T) {
	resp := doIPC(t, nil, `{"action":"status"}`)
	if resp.Status != "error" || resp.Message != "warm pool unavailable" {
		t.Fatalf("resp = %+v, want warm-pool-unavailable error", resp)
	}
}

func TestIPCMalformedJSON(t *testing.T) {
	resp := doIPC(t, testIPCPool(), `{not json`)
	if resp.Status != "error" {
		t.Fatalf("resp = %+v, want error", resp)
	}
}

func TestIPCUnknownAction(t *testing.T) {
	resp := doIPC(t, testIPCPool(), `{"action":"teleport"}`)
	if resp.Status != "error" || !strings.Contains(resp.Message, "unknown IPC action: teleport") {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestIPCInjectRouteValidation(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string // substring of the error, "" means ok
	}{
		{"empty IP", `{"action":"inject_route","route":{"target_ip":""}}`, "valid IP address"},
		{"invalid IP", `{"action":"inject_route","route":{"target_ip":"999.1.1.1"}}`, "valid IP address"},
		{"unknown stealth mode", `{"action":"inject_route","route":{"target_ip":"10.0.0.9","stealth_mode":"invisible"}}`, "unknown stealth_mode"},
		{"bad direction", `{"action":"inject_route","route":{"target_ip":"10.0.0.9","snispf_direction":"sideways"}}`, "legacy' or 'fronting"},
		{"valid route", `{"action":"inject_route","route":{"target_ip":"10.0.0.9","clean_sni":"worker.test","stealth_mode":"tls_micro_frag"}}`, ""},
		{"valid route with TTL", `{"action":"inject_route","route":{"target_ip":"10.0.0.9","clean_sni":"worker.test"},"expected_ttl":55}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testIPCPool()
			resp := doIPC(t, p, tc.cmd)
			if tc.want == "" {
				if resp.Status != "ok" {
					t.Fatalf("resp = %+v, want ok", resp)
				}
				return
			}
			if resp.Status != "error" || !strings.Contains(resp.Message, tc.want) {
				t.Fatalf("resp = %+v, want error containing %q", resp, tc.want)
			}
		})
	}
}

func TestIPCInjectRouteUpdatesPool(t *testing.T) {
	p := testIPCPool()
	resp := doIPC(t, p, `{"action":"inject_route","route":{"target_ip":"10.0.0.9","clean_sni":"worker.test","stealth_mode":"tls_micro_frag"}}`)
	if resp.Status != "ok" || resp.Message != "route injected" {
		t.Fatalf("resp = %+v", resp)
	}
	if got := p.ActiveRoute().TargetIP; got != "10.0.0.9" {
		t.Fatalf("active route = %s, want 10.0.0.9", got)
	}
	// The old route is kept as a failover, so the daemon can come back.
	if routes := p.AllRoutes(); len(routes) != 2 || routes[1].TargetIP != "10.0.0.1" {
		t.Fatalf("routes = %+v, want old route as failover", routes)
	}
}

func TestIPCSetSNISPF(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{"bad direction", `{"action":"set_snispf","snispf_direction":"sideways"}`, "legacy' or 'fronting"},
		{"fronting without spoof", `{"action":"set_snispf","snispf_direction":"fronting"}`, "spoof_sni is required"},
		{"fronting with spoof", `{"action":"set_snispf","snispf_direction":"fronting","spoof_sni":"cdn.test"}`, ""},
		{"legacy", `{"action":"set_snispf","snispf_direction":"legacy"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testIPCPool()
			resp := doIPC(t, p, tc.cmd)
			if tc.want == "" {
				if resp.Status != "ok" {
					t.Fatalf("resp = %+v, want ok", resp)
				}
				return
			}
			if resp.Status != "error" || !strings.Contains(resp.Message, tc.want) {
				t.Fatalf("resp = %+v, want error containing %q", resp, tc.want)
			}
		})
	}
}

func TestIPCSetSNISPFUpdatesPool(t *testing.T) {
	p := testIPCPool()
	resp := doIPC(t, p, `{"action":"set_snispf","snispf_direction":"fronting","spoof_sni":"cdn.test"}`)
	if resp.Status != "ok" {
		t.Fatalf("resp = %+v", resp)
	}
	active := p.ActiveRoute()
	if active.SNISPFDirection != config.SNISPFDirectionFronting || active.SpoofSNI != "cdn.test" {
		t.Fatalf("active = %+v", active)
	}
}

func TestIPCEscalateStealth(t *testing.T) {
	p := testIPCPool()
	resp := doIPC(t, p, `{"action":"escalate_stealth","stealth_mode":"tls_micro_frag","frag_delay_ms":3,"jitter_ms":3}`)
	if resp.Status != "ok" {
		t.Fatalf("resp = %+v", resp)
	}
	if got := p.ActiveRoute().StealthMode; got != factory.ModeTLSMicroFrag {
		t.Fatalf("mode = %q, want tls_micro_frag", got)
	}
}

func TestIPCLockdownXDP(t *testing.T) {
	p := testIPCPool()
	resp := doIPC(t, p, `{"action":"lockdown_xdp","expected_ttl":55,"ttl_tolerance":4,"lockdown":true}`)
	if resp.Status != "ok" || resp.Message != "XDP configuration updated" {
		t.Fatalf("resp = %+v", resp)
	}
	if telemetry.CurrentLockdownMode.Load() != 1 {
		t.Fatal("lockdown_xdp must set the lockdown flag in telemetry")
	}
	telemetry.CurrentLockdownMode.Store(0)
}

func TestIPCStatus(t *testing.T) {
	p := testIPCPool()
	resp := doIPC(t, p, `{"action":"status"}`)
	if resp.Status != "ok" || resp.Snapshot == nil {
		t.Fatalf("resp = %+v, want ok with a snapshot", resp)
	}
	snap := resp.Snapshot
	if snap.ActiveRouteIP != "10.0.0.1" {
		t.Fatalf("active_route_ip = %q", snap.ActiveRouteIP)
	}
	if snap.PoolCapacity != 3 {
		t.Fatalf("pool_capacity = %d, want 3", snap.PoolCapacity)
	}
	if snap.XDPLockdown {
		t.Fatal("lockdown must be off")
	}
	if snap.SNISPFDirection != config.SNISPFDirectionLegacy {
		t.Fatalf("direction = %q", snap.SNISPFDirection)
	}
}

func TestIPCDoctorWithAndWithoutProfile(t *testing.T) {
	resp := doIPC(t, testIPCPool(), `{"action":"doctor"}`)
	if resp.Status != "ok" || len(resp.Checks) == 0 {
		t.Fatalf("resp = %+v, want ok with checks", resp)
	}
	found := false
	for _, c := range resp.Checks {
		if c.Name == "worker host is set" && c.Status == "ok" {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor checks = %+v, want the worker-host check ok", resp.Checks)
	}

	// A pool built without a profile reports the missing profile instead
	// of crashing: the daemon starts empty and waits for IPC injection.
	resp = doIPC(t, pool.NewWarmPool(nil), `{"action":"doctor"}`)
	if resp.Status != "ok" || len(resp.Checks) == 0 {
		t.Fatalf("resp = %+v, want ok with checks", resp)
	}
	if resp.Checks[0].Status != "fail" || !strings.Contains(resp.Checks[0].Detail, "no profile to check") {
		t.Fatalf("checks = %+v, want the missing-profile fail first", resp.Checks)
	}
}

func TestIPCScanCIDRValidation(t *testing.T) {
	cases := []struct {
		name string
		pool *pool.WarmPool
		cmd  string
		want string
	}{
		{"empty cidr", testIPCPool(), `{"action":"scan_cidr","cidr":""}`, "cidr or target IP list is required"},
		{"invalid cidr", testIPCPool(), `{"action":"scan_cidr","cidr":"10.0.0.0/33"}`, ""}, // any error
		{"no worker SNI", pool.NewWarmPool(&config.CombatProfile{
			PrimaryRoute: config.RouteCandidate{TargetIP: "10.0.0.1"},
		}), `{"action":"scan_cidr","cidr":"10.0.0.0/30"}`, "active worker SNI required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doIPC(t, tc.pool, tc.cmd)
			if resp.Status != "error" {
				t.Fatalf("resp = %+v, want error", resp)
			}
			if tc.want != "" && !strings.Contains(resp.Message, tc.want) {
				t.Fatalf("resp = %+v, want error containing %q", resp, tc.want)
			}
		})
	}
}

func TestIPCScanCIDRAlreadyRunning(t *testing.T) {
	busy := true
	telemetry.SetBackgroundBusy(nil, &busy)
	defer func() {
		notBusy := false
		telemetry.SetBackgroundBusy(nil, &notBusy)
	}()
	resp := doIPC(t, testIPCPool(), `{"action":"scan_cidr","cidr":"10.0.0.0/30"}`)
	if resp.Status != "ok" || resp.Message != "scanner already running" {
		t.Fatalf("resp = %+v, want scanner-already-running", resp)
	}
}

func TestIPCEcholocateValidation(t *testing.T) {
	// No active target: nothing to probe.
	p := pool.NewWarmPool(&config.CombatProfile{})
	resp := doIPC(t, p, `{"action":"echolocate"}`)
	if resp.Status != "error" || !strings.Contains(resp.Message, "no active target IP") {
		t.Fatalf("resp = %+v, want no-active-target error", resp)
	}

	// Already running: the second request is a no-op, not a second sweep.
	busy := true
	telemetry.SetBackgroundBusy(&busy, nil)
	defer func() {
		notBusy := false
		telemetry.SetBackgroundBusy(&notBusy, nil)
	}()
	resp = doIPC(t, testIPCPool(), `{"action":"echolocate"}`)
	if resp.Status != "ok" || resp.Message != "echolocation already running" {
		t.Fatalf("resp = %+v, want echolocation-already-running", resp)
	}
}
