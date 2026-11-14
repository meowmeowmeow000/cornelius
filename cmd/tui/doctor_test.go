package main

import (
	"strings"
	"testing"
)

func TestRenderDoctorLinesAllGreen(t *testing.T) {
	checks := []HealthCheck{
		{Name: "worker host is set", Status: "ok", Detail: "bold-heart-a6e2.nedaymarg.workers.dev"},
		{Name: "ECH encrypts the SNI", Status: "warn", Detail: "off — the SNI is visible; randomized fragmentation is the active defence"},
	}
	lines := renderDoctorLines(checks, VitalSnapshot{WarmPipes: 3, ActiveStreams: 2}, 100)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "[ok] worker host is set") {
		t.Fatalf("missing ok line: %q", joined)
	}
	if !strings.Contains(joined, "[!!] ECH encrypts the SNI") {
		t.Fatalf("missing warn line: %q", joined)
	}
	if !strings.Contains(joined, "1 warning(s)") {
		t.Fatalf("missing warning summary: %q", joined)
	}
	if !strings.Contains(joined, "3 warm pipe(s)") {
		t.Fatalf("missing live line: %q", joined)
	}
}

func TestRenderDoctorLinesFailing(t *testing.T) {
	checks := []HealthCheck{
		{Name: "WebSocket path is configured", Status: "fail", Detail: "default_ws_path is empty"},
	}
	lines := renderDoctorLines(checks, VitalSnapshot{}, 100)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "[xx] WebSocket path is configured") {
		t.Fatalf("missing fail line: %q", joined)
	}
	if !strings.Contains(joined, "1 check(s) failing") {
		t.Fatalf("missing failing summary: %q", joined)
	}
}

func TestRenderDoctorLinesEmpty(t *testing.T) {
	lines := renderDoctorLines(nil, VitalSnapshot{}, 100)
	if len(lines) != 1 || !strings.Contains(lines[0], "No health data yet") {
		t.Fatalf("empty checks should explain themselves, got %v", lines)
	}
}

func TestRouteTableShowsWSVerified(t *testing.T) {
	m := initialModel(defaultSockPath)
	m.snap.FailoverRoutes = []RouteCandidate{
		{TargetIP: "104.18.0.181", SNISPFDirection: "legacy", StealthMode: "tls_frag", TLSHandshakeMs: 120, WSVerified: true, Score: 90},
		{TargetIP: "104.18.2.161", SNISPFDirection: "legacy", StealthMode: "tls_frag", TLSHandshakeMs: 200, WSVerified: false, Score: 70},
	}
	m.snap.ActiveRouteIP = "104.18.0.181"
	lines := m.renderRouteTable(100, themes[0])
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "✓") {
		t.Fatalf("verified route should show a check mark: %q", joined)
	}
	if !strings.Contains(joined, "–") {
		t.Fatalf("unverified route should show a dash: %q", joined)
	}
	if !strings.Contains(joined, "WS") {
		t.Fatalf("header should name the WS column: %q", joined)
	}
}
