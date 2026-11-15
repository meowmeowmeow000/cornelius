package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cornelius/internal/bpf"
	"cornelius/internal/config"
	"cornelius/internal/proxy/factory"
)

// Doctor checks are Cornelius telling the truth about itself in plain words.
// `cornelius doctor` answers the question "why doesn't it work?" without
// making the user read logs or guess: it validates the profile, dials the
// real tunnel, and pushes one real stream through it end to end.

// HealthCheck is one plain-language verdict about the daemon's health.
// It is shared by the `cornelius doctor` CLI output and the TUI doctor
// panel (via IPC), so both tell the same truth in the same words.
type HealthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "ok", "warn" or "fail"
	Detail string `json:"detail,omitempty"`
}

func (c HealthCheck) String() string {
	mark := "[ok]"
	switch c.Status {
	case "warn":
		mark = "[!!]"
	case "fail":
		mark = "[xx]"
	}
	if c.Detail == "" {
		return fmt.Sprintf("%s %s", mark, c.Name)
	}
	return fmt.Sprintf("%s %s — %s", mark, c.Name, c.Detail)
}

// CheckProfileHealth checks the loaded profile for the misconfigurations
// that have actually broken Cornelius before. Pure function, unit-tested.
func CheckProfileHealth(p *config.CombatProfile) []HealthCheck {
	var out []HealthCheck
	sf := p.Modules.StealthFactory

	if p.WorkerHost == "" {
		out = append(out, HealthCheck{"worker host is set", "fail", "worker_host is empty; the daemon has nowhere to dial"})
	} else {
		out = append(out, HealthCheck{"worker host is set", "ok", p.WorkerHost})
	}

	switch {
	case sf.DefaultWSPath == "":
		out = append(out, HealthCheck{"WebSocket path is configured", "fail", "default_ws_path is empty, so the daemon skips the WebSocket upgrade and sends raw SMUX at Cloudflare's HTTPS port (EOF)"})
	case sf.DefaultWSPath == "/":
		out = append(out, HealthCheck{"WebSocket path is configured", "fail", "default_ws_path is \"/\" — the secret path is missing, the upgrade goes to the wrong path"})
	default:
		out = append(out, HealthCheck{"WebSocket path is configured", "ok", sf.DefaultWSPath})
	}

	switch sf.SNISPFDirection {
	case config.SNISPFDirectionLegacy:
		out = append(out, HealthCheck{"SNI direction is legacy", "ok", "outer SNI matches the Worker host"})
	case config.SNISPFDirectionFronting:
		out = append(out, HealthCheck{"SNI direction is legacy", "warn", "direction is fronting — Cloudflare blocks SNI/Host mismatches with 403"})
	case "":
		out = append(out, HealthCheck{"SNI direction is legacy", "warn", "direction is unset; routes fall back to legacy only when no spoof SNI is set"})
	default:
		out = append(out, HealthCheck{"SNI direction is legacy", "fail", "unknown direction " + sf.SNISPFDirection})
	}

	switch {
	case sf.ECHEnabled && sf.ECHRequired:
		out = append(out, HealthCheck{"ECH encrypts the SNI", "ok", "strict mode — the tunnel stays down rather than dial without ECH"})
	case sf.ECHEnabled:
		out = append(out, HealthCheck{"ECH encrypts the SNI", "ok", "the ClientHello hides the Worker hostname"})
	default:
		out = append(out, HealthCheck{"ECH encrypts the SNI", "warn", "off — the SNI is visible; randomized fragmentation is the active defence"})
	}

	if sf.ECHRequired && !sf.ECHEnabled {
		out = append(out, HealthCheck{"ECH strict mode is consistent", "fail", "ech_required is set but ech_enabled is off — strict mode needs ECH on"})
	}
	if sf.ECHEnabled && sf.ECHRequired && sf.ECHConfigB64 == "" {
		out = append(out, HealthCheck{"strict ECH has a config source", "warn", "no pasted config — the DoH fetch runs at dial time, and if DoH is blocked the tunnel stays down"})
	}
	if sf.ECHConfigB64 != "" {
		if _, err := factory.DecodeECHConfigB64(sf.ECHConfigB64); err != nil {
			out = append(out, HealthCheck{"pasted ECH config is valid", "fail", err.Error()})
		} else {
			out = append(out, HealthCheck{"pasted ECH config is valid", "ok", "the profile carries its own ECH config; no DoH fetch needed"})
		}
	}

	route := p.PrimaryRoute
	if route.TargetIP == "" {
		out = append(out, HealthCheck{"primary route has a target", "fail", "no target_ip — nothing to dial"})
	} else {
		out = append(out, HealthCheck{"primary route has a target", "ok", fmt.Sprintf("%s:%d (%s)", route.TargetIP, route.TargetPort, route.StealthMode)})
	}
	if route.WSPath != "" && sf.DefaultWSPath != "" && route.WSPath != sf.DefaultWSPath {
		out = append(out, HealthCheck{"route and profile agree on the WebSocket path", "warn", fmt.Sprintf("route says %q, profile default says %q", route.WSPath, sf.DefaultWSPath)})
	}
	if route.CleanSNI == "" {
		out = append(out, HealthCheck{"route knows the Worker host", "fail", "clean_sni is empty"})
	}
	return out
}

// checkProfileAgreement warns when the two profile files in the repo
// disagree, so the user cannot run one by accident and get the other's bugs.
// It looks for combat.profile next to the profile's directory.
func checkProfileAgreement(profilePath string, p *config.CombatProfile) []HealthCheck {
	sibling := filepath.Clean(filepath.Join(filepath.Dir(profilePath), "..", "combat.profile"))
	if filepath.Clean(profilePath) == sibling {
		return nil
	}
	other, err := config.LoadCombatProfile(sibling)
	if err != nil {
		return nil // no second profile to disagree with
	}
	var out []HealthCheck
	a, b := p.Modules.StealthFactory, other.Modules.StealthFactory
	if a.SNISPFDirection != b.SNISPFDirection {
		out = append(out, HealthCheck{"profiles agree on SNI direction", "warn", fmt.Sprintf("%s says %q, %s says %q", profilePath, a.SNISPFDirection, sibling, b.SNISPFDirection)})
	}
	if a.DefaultWSPath != b.DefaultWSPath {
		out = append(out, HealthCheck{"profiles agree on the WebSocket path", "warn", fmt.Sprintf("%s says %q, %s says %q", profilePath, a.DefaultWSPath, sibling, b.DefaultWSPath)})
	}
	return out
}

// checkWorkerDirectly dials the Worker by hostname (normal DNS) and asks for
// the WebSocket upgrade, bypassing the profile's edge IP. It distinguishes
// "the Worker is dead" from "this edge IP is stale or blocked from here".
func checkWorkerDirectly(ctx context.Context, workerHost, wsPath string) HealthCheck {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(workerHost, "443"), &tls.Config{
		ServerName: workerHost,
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		return HealthCheck{"Worker answers directly (by hostname)", "fail", "TLS to " + workerHost + " failed: " + err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var keyBytes [16]byte
	_, _ = rand.Read(keyBytes[:])
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		wsPath, workerHost, base64.StdEncoding.EncodeToString(keyBytes[:]))
	if _, err := conn.Write([]byte(req)); err != nil {
		return HealthCheck{"Worker answers directly (by hostname)", "fail", "upgrade request failed: " + err.Error()}
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return HealthCheck{"Worker answers directly (by hostname)", "fail", "no response to the upgrade: " + err.Error()}
	}
	if strings.Contains(status, "101") {
		return HealthCheck{"Worker answers directly (by hostname)", "ok", "WebSocket upgrade at " + wsPath + " returned 101"}
	}
	return HealthCheck{"Worker answers directly (by hostname)", "fail", "upgrade returned: " + strings.TrimSpace(status)}
}

// proxyEnvSet reports whether this machine routes traffic through a proxy.
// The daemon dials edge IPs directly, so on a proxied machine the live
// tunnel test cannot be trusted: the proxy answers the TCP dial itself and
// the TLS handshake fails with a confusing error. Never print the proxy
// address — it can contain credentials.
func proxyEnvSet() bool {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// RunDoctor runs every check, prints plain-language results, and returns a
// process exit code: 0 when everything is healthy, 1 when anything failed.
// Warnings do not fail the run — they are things to fix before they bite.
func RunDoctor(ctx context.Context, profilePath, iface string) int {
	printCheck := func(c HealthCheck) { fmt.Println(c.String()) }

	profile, err := config.LoadCombatProfile(profilePath)
	if err != nil {
		printCheck(HealthCheck{"profile loads", "fail", err.Error()})
		fmt.Println("\nDoctor: FAILED — fix the profile and run again.")
		return 1
	}
	printCheck(HealthCheck{"profile loads", "ok", profilePath})

	failed := false
	for _, c := range CheckProfileHealth(profile) {
		printCheck(c)
		if c.Status == "fail" {
			failed = true
		}
	}
	for _, c := range checkProfileAgreement(profilePath, profile) {
		printCheck(c)
	}
	if failed {
		fmt.Println("\nDoctor: FAILED — the profile is misconfigured, so the tunnel was not tested.")
		return 1
	}

	// ECH config check: when ECH is on, the Worker host must publish a
	// config for the dialer to fetch, or the profile must carry a pasted
	// one. This runs even on proxied machines — the DoH fetch goes
	// through the proxy like any other HTTPS request.
	sf := profile.Modules.StealthFactory
	if sf.ECHEnabled {
		if sf.ECHConfigB64 != "" {
			// Pasted config: already validated by CheckProfileHealth
			// above (doctor stops before this point on any failure),
			// so report the source instead of fetching.
			list, _ := factory.DecodeECHConfigB64(sf.ECHConfigB64)
			name, _ := factory.ECHPublicName(list)
			printCheck(HealthCheck{"ECH config is published", "ok", fmt.Sprintf("pasted in the profile — public name %s (%d bytes), no DoH fetch needed", name, len(list))})
		} else {
			list, err := factory.FetchECHConfigList(ctx, profile.WorkerHost)
			switch {
			case err != nil:
				detail := "could not fetch it (" + err.Error() + ") — the dialer will fall back to fragmentation without ECH"
				if sf.ECHRequired {
					detail = "could not fetch it (" + err.Error() + ") — in strict mode the dialer will refuse to dial"
				}
				printCheck(HealthCheck{"ECH config is published", "warn", detail})
			case func() bool { _, err := factory.ECHPublicName(list); return err != nil }():
				detail := "fetched but unreadable — the dialer will fall back to fragmentation without ECH"
				if sf.ECHRequired {
					detail = "fetched but unreadable — in strict mode the dialer will refuse to dial"
				}
				printCheck(HealthCheck{"ECH config is published", "warn", detail})
			default:
				name, _ := factory.ECHPublicName(list)
				printCheck(HealthCheck{"ECH config is published", "ok", fmt.Sprintf("public name %s (%d bytes)", name, len(list))})
			}
		}
	}

	// Tunnel + end-to-end stream test against the real Worker. Skipped on
	// proxied machines: the daemon dials directly, and a proxy in the middle
	// answers the dial itself, so the test would fail for the wrong reason.
	if proxyEnvSet() {
		printCheck(HealthCheck{"live tunnel test", "warn", "skipped — this machine routes traffic through a proxy, so direct dials cannot be trusted here; run doctor on your own machine to test the tunnel"})
		fmt.Println("\nDoctor: profile is healthy; the live tunnel test was skipped here.")
		return 0
	}

	dialCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	conn, err := factory.DialStealthTunnel(dialCtx, factory.StealthDialConfig{
		Route:        profile.PrimaryRoute,
		FragDelayMs:  sf.FragmentationDelayMs,
		JitterMs:     sf.JitterMs,
		AllowInsec:   sf.AllowInsecureCerts,
		WSPath:       sf.DefaultWSPath,
		ECHEnabled:   sf.ECHEnabled,
		ECHRequired:  sf.ECHRequired,
		ECHConfigB64: sf.ECHConfigB64,
	})
	if err != nil {
		printCheck(HealthCheck{"tunnel dials and upgrades", "fail", err.Error()})
		direct := checkWorkerDirectly(dialCtx, profile.WorkerHost, sf.DefaultWSPath)
		printCheck(direct)
		if direct.Status == "ok" {
			fmt.Println("\nDoctor: FAILED — the tunnel to the profile's edge IP is down, but the Worker itself is alive. The edge IP is probably stale (re-scan for fresh edges) or blocked from this network.")
		} else {
			fmt.Println("\nDoctor: FAILED — the tunnel itself is down. Check the Worker deployment and the route.")
			if strings.Contains(err.Error(), "first record does not look like a TLS handshake") && strings.Contains(direct.Detail, "first record does not look like a TLS handshake") {
				fmt.Println("Note: the edge IP and the hostname fail in exactly the same way — that usually means this network intercepts TLS (a proxy or middlebox), not that the Worker is down. Run doctor on your own machine to be sure.")
			}
		}
		return 1
	}
	printCheck(HealthCheck{"tunnel dials and upgrades", "ok", fmt.Sprintf("TLS + WebSocket upgrade to %s", profile.PrimaryRoute.TargetIP)})
	defer conn.Close()

	sess := newSmuxSession(conn)
	defer sess.Close()
	streamCtx, streamCancel := context.WithTimeout(dialCtx, 15*time.Second)
	defer streamCancel()
	st, err := sess.OpenStream(streamCtx, "example.com", 80)
	if err != nil {
		printCheck(HealthCheck{"a real stream works end to end", "fail", "could not open a stream: " + err.Error()})
		fmt.Println("\nDoctor: FAILED — the tunnel is up but streams do not work. Check the Worker's SMUX handling.")
		return 1
	}
	defer st.Close()
	_, _ = st.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
	buf := make([]byte, 4096)
	type readResult struct {
		n   int
		err error
	}
	resCh := make(chan readResult, 1)
	go func() {
		n, err := st.Read(buf)
		resCh <- readResult{n, err}
	}()
	var n int
	var readErr error
	select {
	case res := <-resCh:
		n, readErr = res.n, res.err
	case <-time.After(10 * time.Second):
		readErr = fmt.Errorf("timed out waiting for a response")
	}
	if readErr != nil || n == 0 || !strings.HasPrefix(string(buf[:n]), "HTTP/") {
		detail := "no HTTP response came back through the tunnel"
		if readErr != nil {
			detail = readErr.Error()
		}
		printCheck(HealthCheck{"a real stream works end to end", "fail", detail})
		fmt.Println("\nDoctor: FAILED — the tunnel is up but streams do not work. Check the Worker's SMUX handling.")
		return 1
	}
	printCheck(HealthCheck{"a real stream works end to end", "ok", "fetched example.com through the tunnel, got " + strings.TrimSpace(strings.SplitN(string(buf[:n]), "\r\n", 2)[0])})

	// ECH refresh through the tunnel: reuse this session to fetch the
	// Worker's ECH config through the tunnel itself, the way the
	// daemon's refresher loop does. A warn, not a fail — the tunnel
	// works either way, and the direct DoH fetch remains the fallback.
	if sf.ECHEnabled {
		list, _, err := fetchECHThroughSession(dialCtx, sess, profile.WorkerHost)
		switch {
		case err != nil:
			printCheck(HealthCheck{"ECH config refreshes through the tunnel", "warn", "could not fetch it through the tunnel (" + err.Error() + ") — the dialer will keep using direct DoH"})
		default:
			name, _ := factory.ECHPublicName(list)
			printCheck(HealthCheck{"ECH config refreshes through the tunnel", "ok", fmt.Sprintf("public name %s (%d bytes), no direct DoH query", name, len(list))})
		}
	}

	// XDP shield: only tested when an interface is given, because attaching
	// needs root and a real interface.
	if iface != "" {
		if os.Geteuid() != 0 {
			printCheck(HealthCheck{"XDP shield attaches", "warn", "not running as root; attaching the XDP shield will likely fail"})
		} else if err := bpf.AttachXDP(iface); err != nil {
			printCheck(HealthCheck{"XDP shield attaches", "fail", err.Error()})
			fmt.Println("\nDoctor: FAILED — the tunnel works, but the XDP shield does not attach.")
			return 1
		} else {
			printCheck(HealthCheck{"XDP shield attaches", "ok", iface})
			bpf.CloseXDP()
		}
	} else {
		printCheck(HealthCheck{"XDP shield", "warn", "not tested — pass -i <interface> (as root) to test the shield too"})
	}

	fmt.Println("\nDoctor: all green — the tunnel works end to end.")
	return 0
}
