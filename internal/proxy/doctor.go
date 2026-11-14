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

type checkStatus string

const (
	statusOK   checkStatus = "ok"
	statusWarn checkStatus = "warn"
	statusFail checkStatus = "fail"
)

type doctorCheck struct {
	name   string
	status checkStatus
	detail string
}

func (c doctorCheck) String() string {
	mark := "[ok]"
	switch c.status {
	case statusWarn:
		mark = "[!!]"
	case statusFail:
		mark = "[xx]"
	}
	if c.detail == "" {
		return fmt.Sprintf("%s %s", mark, c.name)
	}
	return fmt.Sprintf("%s %s — %s", mark, c.name, c.detail)
}

// validateProfile checks the loaded profile for the misconfigurations that
// have actually broken Cornelius before. Pure function, unit-tested.
func validateProfile(p *config.CombatProfile) []doctorCheck {
	var out []doctorCheck
	sf := p.Modules.StealthFactory

	if p.WorkerHost == "" {
		out = append(out, doctorCheck{"worker host is set", statusFail, "worker_host is empty; the daemon has nowhere to dial"})
	} else {
		out = append(out, doctorCheck{"worker host is set", statusOK, p.WorkerHost})
	}

	switch {
	case sf.DefaultWSPath == "":
		out = append(out, doctorCheck{"WebSocket path is configured", statusFail, "default_ws_path is empty, so the daemon skips the WebSocket upgrade and sends raw SMUX at Cloudflare's HTTPS port (EOF)"})
	case sf.DefaultWSPath == "/":
		out = append(out, doctorCheck{"WebSocket path is configured", statusFail, "default_ws_path is \"/\" — the secret path is missing, the upgrade goes to the wrong path"})
	default:
		out = append(out, doctorCheck{"WebSocket path is configured", statusOK, sf.DefaultWSPath})
	}

	switch sf.SNISPFDirection {
	case config.SNISPFDirectionLegacy:
		out = append(out, doctorCheck{"SNI direction is legacy", statusOK, "outer SNI matches the Worker host"})
	case config.SNISPFDirectionFronting:
		out = append(out, doctorCheck{"SNI direction is legacy", statusWarn, "direction is fronting — Cloudflare blocks SNI/Host mismatches with 403"})
	case "":
		out = append(out, doctorCheck{"SNI direction is legacy", statusWarn, "direction is unset; routes fall back to legacy only when no spoof SNI is set"})
	default:
		out = append(out, doctorCheck{"SNI direction is legacy", statusFail, "unknown direction " + sf.SNISPFDirection})
	}

	route := p.PrimaryRoute
	if route.TargetIP == "" {
		out = append(out, doctorCheck{"primary route has a target", statusFail, "no target_ip — nothing to dial"})
	} else {
		out = append(out, doctorCheck{"primary route has a target", statusOK, fmt.Sprintf("%s:%d (%s)", route.TargetIP, route.TargetPort, route.StealthMode)})
	}
	if route.WSPath != "" && sf.DefaultWSPath != "" && route.WSPath != sf.DefaultWSPath {
		out = append(out, doctorCheck{"route and profile agree on the WebSocket path", statusWarn, fmt.Sprintf("route says %q, profile default says %q", route.WSPath, sf.DefaultWSPath)})
	}
	if route.CleanSNI == "" {
		out = append(out, doctorCheck{"route knows the Worker host", statusFail, "clean_sni is empty"})
	}
	return out
}

// checkProfileAgreement warns when the two profile files in the repo
// disagree, so the user cannot run one by accident and get the other's bugs.
// It looks for combat.profile next to the profile's directory.
func checkProfileAgreement(profilePath string, p *config.CombatProfile) []doctorCheck {
	sibling := filepath.Clean(filepath.Join(filepath.Dir(profilePath), "..", "combat.profile"))
	if filepath.Clean(profilePath) == sibling {
		return nil
	}
	other, err := config.LoadCombatProfile(sibling)
	if err != nil {
		return nil // no second profile to disagree with
	}
	var out []doctorCheck
	a, b := p.Modules.StealthFactory, other.Modules.StealthFactory
	if a.SNISPFDirection != b.SNISPFDirection {
		out = append(out, doctorCheck{"profiles agree on SNI direction", statusWarn, fmt.Sprintf("%s says %q, %s says %q", profilePath, a.SNISPFDirection, sibling, b.SNISPFDirection)})
	}
	if a.DefaultWSPath != b.DefaultWSPath {
		out = append(out, doctorCheck{"profiles agree on the WebSocket path", statusWarn, fmt.Sprintf("%s says %q, %s says %q", profilePath, a.DefaultWSPath, sibling, b.DefaultWSPath)})
	}
	return out
}

// checkWorkerDirectly dials the Worker by hostname (normal DNS) and asks for
// the WebSocket upgrade, bypassing the profile's edge IP. It distinguishes
// "the Worker is dead" from "this edge IP is stale or blocked from here".
func checkWorkerDirectly(ctx context.Context, workerHost, wsPath string) doctorCheck {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(workerHost, "443"), &tls.Config{
		ServerName: workerHost,
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		return doctorCheck{"Worker answers directly (by hostname)", statusFail, "TLS to " + workerHost + " failed: " + err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var keyBytes [16]byte
	_, _ = rand.Read(keyBytes[:])
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		wsPath, workerHost, base64.StdEncoding.EncodeToString(keyBytes[:]))
	if _, err := conn.Write([]byte(req)); err != nil {
		return doctorCheck{"Worker answers directly (by hostname)", statusFail, "upgrade request failed: " + err.Error()}
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return doctorCheck{"Worker answers directly (by hostname)", statusFail, "no response to the upgrade: " + err.Error()}
	}
	if strings.Contains(status, "101") {
		return doctorCheck{"Worker answers directly (by hostname)", statusOK, "WebSocket upgrade at " + wsPath + " returned 101"}
	}
	return doctorCheck{"Worker answers directly (by hostname)", statusFail, "upgrade returned: " + strings.TrimSpace(status)}
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
	printCheck := func(c doctorCheck) { fmt.Println(c.String()) }

	profile, err := config.LoadCombatProfile(profilePath)
	if err != nil {
		printCheck(doctorCheck{"profile loads", statusFail, err.Error()})
		fmt.Println("\nDoctor: FAILED — fix the profile and run again.")
		return 1
	}
	printCheck(doctorCheck{"profile loads", statusOK, profilePath})

	failed := false
	for _, c := range validateProfile(profile) {
		printCheck(c)
		if c.status == statusFail {
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

	// Tunnel + end-to-end stream test against the real Worker. Skipped on
	// proxied machines: the daemon dials directly, and a proxy in the middle
	// answers the dial itself, so the test would fail for the wrong reason.
	if proxyEnvSet() {
		printCheck(doctorCheck{"live tunnel test", statusWarn, "skipped — this machine routes traffic through a proxy, so direct dials cannot be trusted here; run doctor on your own machine to test the tunnel"})
		fmt.Println("\nDoctor: profile is healthy; the live tunnel test was skipped here.")
		return 0
	}

	dialCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	sf := profile.Modules.StealthFactory
	conn, err := factory.DialStealthTunnel(dialCtx, factory.StealthDialConfig{
		Route:       profile.PrimaryRoute,
		FragDelayMs: sf.FragmentationDelayMs,
		JitterMs:    sf.JitterMs,
		AllowInsec:  sf.AllowInsecureCerts,
		WSPath:      sf.DefaultWSPath,
	})
	if err != nil {
		printCheck(doctorCheck{"tunnel dials and upgrades", statusFail, err.Error()})
		direct := checkWorkerDirectly(dialCtx, profile.WorkerHost, sf.DefaultWSPath)
		printCheck(direct)
		if direct.status == statusOK {
			fmt.Println("\nDoctor: FAILED — the tunnel to the profile's edge IP is down, but the Worker itself is alive. The edge IP is probably stale (re-scan for fresh edges) or blocked from this network.")
		} else {
			fmt.Println("\nDoctor: FAILED — the tunnel itself is down. Check the Worker deployment and the route.")
			if strings.Contains(err.Error(), "first record does not look like a TLS handshake") && strings.Contains(direct.detail, "first record does not look like a TLS handshake") {
				fmt.Println("Note: the edge IP and the hostname fail in exactly the same way — that usually means this network intercepts TLS (a proxy or middlebox), not that the Worker is down. Run doctor on your own machine to be sure.")
			}
		}
		return 1
	}
	printCheck(doctorCheck{"tunnel dials and upgrades", statusOK, fmt.Sprintf("TLS + WebSocket upgrade to %s", profile.PrimaryRoute.TargetIP)})
	defer conn.Close()

	sess := newSmuxSession(conn)
	defer sess.Close()
	streamCtx, streamCancel := context.WithTimeout(dialCtx, 15*time.Second)
	defer streamCancel()
	st, err := sess.OpenStream(streamCtx, "example.com", 80)
	if err != nil {
		printCheck(doctorCheck{"a real stream works end to end", statusFail, "could not open a stream: " + err.Error()})
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
		printCheck(doctorCheck{"a real stream works end to end", statusFail, detail})
		fmt.Println("\nDoctor: FAILED — the tunnel is up but streams do not work. Check the Worker's SMUX handling.")
		return 1
	}
	printCheck(doctorCheck{"a real stream works end to end", statusOK, "fetched example.com through the tunnel, got " + strings.TrimSpace(strings.SplitN(string(buf[:n]), "\r\n", 2)[0])})

	// XDP shield: only tested when an interface is given, because attaching
	// needs root and a real interface.
	if iface != "" {
		if os.Geteuid() != 0 {
			printCheck(doctorCheck{"XDP shield attaches", statusWarn, "not running as root; attaching the XDP shield will likely fail"})
		} else if err := bpf.AttachXDP(iface); err != nil {
			printCheck(doctorCheck{"XDP shield attaches", statusFail, err.Error()})
			fmt.Println("\nDoctor: FAILED — the tunnel works, but the XDP shield does not attach.")
			return 1
		} else {
			printCheck(doctorCheck{"XDP shield attaches", statusOK, iface})
			bpf.CloseXDP()
		}
	} else {
		printCheck(doctorCheck{"XDP shield", statusWarn, "not tested — pass -i <interface> (as root) to test the shield too"})
	}

	fmt.Println("\nDoctor: all green — the tunnel works end to end.")
	return 0
}
