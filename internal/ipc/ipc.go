package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cornelius/internal/bpf"
	"cornelius/internal/config"
	"cornelius/internal/proxy"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/proxy/pool"
	"cornelius/internal/scanner"
	"cornelius/internal/telemetry"
)

const SockAddr = "/run/cornelius/ipc.sock"

type IPCCommand struct {
	Action          string                `json:"action"`
	Route           config.RouteCandidate `json:"route,omitempty"`
	SNISPFDirection string                `json:"snispf_direction,omitempty"`
	SpoofSNI        string                `json:"spoof_sni,omitempty"`
	CIDR            string                `json:"cidr,omitempty"`
	ExpectedTTL     uint8                 `json:"expected_ttl,omitempty"`
	TTLTolerance    uint8                 `json:"ttl_tolerance,omitempty"`
	Lockdown        bool                  `json:"lockdown,omitempty"`
	StealthMode     string                `json:"stealth_mode,omitempty"`
	FragDelayMs     int                   `json:"frag_delay_ms,omitempty"`
	JitterMs        int                   `json:"jitter_ms,omitempty"`
}

type IPCResponse struct {
	Status   string                   `json:"status"`
	Message  string                   `json:"message,omitempty"`
	Snapshot *telemetry.VitalSnapshot `json:"snapshot,omitempty"`
	Checks   []proxy.HealthCheck      `json:"checks,omitempty"`
}

func StartControlPlane(ctx context.Context, warmPool *pool.WarmPool) {
	if err := os.MkdirAll(filepath.Dir(SockAddr), 0700); err != nil {
		telemetry.Log.Error("IPC runtime directory unavailable", slog.String("err", err.Error()))
		return
	}
	if err := os.Chmod(filepath.Dir(SockAddr), 0700); err != nil {
		telemetry.Log.Error("Could not secure IPC runtime directory", slog.String("err", err.Error()))
		return
	}
	if _, err := os.Lstat(SockAddr); err == nil {
		telemetry.Log.Error("IPC socket path already exists; refusing to replace it", slog.String("path", SockAddr))
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		telemetry.Log.Error("Could not inspect IPC socket path", slog.String("err", err.Error()))
		return
	}

	listener, err := net.Listen("unix", SockAddr)
	if err != nil {
		telemetry.Log.Error("IPC Unix socket failed to bind", slog.String("err", err.Error()))
		return
	}
	if err := os.Chmod(SockAddr, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(SockAddr)
		telemetry.Log.Error("Could not secure IPC socket", slog.String("err", err.Error()))
		return
	}
	ownedInfo, err := os.Lstat(SockAddr)
	if err != nil {
		_ = listener.Close()
		telemetry.Log.Error("Could not inspect bound IPC socket", slog.String("err", err.Error()))
		return
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
		if current, err := os.Lstat(SockAddr); err == nil && os.SameFile(ownedInfo, current) {
			_ = os.Remove(SockAddr)
		}
	}()
	telemetry.RecordEvent("IPC", "info", "Control plane listening on "+SockAddr)
	telemetry.Log.Info("Cornelius IPC Control Plane Listening", slog.String("socket", SockAddr))

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleIPCConn(conn, warmPool)
	}
}

func handleIPCConn(conn net.Conn, warmPool *pool.WarmPool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var cmd IPCCommand
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&cmd); err != nil {
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: err.Error()})
		return
	}
	if warmPool == nil {
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "warm pool unavailable"})
		return
	}

	switch cmd.Action {
	case "inject_route":
		if cmd.Route.TargetIP == "" || net.ParseIP(cmd.Route.TargetIP) == nil {
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "route.target_ip must be a valid IP address"})
			return
		}
		switch cmd.Route.StealthMode {
		case "", factory.ModeTLSFrag, factory.ModeTLSMicroFrag, factory.ModeTLSDisorder, factory.ModeSNIFront:
		default:
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "unknown stealth_mode: " + cmd.Route.StealthMode})
			return
		}
		switch cmd.Route.SNISPFDirection {
		case "", config.SNISPFDirectionLegacy, config.SNISPFDirectionFronting:
		default:
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "snispf_direction must be 'legacy' or 'fronting'"})
			return
		}
		ttl := cmd.Route.ExpectedTTL
		if ttl == 0 {
			ttl = cmd.ExpectedTTL
		}
		if ttl > 0 {
			tol := cmd.TTLTolerance
			if tol == 0 {
				tol = 4
			}
			_ = bpf.UpdateXDPConfig(ttl, tol, cmd.Lockdown, cmd.Route.TargetPort)
		}
		warmPool.InjectEmergencyRoute(cmd.Route)
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "route injected"})

	case "set_snispf":
		switch cmd.SNISPFDirection {
		case "", config.SNISPFDirectionLegacy, config.SNISPFDirectionFronting:
		default:
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "snispf_direction must be 'legacy' or 'fronting'"})
			return
		}
		if cmd.SNISPFDirection == config.SNISPFDirectionFronting && cmd.SpoofSNI == "" && warmPool.ActiveRoute().SpoofSNI == "" {
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "spoof_sni is required for fronting direction"})
			return
		}
		warmPool.SetSNISPFDirection(cmd.SNISPFDirection, cmd.SpoofSNI)
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "SNISPF direction updated"})

	case "lockdown_xdp":
		active := warmPool.ActiveRoute()
		_ = bpf.UpdateXDPConfig(cmd.ExpectedTTL, cmd.TTLTolerance, cmd.Lockdown, active.TargetPort)
		state := "ADAPTIVE"
		if cmd.Lockdown {
			state = "LOCKDOWN"
		}
		telemetry.RecordEvent("XDP", "warn", "Manual XDP mode -> "+state)
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "XDP configuration updated"})

	case "escalate_stealth":
		warmPool.EscalateStealthMode(cmd.StealthMode, cmd.FragDelayMs, cmd.JitterMs)
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "stealth mode updated"})

	case "echolocate":
		active := warmPool.ActiveRoute()
		if active.TargetIP == "" {
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "no active target IP to echolocate"})
			return
		}
		echoBusy, _ := telemetry.GetBackgroundBusy()
		if echoBusy {
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "echolocation already running"})
			return
		}
		busyTrue := true
		telemetry.SetBackgroundBusy(&busyTrue, nil)
		telemetry.RecordEvent("ECHO", "info", fmt.Sprintf("Probing DPI hop topology -> %s", active.TargetIP))

		go func(route config.RouteCandidate) {
			defer func() {
				busyFalse := false
				telemetry.SetBackgroundBusy(&busyFalse, nil)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			probeHost := route.CleanSNI
			if probeHost == "" {
				probeHost = "www.youtube.com"
			}
			rep, err := scanner.EcholocateDPI(ctx, route.TargetIP, int(route.TargetPort), probeHost, 18)
			if err != nil || rep == nil {
				telemetry.RecordEvent("ECHO", "warn", "Echolocation sweep incomplete")
				return
			}
			hops := make([]telemetry.EchoHopSummary, 0, len(rep.Hops))
			for _, h := range rep.Hops {
				hops = append(hops, telemetry.EchoHopSummary{
					TTL:      h.TTL,
					RouterIP: h.RouterIP,
					Event:    h.Event,
					RTTMs:    h.RTT.Milliseconds(),
				})
			}
			summary := &telemetry.EchoSummary{
				TargetIP:            rep.TargetIP,
				DPIIntercepted:      rep.DPIIntercepted,
				DPIDistanceHops:     rep.DPIDistanceHops,
				ServerDistanceHops:  rep.ServerDistanceHops,
				RecommendedDecoyTTL: rep.RecommendedDecoyTTL,
				Hops:                hops,
			}
			telemetry.SetEchoSummary(summary)
			warmPool.UpdateDecoyTTL(rep.RecommendedDecoyTTL, rep.DPIDistanceHops)
			if rep.DPIIntercepted {
				telemetry.RecordEvent("ECHO", "crit", fmt.Sprintf("DPI middlebox detected at hop %d (DecoyTTL=%d)", rep.DPIDistanceHops, rep.RecommendedDecoyTTL))
			} else {
				telemetry.RecordEvent("ECHO", "info", fmt.Sprintf("Clean path (%d hops; DecoyTTL=%d)", rep.ServerDistanceHops, rep.RecommendedDecoyTTL))
			}
		}(active)

		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "echolocation started"})

	case "scan_cidr":
		rawCIDR := strings.TrimSpace(cmd.CIDR)
		if rawCIDR == "" {
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "cidr or target IP list is required"})
			return
		}
		var targets []string
		if strings.Contains(rawCIDR, "/") {
			expanded, err := scanner.ExpandCIDR(rawCIDR)
			if err != nil {
				_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: err.Error()})
				return
			}
			targets = expanded
		} else {
			for _, part := range strings.Split(rawCIDR, ",") {
				if p := strings.TrimSpace(part); p != "" {
					targets = append(targets, p)
				}
			}
		}
		_, scanBusy := telemetry.GetBackgroundBusy()
		if scanBusy {
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "scanner already running"})
			return
		}
		active := warmPool.ActiveRoute()
		worker := active.CleanSNI
		if worker == "" {
			_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: "active worker SNI required before scanning"})
			return
		}
		spoof := strings.TrimSpace(cmd.SpoofSNI)
		if spoof == "" {
			spoof = active.SpoofSNI
		}
		busyTrue := true
		telemetry.SetBackgroundBusy(nil, &busyTrue)
		telemetry.RecordEvent("SCAN", "info", fmt.Sprintf("Cartographer scanning %d targets...", len(targets)))

		go func(ips []string, wHost, sHost, wsPath string) {
			defer func() {
				busyFalse := false
				telemetry.SetBackgroundBusy(nil, &busyFalse)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			cart := scanner.NewCartographer(16, 4*time.Second, sHost)
			cart.WSPath = wsPath
			rep := cart.Run(ctx, ips, wHost)
			primary, failovers, err := scanner.RankUniqueRoutes(rep)
			if err != nil {
				telemetry.RecordEvent("SCAN", "warn", "Scan finished with 0 verified edges")
				return
			}
			warmPool.ReplaceRoutesFromScan(primary, failovers)
		}(targets, worker, spoof, active.WSPath)

		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Message: "scanner started"})

	case "doctor":
		// Cheap checks only: profile validation plus live counters. The
		// full live tunnel test stays in the `cornelius doctor` CLI — it
		// dials the network and must not run on every TUI poll.
		var checks []proxy.HealthCheck
		if prof := warmPool.Profile(); prof != nil {
			checks = append(checks, proxy.CheckProfileHealth(prof)...)
		} else {
			checks = append(checks, proxy.HealthCheck{Name: "profile is loaded", Status: "fail", Detail: "the daemon has no profile to check"})
		}
		if pipes := telemetry.PoolHealthyPipes.Load(); pipes > 0 {
			checks = append(checks, proxy.HealthCheck{Name: "warm tunnels ready", Status: "ok", Detail: fmt.Sprintf("%d warm pipe(s) in the pool", pipes)})
		} else {
			checks = append(checks, proxy.HealthCheck{Name: "warm tunnels ready", Status: "warn", Detail: "no warm pipes — dials will be cold until the pool replenishes"})
		}
		if fails := telemetry.DialFailures.Load(); fails > 0 {
			checks = append(checks, proxy.HealthCheck{Name: "dial failures since start", Status: "warn", Detail: fmt.Sprintf("%d failed dial(s)", fails)})
		} else {
			checks = append(checks, proxy.HealthCheck{Name: "dial failures since start", Status: "ok", Detail: "none"})
		}
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Checks: checks})

	case "status":
		active := warmPool.ActiveRoute()
		dir, _, _ := factory.ResolveSNIDirection(active)
		echoBusy, scanBusy := telemetry.GetBackgroundBusy()
		snap := &telemetry.VitalSnapshot{
			ActiveStreams:   telemetry.ActiveStreams.Load(),
			WarmPipes:       telemetry.PoolHealthyPipes.Load(),
			PoolCapacity:    warmPool.Capacity(),
			TxKB:            telemetry.TotalBytesTx.Load() / 1024,
			RxKB:            telemetry.TotalBytesRx.Load() / 1024,
			RouteRotations:  telemetry.RouteRotations.Load(),
			ModeEscalations: telemetry.ModeEscalations.Load(),
			XDPDroppedPkts:  telemetry.XDPDroppedRSTs.Load(),
			IPCOverrides:    telemetry.IPCOverrides.Load(),
			DialFailures:    telemetry.DialFailures.Load(),
			ExpectedTTL:     telemetry.CurrentExpectedTTL.Load(),
			TTLTolerance:    telemetry.CurrentTTLTolerance.Load(),
			XDPLockdown:     telemetry.CurrentLockdownMode.Load() == 1,
			ActiveRouteIP:   active.TargetIP,
			SNISPFDirection: dir,
			ActiveSpoofSNI:  active.SpoofSNI,
			ActiveSNI:       active.CleanSNI,
			ActiveStealth:   active.StealthMode,
			FailoverRoutes:  warmPool.AllRoutes(),
			RecentEvents:    telemetry.RecentEvents(10),
			Echo:            telemetry.GetEchoSummary(),
			EchoBusy:        echoBusy,
			ScanBusy:        scanBusy,
		}
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "ok", Snapshot: snap})

	default:
		_ = json.NewEncoder(conn).Encode(IPCResponse{Status: "error", Message: fmt.Sprintf("unknown IPC action: %s", cmd.Action)})
	}
}
