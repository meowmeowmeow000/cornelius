package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cornelius/internal/bpf"
	"cornelius/internal/config"
	"cornelius/internal/coordinator"
	"cornelius/internal/ipc"
	"cornelius/internal/proxy"
	"cornelius/internal/proxy/pool"
	"cornelius/internal/scanner"
	"cornelius/internal/telemetry"
)

func main() {
	configPath := flag.String("c", "configs/combat.profile", "Path to the combat.profile JSON")
	iface := flag.String("i", "", "Network interface for XDP Shield (e.g., eth0)")
	listenAddr := flag.String("l", "127.0.0.1:40443", "Local proxy listen address")
	scanCIDR := flag.String("scan", "", "Optional CIDR or comma-separated IPs to scan before starting")
	workerSNI := flag.String("worker", "", "Inner worker SNI hostname for pre-boot scan")
	spoofSNI := flag.String("spoof", "", "Optional outer SpoofSNI for dual-direction SNISPF fronting")
	flag.Parse()

	telemetry.InitLogger(slog.LevelInfo)
	telemetry.Log.Info("Starting Cornelius v1.2.0 Engine...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *iface != "" {
		telemetry.Log.Info("Attaching XDP DPI-RST Shield...", slog.String("interface", *iface))
		if err := bpf.AttachXDP(*iface); err != nil {
			telemetry.Log.Error("Failed to attach XDP shield", slog.String("err", err.Error()))
			os.Exit(1)
		}
		defer bpf.CloseXDP()
		telemetry.Log.Info("XDP Shield Active")
	} else {
		telemetry.Log.Warn("No interface provided (-i). XDP Kernel Defense is disabled.")
	}

	if *scanCIDR != "" && *workerSNI != "" {
		var targets []string
		if strings.Contains(*scanCIDR, "/") {
			expanded, err := scanner.ExpandCIDR(*scanCIDR)
			if err != nil {
				telemetry.Log.Error("Invalid scan CIDR", slog.String("err", err.Error()))
				os.Exit(1)
			}
			targets = expanded
		} else {
			targets = strings.Split(*scanCIDR, ",")
		}
		cart := scanner.NewCartographer(16, 4*time.Second, *spoofSNI)
		rep := cart.Run(ctx, targets, *workerSNI)
		if _, err := scanner.CompileCombatProfile(rep, *configPath); err != nil {
			telemetry.Log.Warn("Scan did not produce a new profile", slog.String("err", err.Error()))
		}
	}

	profile, err := config.LoadCombatProfile(*configPath)
	if err != nil {
		telemetry.Log.Warn("Could not load combat.profile; waiting for IPC route injection", slog.String("err", err.Error()))
		profile = &config.CombatProfile{}
	} else {
		telemetry.Log.Info("Loaded combat.profile",
			slog.String("primary_target", profile.PrimaryRoute.TargetIP),
			slog.String("snispf_direction", profile.PrimaryRoute.SNISPFDirection),
			slog.String("spoof_sni", profile.PrimaryRoute.SpoofSNI),
			slog.String("worker_sni", profile.PrimaryRoute.CleanSNI))
	}

	if profile.ExpectedTTL > 0 {
		tol := profile.Modules.XDPShield.TTLTolerance
		if tol == 0 {
			tol = 4
		}
		lockdown := profile.Modules.XDPShield.Mode == "lockdown"
		_ = bpf.UpdateXDPConfig(profile.ExpectedTTL, tol, lockdown, profile.PrimaryRoute.TargetPort)
	}

	warmPool := pool.NewWarmPool(profile)
	if err := warmPool.Start(ctx); err != nil {
		telemetry.Log.Error("Failed to initialize warm pool", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer warmPool.Close()

	if profile.PrimaryRoute.TargetIP != "" {
		telemetry.RecordEvent("BOOT", "info", "Active edge "+profile.PrimaryRoute.TargetIP+" ("+profile.PrimaryRoute.SNISPFDirection+")")
	}

	strat := coordinator.NewStrategist(warmPool, profile)
	go strat.Start(ctx)

	go ipc.StartControlPlane(ctx, warmPool)

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		telemetry.Log.Error("Failed to bind local proxy listener", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer ln.Close()
	go proxy.StartSOCKS5Server(ctx, "127.0.0.1:10808", warmPool)
	telemetry.Log.Info("Cornelius listening for local Trojan/V2Ray traffic", slog.String("addr", *listenAddr))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		telemetry.Log.Info("Shutdown signal received. Tearing down Cornelius...")
		cancel()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go warmPool.HandleLocalConnection(conn)
	}

	telemetry.Log.Info("Cornelius shut down cleanly.")
}
