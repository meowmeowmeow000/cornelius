package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"cornelius/internal/config"
)

const (
	maxCIDRAddresses = 256
	maxConcurrency   = 32
	defaultTimeout   = 4 * time.Second
	maxProbeTimeout  = 30 * time.Second
)

type Cartographer struct {
	// Mode is the scan strategy (default Balanced when zero). See modes.go.
	Mode ScanMode
	// SpoofSNI is the outer SNI used for fronting-direction probes.
	SpoofSNI string
	// WSPath is the secret WebSocket path; probes verify the full tunnel
	// when set.
	WSPath string
	// Avoid lists IPs to skip for this run — gateways that just failed.
	// Aether has no duration-based cooldown, only slot-drop plus a
	// per-scan avoid set; this is the per-scan half of that.
	Avoid []string
}

func NewCartographer(concurrency int, timeout time.Duration, spoofSNI ...string) *Cartographer {
	spoofer := ""
	if len(spoofSNI) > 0 {
		spoofer = spoofSNI[0]
	}
	// The historical call sites pass (16, 4s): Balanced with those values.
	mode := ScanModeBalanced
	if concurrency > 0 {
		mode.Concurrency = concurrency
	}
	if timeout > 0 {
		mode.PerProbeTimeout = timeout
	}
	return &Cartographer{
		Mode:     mode,
		SpoofSNI: spoofer,
	}
}

func ExpandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	maskSize, bits := ipnet.Mask.Size()
	hostBits := bits - maskSize
	if hostBits < 0 || hostBits > 8 {
		return nil, fmt.Errorf("CIDR contains more than %d addresses; use an explicitly scoped smaller range", maxCIDRAddresses)
	}

	count := 1 << hostBits
	if count > maxCIDRAddresses {
		return nil, fmt.Errorf("CIDR contains %d addresses; maximum is %d", count, maxCIDRAddresses)
	}

	base := append(net.IP(nil), ipnet.IP...)
	if ipv4 := base.To4(); ipv4 != nil {
		base = ipv4
	}
	ips := make([]string, 0, count)
	for i := 0; i < count; i++ {
		cur := append(net.IP(nil), base...)
		ips = append(ips, cur.String())
		if i+1 < count {
			base = incrementIP(base)
		}
	}
	return ips, nil
}

func incrementIP(ip net.IP) net.IP {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
	return ip
}

func (c *Cartographer) Run(ctx context.Context, targetIPs []string, workerHost string) *IntelligenceReport {
	mode := c.Mode
	if mode.Name == "" {
		mode = ScanModeBalanced
	}
	concurrency := CapConcurrency(mode.Concurrency)
	timeout := mode.PerProbeTimeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > maxProbeTimeout {
		timeout = maxProbeTimeout
	}

	report := &IntelligenceReport{
		Timestamp:  time.Now(),
		WorkerHost: workerHost,
		SpoofHost:  c.SpoofSNI,
		ScanMode:   mode.Name,
		CleanEdges: []ProbeResult{},
	}
	if ctx == nil || workerHost == "" || len(targetIPs) == 0 {
		return report
	}

	// The mode's deadline bounds the scan; the caller's context still
	// bounds it too — whichever fires first wins. Always derive a
	// cancellable context so an early finish (target reached, quiet
	// window expired) can stop in-flight probes instead of leaking them.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if mode.Deadline > 0 {
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithTimeout(ctx, mode.Deadline)
		defer deadlineCancel()
	}

	if len(targetIPs) > maxCIDRAddresses {
		log.Warnf("Cartographer target list exceeds the limit of %d addresses; no probes started", maxCIDRAddresses)
		return report
	}

	avoid := make(map[string]struct{}, len(c.Avoid))
	for _, ip := range c.Avoid {
		if parsed := net.ParseIP(ip); parsed != nil {
			avoid[parsed.String()] = struct{}{}
		}
	}

	unique := make([]string, 0, len(targetIPs))
	seen := make(map[string]struct{}, len(targetIPs))
	for _, target := range targetIPs {
		ip := net.ParseIP(target)
		if ip == nil {
			log.Warnf("Skipping invalid target IP %q", target)
			continue
		}
		canonical := ip.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		if _, ok := avoid[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		unique = append(unique, canonical)
	}
	if len(unique) == 0 {
		return report
	}

	log.Infof("Launching bounded Cartographer [Mode: %s, Concurrency: %d, Target IPs: %d, SpoofSNI: %q]", mode.Name, concurrency, len(unique), c.SpoofSNI)
	tasks := make(chan ProbeTask, concurrency)
	results := make(chan *ProbeResult, concurrency)
	fingerprints := make([]string, 0, len(FingerprintMap))
	for name := range FingerprintMap {
		fingerprints = append(fingerprints, name)
	}

	// requestStop tells the feeder to stop sending new candidates once
	// the target is reached; in-flight probes still finish and their
	// results still count during the quiet window.
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	requestStop := func() { stopOnce.Do(func() { close(stopCh) }) }

	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range tasks {
				var res *ProbeResult
				if task.SpoofSNI != "" {
					task.Direction = config.SNISPFDirectionFronting
					task.Mode = ModeTLSFrag
					res, _ = DialStealthProbe(ctx, task)
					if res != nil && !res.Success && ctx.Err() == nil {
						task.Mode = ModeTLSMicroFrag
						res, _ = DialStealthProbe(ctx, task)
					}
				}
				if (res == nil || !res.Success) && ctx.Err() == nil {
					task.Direction = config.SNISPFDirectionLegacy
					task.Mode = ModeTLSFrag
					res, _ = DialStealthProbe(ctx, task)
					if res != nil && !res.Success && ctx.Err() == nil {
						task.Mode = ModeTLSMicroFrag
						res, _ = DialStealthProbe(ctx, task)
					}
				}
				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(tasks)
		for _, ip := range unique {
			for _, fpName := range fingerprints {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				case tasks <- ProbeTask{
					IP:          ip,
					Port:        443,
					SpoofSNI:    c.SpoofSNI,
					TargetSNI:   workerHost,
					Fingerprint: fpName,
					ClientHello: FingerprintMap[fpName],
					Mode:        ModeTLSFrag,
					WSPath:      c.WSPath,
					Timeout:     timeout,
				}:
				}
			}
		}
	}()

	go func() {
		workers.Wait()
		close(results)
	}()

	// Target + quiet window, borrowed from Aether: once TargetSuccesses
	// is reached, stop feeding new candidates and keep collecting for
	// QuietWindow in case a faster gateway shows up, then finalize with
	// the lowest RTT. EarlyExitFirst (Turbo) returns on the first
	// success with no ranking. TargetSuccesses 0 (Thorough) collects
	// everything and ignores the quiet window.
	successes := 0
	var quiet *time.Timer
	var quietCh <-chan time.Time
	collect := func(res *ProbeResult) bool {
		if res == nil {
			return true
		}
		report.TotalScanned++
		if !res.Success {
			return true
		}
		report.SuccessfulTLS++
		report.CleanEdges = append(report.CleanEdges, *res)
		successes++
		log.Infof("[+] TLS endpoint verified: %s | Dir: %s | Mode: %s | FP: %s | TTL: %d | Latency: %dms",
			res.IP, res.Direction, res.Mode, res.Fingerprint, res.ExpectedTTL, res.Latency/time.Millisecond)
		if mode.EarlyExitFirst {
			return false
		}
		if mode.TargetSuccesses > 0 && successes >= mode.TargetSuccesses {
			requestStop()
			if mode.QuietWindow <= 0 {
				return false
			}
			// The quiet window is armed once, when the target is first
			// reached, and later successes do not extend it — Aether
			// does the same (quiet_until is set only when none is
			// running). The window is a deadline for a faster gateway
			// to show up, not a sliding inactivity timer.
			if quiet == nil {
				quiet = time.NewTimer(mode.QuietWindow)
				quietCh = quiet.C
			}
		}
		return true
	}

collectLoop:
	for {
		select {
		case res, ok := <-results:
			if !ok {
				break collectLoop
			}
			if !collect(res) {
				break collectLoop
			}
		case <-quietCh:
			log.Infof("[+] Quiet window expired (%s); finalizing selection", mode.QuietWindow)
			break collectLoop
		case <-ctx.Done():
			break collectLoop
		}
	}
	if quiet != nil {
		quiet.Stop()
	}
	return report
}
