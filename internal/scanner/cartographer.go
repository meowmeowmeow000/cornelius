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
	Concurrency int
	Timeout     time.Duration
	SpoofSNI    string
}

func NewCartographer(concurrency int, timeout time.Duration, spoofSNI ...string) *Cartographer {
	spoofer := ""
	if len(spoofSNI) > 0 {
		spoofer = spoofSNI[0]
	}
	return &Cartographer{
		Concurrency: concurrency,
		Timeout:     timeout,
		SpoofSNI:    spoofer,
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
	concurrency := c.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}
	timeout := c.Timeout
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
		CleanEdges: []ProbeResult{},
	}
	if ctx == nil || workerHost == "" || len(targetIPs) == 0 {
		return report
	}

	if len(targetIPs) > maxCIDRAddresses {
		log.Warnf("Cartographer target list exceeds the limit of %d addresses; no probes started", maxCIDRAddresses)
		return report
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
		seen[canonical] = struct{}{}
		unique = append(unique, canonical)
	}
	if len(unique) == 0 {
		return report
	}

	log.Infof("Launching bounded Cartographer [Concurrency: %d, Target IPs: %d, SpoofSNI: %q]", concurrency, len(unique), c.SpoofSNI)
	tasks := make(chan ProbeTask, concurrency)
	results := make(chan *ProbeResult, concurrency)
	fingerprints := make([]string, 0, len(FingerprintMap))
	for name := range FingerprintMap {
		fingerprints = append(fingerprints, name)
	}

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
				if ctx.Err() != nil {
					return
				}
				select {
				case tasks <- ProbeTask{
					IP:          ip,
					Port:        443,
					SpoofSNI:    c.SpoofSNI,
					TargetSNI:   workerHost,
					Fingerprint: fpName,
					ClientHello: FingerprintMap[fpName],
					Mode:        ModeTLSFrag,
					Timeout:     timeout,
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		workers.Wait()
		close(results)
	}()

	for res := range results {
		if res == nil {
			continue
		}
		report.TotalScanned++
		if res.Success {
			report.SuccessfulTLS++
			report.CleanEdges = append(report.CleanEdges, *res)
			log.Infof("[+] TLS endpoint verified: %s | Dir: %s | Mode: %s | FP: %s | TTL: %d | Latency: %dms",
				res.IP, res.Direction, res.Mode, res.Fingerprint, res.ExpectedTTL, res.Latency/time.Millisecond)
		}
	}
	return report
}
