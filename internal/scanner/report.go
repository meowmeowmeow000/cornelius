package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"cornelius/internal/config"
)

const maxFailoverRoutes = 5

func ExportAtlasJSON(report *IntelligenceReport, filepath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal atlas json: %w", err)
	}
	return os.WriteFile(filepath, data, 0600)
}

func RankUniqueRoutes(report *IntelligenceReport) (config.RouteCandidate, []config.RouteCandidate, error) {
	if report == nil {
		return config.RouteCandidate{}, nil, fmt.Errorf("probe report is nil")
	}
	if len(report.CleanEdges) == 0 {
		return config.RouteCandidate{}, nil, fmt.Errorf("no certificate-verified TLS endpoints")
	}
	if report.WorkerHost == "" {
		return config.RouteCandidate{}, nil, fmt.Errorf("worker host is required")
	}

	bestByIP := make(map[string]ProbeResult, len(report.CleanEdges))
	for _, edge := range report.CleanEdges {
		if !edge.Success || edge.IP == "" {
			continue
		}
		existing, ok := bestByIP[edge.IP]
		if !ok || isBetterProbe(edge, existing) {
			bestByIP[edge.IP] = edge
		}
	}

	if len(bestByIP) == 0 {
		return config.RouteCandidate{}, nil, fmt.Errorf("no valid unique TLS endpoints")
	}

	uniqueEdges := make([]ProbeResult, 0, len(bestByIP))
	for _, edge := range bestByIP {
		uniqueEdges = append(uniqueEdges, edge)
	}
	sort.Slice(uniqueEdges, func(i, j int) bool {
		// A route that proved the full tunnel (WebSocket upgrade + SMUX
		// echo) always beats a faster one that only proved TLS.
		if uniqueEdges[i].WSVerified != uniqueEdges[j].WSVerified {
			return uniqueEdges[i].WSVerified
		}
		return uniqueEdges[i].Latency < uniqueEdges[j].Latency
	})

	primary := toRouteCandidate(report.WorkerHost, report.SpoofHost, uniqueEdges[0])

	failoverCap := len(uniqueEdges) - 1
	if failoverCap > maxFailoverRoutes {
		failoverCap = maxFailoverRoutes
	}
	failovers := make([]config.RouteCandidate, 0, failoverCap)
	for _, edge := range uniqueEdges[1 : 1+failoverCap] {
		failovers = append(failovers, toRouteCandidate(report.WorkerHost, report.SpoofHost, edge))
	}

	echoCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	echoRep, echoErr := EcholocateDPI(echoCtx, primary.TargetIP, int(primary.TargetPort), report.WorkerHost, 16)
	cancel()
	if echoErr == nil && echoRep != nil {
		primary.DPIDistance = echoRep.DPIDistanceHops
		primary.DecoyTTL = echoRep.RecommendedDecoyTTL
		for i := range failovers {
			failovers[i].DPIDistance = echoRep.DPIDistanceHops
			failovers[i].DecoyTTL = echoRep.RecommendedDecoyTTL
		}
	}

	return primary, failovers, nil
}

func CompileCombatProfile(report *IntelligenceReport, outputPath string) (*config.CombatProfile, error) {
	primary, failovers, err := RankUniqueRoutes(report)
	if err != nil {
		return nil, fmt.Errorf("%w; profile was not written", err)
	}

	// Remember the winning gateway in the last-good ring beside the
	// profile, so the next scan tries it first. Best-effort: the ring
	// is a cache and must never fail a profile write.
	if ringPath := LastGoodPath(outputPath); ringPath != "" {
		ring := LoadLastGood(ringPath)
		ring.Record(primary.TargetIP)
		_ = ring.Save(ringPath)
	}

	// Preserve the settings a rescan must not silently drop. Freshly ranked
	// routes carry neither a WebSocket path nor any ECH settings (the
	// scanner only verifies TLS), so without this a rescan drops
	// default_ws_path — the daemon stops doing the WebSocket upgrade
	// entirely, raw SMUX frames hit Cloudflare's HTTPS port and the
	// connection dies with EOF — and ech_enabled / ech_required /
	// ech_config_b64, silently turning ECH off so the Worker hostname
	// shows in the SNI again.
	var echEnabled, echRequired bool
	var echConfigB64 string
	var preserved *config.CombatProfile
	if existing, err := config.LoadCombatProfile(outputPath); err == nil {
		sf := existing.Modules.StealthFactory
		if primary.WSPath == "" && sf.DefaultWSPath != "" {
			primary.WSPath = sf.DefaultWSPath
		}
		echEnabled, echRequired, echConfigB64 = sf.ECHEnabled, sf.ECHRequired, sf.ECHConfigB64
		preserved = existing
	}

	profile := config.DefaultCombatProfile(report.WorkerHost, primary, failovers)
	profile.Modules.StealthFactory.ECHEnabled = echEnabled
	profile.Modules.StealthFactory.ECHRequired = echRequired
	profile.Modules.StealthFactory.ECHConfigB64 = echConfigB64
	if preserved != nil {
		preserveUserSettings(profile, preserved)
	}
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal combat profile: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write combat profile: %w", err)
	}
	return profile, nil
}

// preserveUserSettings carries the user-tunable settings of the profile
// being overwritten onto the freshly compiled one, so a rescan only
// replaces routes. Zero-valued groups (an older profile that predates the
// field) keep the defaults. Of the XDP shield only RSTBurstThreshold is
// preserved: Mode, TTLTolerance and ExpectedTTL are scan-derived and must
// follow the fresh scan (e.g. a rescan that newly detects DPI must switch
// the shield to lockdown).
func preserveUserSettings(profile, existing *config.CombatProfile) {
	if existing.OperationalDoctrine != (config.OperationalDoctrine{}) {
		profile.OperationalDoctrine = existing.OperationalDoctrine
	}
	old, sf := existing.Modules, &profile.Modules.StealthFactory
	if old.WarmPool != (config.WarmPoolConfig{}) {
		profile.Modules.WarmPool = old.WarmPool
	}
	if old.XDPShield.RSTBurstThreshold != 0 {
		profile.Modules.XDPShield.RSTBurstThreshold = old.XDPShield.RSTBurstThreshold
	}
	if old.StealthFactory.FallbackMode != "" {
		sf.FallbackMode = old.StealthFactory.FallbackMode
	}
	sf.FragmentationDelayMs = old.StealthFactory.FragmentationDelayMs
	sf.JitterMs = old.StealthFactory.JitterMs
	if len(existing.ContingencyMatrix) > 0 {
		profile.ContingencyMatrix = existing.ContingencyMatrix
	}
}

func isBetterProbe(candidate, current ProbeResult) bool {
	if candidate.WSVerified != current.WSVerified {
		return candidate.WSVerified
	}
	if candidate.Direction == config.SNISPFDirectionFronting && current.Direction != config.SNISPFDirectionFronting {
		return true
	}
	if candidate.Direction != config.SNISPFDirectionFronting && current.Direction == config.SNISPFDirectionFronting {
		return false
	}
	if candidate.ExpectedTTL > 0 && current.ExpectedTTL == 0 {
		return true
	}
	if candidate.ExpectedTTL == 0 && current.ExpectedTTL > 0 {
		return false
	}
	return candidate.Latency < current.Latency
}

func toRouteCandidate(workerHost, defaultSpoof string, edge ProbeResult) config.RouteCandidate {
	ms := edge.Latency.Milliseconds()
	score := 100 - int(ms/10)
	if score > 100 {
		score = 100
	}
	if score < 10 {
		score = 10
	}
	port := uint16(edge.Port)
	if port == 0 {
		port = 443
	}
	spoof := edge.SpoofSNI
	if spoof == "" {
		spoof = defaultSpoof
	}
	dir := edge.Direction
	if dir == "" {
		if spoof != "" && spoof != workerHost {
			dir = config.SNISPFDirectionFronting
		} else {
			dir = config.SNISPFDirectionLegacy
		}
	}
	return config.RouteCandidate{
		TargetIP:        edge.IP,
		TargetPort:      port,
		SNISPFDirection: dir,
		SpoofSNI:        spoof,
		CleanSNI:        workerHost,
		StealthMode:     string(edge.Mode),
		Fingerprint:     edge.Fingerprint,
		ExpectedTTL:     edge.ExpectedTTL,
		TLSHandshakeMs:  ms,
		WSVerified:      edge.WSVerified,
		Score:           score,
		DPIActive:       edge.Mode == ModeTLSMicroFrag,
	}
}
