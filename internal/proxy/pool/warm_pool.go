package pool

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"cornelius/internal/config"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/telemetry"
)

type WarmPool struct {
	mu          sync.RWMutex
	profile     *config.CombatProfile
	activeRoute config.RouteCandidate
	failovers   []config.RouteCandidate
	fragDelayMs int
	jitterMs    int
	allowInsec  bool
	echEnabled  bool
	defaultWS   string
	capacity    int
	pipes       chan net.Conn
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewWarmPool(profile *config.CombatProfile) *WarmPool {
	capSize := 3
	fragDelay := 2
	jitter := 2
	allowInsec := false
	echEnabled := false
	defaultWS := ""
	var primary config.RouteCandidate
	var failovers []config.RouteCandidate

	if profile != nil {
		primary = profile.PrimaryRoute
		failovers = append([]config.RouteCandidate(nil), profile.FailoverRoutes...)
		defaultWS = profile.Modules.StealthFactory.DefaultWSPath
		if profile.Modules.WarmPool.TargetCapacity > 0 {
			capSize = profile.Modules.WarmPool.TargetCapacity
		}
		if profile.Modules.StealthFactory.FragmentationDelayMs > 0 {
			fragDelay = profile.Modules.StealthFactory.FragmentationDelayMs
		}
		if profile.Modules.StealthFactory.JitterMs > 0 {
			jitter = profile.Modules.StealthFactory.JitterMs
		}
		allowInsec = profile.Modules.StealthFactory.AllowInsecureCerts
		echEnabled = profile.Modules.StealthFactory.ECHEnabled
	}

	return &WarmPool{
		profile:     profile,
		activeRoute: primary,
		failovers:   failovers,
		fragDelayMs: fragDelay,
		jitterMs:    jitter,
		allowInsec:  allowInsec,
		echEnabled:  echEnabled,
		defaultWS:   defaultWS,
		capacity:    capSize,
		pipes:       make(chan net.Conn, capSize),
	}
}

// Profile returns the profile the pool was built from, for health checks.
// It may be nil when the pool was built without one.
func (p *WarmPool) Profile() *config.CombatProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.profile
}

func (p *WarmPool) Capacity() uint64 {
	return uint64(p.capacity)
}

func (p *WarmPool) Start(parentCtx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(parentCtx)
	go p.maintainerLoop()
	return nil
}

func (p *WarmPool) maintainerLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.replenish()
		}
	}
}

func (p *WarmPool) replenish() {
	route := p.ActiveRoute()
	if route.TargetIP == "" || route.CleanSNI == "" {
		return
	}
	for len(p.pipes) < p.capacity {
		dialCtx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
		conn, err := p.dialCurrent(dialCtx)
		cancel()
		if err != nil {
			telemetry.DialFailures.Add(1)
			return
		}
		select {
		case p.pipes <- conn:
			telemetry.PoolHealthyPipes.Store(uint64(len(p.pipes)))
		default:
			_ = conn.Close()
			return
		}
	}
}

func (p *WarmPool) dialCurrent(ctx context.Context) (net.Conn, error) {
	p.mu.RLock()
	cfg := factory.StealthDialConfig{
		Route:       p.activeRoute,
		FragDelayMs: p.fragDelayMs,
		JitterMs:    p.jitterMs,
		AllowInsec:  p.allowInsec,
		WSPath:      p.defaultWS,
		ECHEnabled:  p.echEnabled,
	}
	p.mu.RUnlock()
	return factory.DialStealthTunnel(ctx, cfg)
}

func (p *WarmPool) Acquire(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-p.pipes:
		telemetry.PoolHealthyPipes.Store(uint64(len(p.pipes)))
		return conn, nil
	default:
		conn, err := p.dialCurrent(ctx)
		if err != nil {
			telemetry.DialFailures.Add(1)
			return nil, err
		}
		return conn, nil
	}
}

func (p *WarmPool) ActiveRoute() config.RouteCandidate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.activeRoute
}

func (p *WarmPool) AllRoutes() []config.RouteCandidate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]config.RouteCandidate, 0, 1+len(p.failovers))
	if p.activeRoute.TargetIP != "" {
		out = append(out, p.activeRoute)
	}
	for _, f := range p.failovers {
		if f.TargetIP != "" && f.TargetIP != p.activeRoute.TargetIP {
			out = append(out, f)
		}
	}
	return out
}

func (p *WarmPool) UpdateDecoyTTL(decoyTTL uint8, dpiHops int) {
	p.mu.Lock()
	p.activeRoute.DecoyTTL = decoyTTL
	p.activeRoute.DPIDistance = dpiHops
	for i := range p.failovers {
		p.failovers[i].DecoyTTL = decoyTTL
		p.failovers[i].DPIDistance = dpiHops
	}
	p.mu.Unlock()
}

func (p *WarmPool) ReplaceRoutesFromScan(primary config.RouteCandidate, failovers []config.RouteCandidate) {
	p.mu.Lock()
	old := p.activeRoute
	if primary.CleanSNI == "" {
		primary.CleanSNI = old.CleanSNI
	}
	if primary.SpoofSNI == "" {
		primary.SpoofSNI = old.SpoofSNI
	}
	p.activeRoute = primary
	p.failovers = append([]config.RouteCandidate(nil), failovers...)
	p.mu.Unlock()

	p.drainPool()
	telemetry.RouteRotations.Add(1)
	telemetry.RecordEvent("SCAN", "info", fmt.Sprintf("Loaded %d routes; active -> %s", 1+len(failovers), primary.TargetIP))
}

func (p *WarmPool) InjectEmergencyRoute(route config.RouteCandidate) {
	p.mu.Lock()
	old := p.activeRoute
	if route.CleanSNI == "" {
		route.CleanSNI = old.CleanSNI
	}
	if route.SpoofSNI == "" {
		route.SpoofSNI = old.SpoofSNI
	}
	if route.SNISPFDirection == "" {
		route.SNISPFDirection = old.SNISPFDirection
	}
	if route.WSPath == "" {
		route.WSPath = old.WSPath
	}
	if route.StealthMode == "" {
		route.StealthMode = old.StealthMode
	}
	if route.Fingerprint == "" {
		route.Fingerprint = old.Fingerprint
	}
	if route.ExpectedTTL == 0 {
		route.ExpectedTTL = old.ExpectedTTL
	}
	if route.DecoyTTL == 0 {
		route.DecoyTTL = old.DecoyTTL
	}
	if route.TargetPort == 0 {
		route.TargetPort = 443
	}

	// Keep previous active route in the failover ring if switching to a new IP.
	if old.TargetIP != "" && old.TargetIP != route.TargetIP {
		filtered := make([]config.RouteCandidate, 0, len(p.failovers)+1)
		for _, f := range p.failovers {
			if f.TargetIP != route.TargetIP && f.TargetIP != old.TargetIP {
				filtered = append(filtered, f)
			}
		}
		p.failovers = append([]config.RouteCandidate{old}, filtered...)
	}
	p.activeRoute = route
	p.mu.Unlock()

	p.drainPool()
	telemetry.RouteRotations.Add(1)
	telemetry.IPCOverrides.Add(1)
	telemetry.RecordEvent("IPC", "info", fmt.Sprintf("Hot-swapped edge -> %s (%s)", route.TargetIP, route.SNISPFDirection))
	telemetry.Log.Info("Hot-swapped active route",
		slog.String("target_ip", route.TargetIP),
		slog.String("direction", route.SNISPFDirection),
		slog.String("spoof_sni", route.SpoofSNI),
		slog.String("worker_sni", route.CleanSNI))
}

func (p *WarmPool) SetSNISPFDirection(direction, spoofSNI string) {
	p.mu.Lock()
	if direction != "" {
		p.activeRoute.SNISPFDirection = direction
	}
	if spoofSNI != "" {
		p.activeRoute.SpoofSNI = spoofSNI
	}
	active := p.activeRoute
	p.mu.Unlock()

	p.drainPool()
	telemetry.IPCOverrides.Add(1)
	telemetry.RecordEvent("IPC", "info", fmt.Sprintf("SNISPF direction -> %s", active.SNISPFDirection))
}

func (p *WarmPool) RotateToNextFailover() (config.RouteCandidate, bool) {
	p.mu.Lock()
	if len(p.failovers) == 0 {
		p.mu.Unlock()
		return config.RouteCandidate{}, false
	}
	old := p.activeRoute
	next := p.failovers[0]
	p.failovers = append(p.failovers[1:], old)
	p.activeRoute = next
	p.mu.Unlock()

	p.drainPool()
	telemetry.RouteRotations.Add(1)
	telemetry.RecordEvent("POOL", "warn", fmt.Sprintf("Rotated edge %s -> %s", old.TargetIP, next.TargetIP))
	return next, true
}

func (p *WarmPool) EscalateStealthMode(mode string, fragDelayMs, jitterMs int) {
	p.mu.Lock()
	if mode != "" {
		p.activeRoute.StealthMode = mode
	}
	if fragDelayMs > 0 {
		p.fragDelayMs = fragDelayMs
	}
	if jitterMs > 0 {
		p.jitterMs = jitterMs
	}
	curMode := p.activeRoute.StealthMode
	p.mu.Unlock()

	p.drainPool()
	telemetry.ModeEscalations.Add(1)
	telemetry.RecordEvent("STEALTH", "warn", fmt.Sprintf("Escalated framing -> %s", curMode))
}

func (p *WarmPool) drainPool() {
	for {
		select {
		case c := <-p.pipes:
			_ = c.Close()
		default:
			telemetry.PoolHealthyPipes.Store(0)
			return
		}
	}
}

func (p *WarmPool) HandleLocalConnection(clientConn net.Conn) {
	defer clientConn.Close()
	telemetry.ActiveStreams.Add(1)
	defer telemetry.ActiveStreams.Add(^uint64(0))

	ctx, cancel := context.WithTimeout(p.ctx, 8*time.Second)
	upstream, err := p.Acquire(ctx)
	cancel()
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, clientConn)
		if n > 0 {
			telemetry.TotalBytesTx.Add(uint64(n))
		}
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, upstream)
		if n > 0 {
			telemetry.TotalBytesRx.Add(uint64(n))
		}
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func (p *WarmPool) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.drainPool()
}
