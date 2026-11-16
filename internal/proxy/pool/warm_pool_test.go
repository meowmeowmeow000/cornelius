package pool

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cornelius/internal/config"
	"cornelius/internal/mockworker"
	"cornelius/internal/proxy/factory"
	"cornelius/internal/telemetry"
)

func testRoute(ip string) config.RouteCandidate {
	return config.RouteCandidate{
		TargetIP:        ip,
		TargetPort:      443,
		SNISPFDirection: config.SNISPFDirectionLegacy,
		CleanSNI:        "worker.test",
		WSPath:          "/secret-knock-99",
		StealthMode:     factory.ModeTLSFrag,
		ExpectedTTL:     55,
	}
}

func TestNewWarmPoolDefaults(t *testing.T) {
	p := NewWarmPool(nil)
	if p.Capacity() != 3 {
		t.Fatalf("capacity = %d, want 3", p.Capacity())
	}
	if p.fragDelayMs != 2 || p.jitterMs != 2 {
		t.Fatalf("frag/jitter = %d/%d, want 2/2", p.fragDelayMs, p.jitterMs)
	}
	if p.allowInsec || p.echEnabled || p.echRequired {
		t.Fatal("nil profile must leave ECH and insecure off")
	}
	if got := p.ActiveRoute(); got.TargetIP != "" {
		t.Fatalf("active route = %+v, want empty", got)
	}
	if p.Profile() != nil {
		t.Fatal("Profile() must be nil for a pool built without one")
	}
}

func TestNewWarmPoolFromProfile(t *testing.T) {
	failovers := []config.RouteCandidate{testRoute("10.0.0.2")}
	prof := &config.CombatProfile{
		PrimaryRoute:   testRoute("10.0.0.1"),
		FailoverRoutes: failovers,
	}
	prof.Modules.StealthFactory.DefaultWSPath = "/secret-knock-99"
	prof.Modules.StealthFactory.FragmentationDelayMs = 5
	prof.Modules.StealthFactory.JitterMs = 7
	prof.Modules.StealthFactory.AllowInsecureCerts = true
	prof.Modules.StealthFactory.ECHEnabled = true
	prof.Modules.StealthFactory.ECHRequired = true
	prof.Modules.StealthFactory.ECHConfigB64 = "cGFzdGVk"
	prof.Modules.WarmPool.TargetCapacity = 6

	p := NewWarmPool(prof)
	if p.Capacity() != 6 {
		t.Fatalf("capacity = %d, want 6", p.Capacity())
	}
	if p.fragDelayMs != 5 || p.jitterMs != 7 {
		t.Fatalf("frag/jitter = %d/%d, want 5/7", p.fragDelayMs, p.jitterMs)
	}
	if !p.allowInsec || !p.echEnabled || !p.echRequired || p.echConfigB64 != "cGFzdGVk" {
		t.Fatal("ECH / insecure settings were not copied from the profile")
	}
	if p.defaultWS != "/secret-knock-99" {
		t.Fatalf("defaultWS = %q", p.defaultWS)
	}
	if p.Profile() != prof {
		t.Fatal("Profile() must return the profile the pool was built from")
	}
	// The pool copies the failover list: mutating the caller's slice
	// afterwards must not change the pool's routes.
	failovers[0].TargetIP = "10.9.9.9"
	if routes := p.AllRoutes(); len(routes) != 2 || routes[1].TargetIP != "10.0.0.2" {
		t.Fatalf("failover list was not copied, routes = %+v", routes)
	}
}

func TestAllRoutesSkipsEmptyAndDedupes(t *testing.T) {
	prof := &config.CombatProfile{
		PrimaryRoute: testRoute("10.0.0.1"),
		FailoverRoutes: []config.RouteCandidate{
			testRoute("10.0.0.1"), // same IP as active: deduped
			{TargetIP: ""},        // empty: skipped
			testRoute("10.0.0.2"),
			testRoute("10.0.0.2"), // duplicate failover: kept once per entry
		},
	}
	p := NewWarmPool(prof)
	routes := p.AllRoutes()
	if len(routes) != 3 {
		t.Fatalf("AllRoutes() = %d routes, want 3 (active + 10.0.0.2 twice)", len(routes))
	}
	if routes[0].TargetIP != "10.0.0.1" || routes[1].TargetIP != "10.0.0.2" {
		t.Fatalf("unexpected route order: %+v", routes)
	}
}

func TestReplaceRoutesFromScanFillsBlanksAndDrains(t *testing.T) {
	p := NewWarmPool(&config.CombatProfile{PrimaryRoute: testRoute("10.0.0.1")})
	seeded, peer := net.Pipe()
	p.pipes <- seeded

	before := telemetry.RouteRotations.Load()
	primary := config.RouteCandidate{TargetIP: "10.0.0.9", StealthMode: factory.ModeTLSMicroFrag}
	p.ReplaceRoutesFromScan(primary, []config.RouteCandidate{testRoute("10.0.0.8")})

	active := p.ActiveRoute()
	if active.TargetIP != "10.0.0.9" {
		t.Fatalf("active = %s, want 10.0.0.9", active.TargetIP)
	}
	// Missing SNI fields are inherited from the old route, not left blank.
	if active.CleanSNI != "worker.test" || active.SpoofSNI != "" {
		t.Fatalf("SNI fields not inherited: %+v", active)
	}
	if len(p.pipes) != 0 {
		t.Fatal("replace must drain the pool: stale pipes speak the old route")
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("seeded pipe was not closed by the drain, err = %v", err)
	}
	if telemetry.RouteRotations.Load() != before+1 {
		t.Fatal("replace must record one route rotation")
	}
	if routes := p.AllRoutes(); len(routes) != 2 {
		t.Fatalf("AllRoutes() = %d, want 2", len(routes))
	}
}

func TestInjectEmergencyRouteFillsBlanksAndKeepsOldAsFailover(t *testing.T) {
	p := NewWarmPool(&config.CombatProfile{
		PrimaryRoute:   testRoute("10.0.0.1"),
		FailoverRoutes: []config.RouteCandidate{testRoute("10.0.0.2")},
	})
	before := telemetry.IPCOverrides.Load()
	p.InjectEmergencyRoute(config.RouteCandidate{TargetIP: "10.0.0.9"})

	active := p.ActiveRoute()
	if active.TargetIP != "10.0.0.9" {
		t.Fatalf("active = %s, want 10.0.0.9", active.TargetIP)
	}
	if active.CleanSNI != "worker.test" || active.WSPath != "/secret-knock-99" ||
		active.StealthMode != factory.ModeTLSFrag || active.ExpectedTTL != 55 ||
		active.TargetPort != 443 || active.SNISPFDirection != config.SNISPFDirectionLegacy {
		t.Fatalf("blanks not inherited from the old route: %+v", active)
	}
	routes := p.AllRoutes()
	if len(routes) != 3 || routes[1].TargetIP != "10.0.0.1" || routes[2].TargetIP != "10.0.0.2" {
		t.Fatalf("old route must become the first failover, routes = %+v", routes)
	}
	if telemetry.IPCOverrides.Load() != before+1 {
		t.Fatal("injection must record one IPC override")
	}
}

func TestInjectEmergencyRouteSameIPDoesNotDuplicate(t *testing.T) {
	p := NewWarmPool(&config.CombatProfile{
		PrimaryRoute:   testRoute("10.0.0.1"),
		FailoverRoutes: []config.RouteCandidate{testRoute("10.0.0.2")},
	})
	p.InjectEmergencyRoute(config.RouteCandidate{TargetIP: "10.0.0.1", StealthMode: factory.ModeTLSMicroFrag})
	routes := p.AllRoutes()
	if len(routes) != 2 {
		t.Fatalf("same-IP injection must not duplicate the route, routes = %+v", routes)
	}
	if routes[0].StealthMode != factory.ModeTLSMicroFrag {
		t.Fatalf("mode = %q, want tls_micro_frag", routes[0].StealthMode)
	}
}

func TestRotateToNextFailover(t *testing.T) {
	p := NewWarmPool(&config.CombatProfile{
		PrimaryRoute:   testRoute("10.0.0.1"),
		FailoverRoutes: []config.RouteCandidate{testRoute("10.0.0.2"), testRoute("10.0.0.3")},
	})
	next, ok := p.RotateToNextFailover()
	if !ok || next.TargetIP != "10.0.0.2" {
		t.Fatalf("first rotation = (%v, %v), want (10.0.0.2, true)", next.TargetIP, ok)
	}
	if got := p.ActiveRoute().TargetIP; got != "10.0.0.2" {
		t.Fatalf("active = %s, want 10.0.0.2", got)
	}
	// The old route goes to the back of the ring, so rotation cycles.
	next, _ = p.RotateToNextFailover()
	if next.TargetIP != "10.0.0.3" {
		t.Fatalf("second rotation = %s, want 10.0.0.3", next.TargetIP)
	}
	next, _ = p.RotateToNextFailover()
	if next.TargetIP != "10.0.0.1" {
		t.Fatalf("third rotation = %s, want 10.0.0.1 (cycle)", next.TargetIP)
	}
}

func TestRotateToNextFailoverEmpty(t *testing.T) {
	p := NewWarmPool(&config.CombatProfile{PrimaryRoute: testRoute("10.0.0.1")})
	if _, ok := p.RotateToNextFailover(); ok {
		t.Fatal("rotation with no failovers must report false")
	}
	if got := p.ActiveRoute().TargetIP; got != "10.0.0.1" {
		t.Fatalf("active changed to %s", got)
	}
}

func TestEscalateStealthMode(t *testing.T) {
	p := NewWarmPool(&config.CombatProfile{PrimaryRoute: testRoute("10.0.0.1")})
	before := telemetry.ModeEscalations.Load()
	p.EscalateStealthMode(factory.ModeTLSMicroFrag, 3, 3)
	if got := p.ActiveRoute().StealthMode; got != factory.ModeTLSMicroFrag {
		t.Fatalf("mode = %q, want tls_micro_frag", got)
	}
	if p.fragDelayMs != 3 || p.jitterMs != 3 {
		t.Fatalf("frag/jitter = %d/%d, want 3/3", p.fragDelayMs, p.jitterMs)
	}
	if telemetry.ModeEscalations.Load() != before+1 {
		t.Fatal("escalation must record one mode escalation")
	}
	// Zero means "leave it": delays and mode keep their values.
	p.EscalateStealthMode("", 0, 0)
	if got := p.ActiveRoute().StealthMode; got != factory.ModeTLSMicroFrag {
		t.Fatalf("empty escalation changed the mode to %q", got)
	}
	if p.fragDelayMs != 3 || p.jitterMs != 3 {
		t.Fatalf("zero delays changed frag/jitter to %d/%d", p.fragDelayMs, p.jitterMs)
	}
	// Negative delays are also ignored.
	p.EscalateStealthMode("", -1, -1)
	if p.fragDelayMs != 3 || p.jitterMs != 3 {
		t.Fatalf("negative delays changed frag/jitter to %d/%d", p.fragDelayMs, p.jitterMs)
	}
}

func TestSetSNISPFDirectionKeepsBlanks(t *testing.T) {
	p := NewWarmPool(&config.CombatProfile{PrimaryRoute: testRoute("10.0.0.1")})
	p.SetSNISPFDirection("", "")
	if got := p.ActiveRoute().SNISPFDirection; got != config.SNISPFDirectionLegacy {
		t.Fatalf("empty set changed the direction to %q", got)
	}
	p.SetSNISPFDirection(config.SNISPFDirectionFronting, "cdn.test")
	active := p.ActiveRoute()
	if active.SNISPFDirection != config.SNISPFDirectionFronting || active.SpoofSNI != "cdn.test" {
		t.Fatalf("direction/spoof = %q/%q", active.SNISPFDirection, active.SpoofSNI)
	}
}

func TestUpdateDecoyTTLAppliesToAllRoutes(t *testing.T) {
	p := NewWarmPool(&config.CombatProfile{
		PrimaryRoute:   testRoute("10.0.0.1"),
		FailoverRoutes: []config.RouteCandidate{testRoute("10.0.0.2")},
	})
	p.UpdateDecoyTTL(3, 9)
	if active := p.ActiveRoute(); active.DecoyTTL != 3 || active.DPIDistance != 9 {
		t.Fatalf("active decoy = %d/%d, want 3/9", active.DecoyTTL, active.DPIDistance)
	}
	if f := p.AllRoutes()[1]; f.DecoyTTL != 3 || f.DPIDistance != 9 {
		t.Fatalf("failover decoy = %d/%d, want 3/9", f.DecoyTTL, f.DPIDistance)
	}
}

func TestAcquireSeededPipe(t *testing.T) {
	p := NewWarmPool(nil)
	a, b := net.Pipe()
	defer b.Close()
	p.pipes <- a
	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn != a {
		t.Fatal("Acquire must return the seeded pipe")
	}
	if telemetry.PoolHealthyPipes.Load() != 0 {
		t.Fatal("acquiring the only pipe must leave the pool empty")
	}
}

func TestAcquireColdDialFailsFast(t *testing.T) {
	// Nothing listens on 127.0.0.1:1: the cold-dial fallback must fail
	// promptly instead of hanging or returning a dead pipe.
	p := NewWarmPool(&config.CombatProfile{PrimaryRoute: testRoute("127.0.0.1")})
	// Point the route at the closed port.
	route := p.ActiveRoute()
	route.TargetPort = 1
	route.CleanSNI = "localhost"
	p.ReplaceRoutesFromScan(route, nil)
	before := telemetry.DialFailures.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := p.Acquire(ctx)
	if err == nil {
		t.Fatal("Acquire with no pipes and an unreachable edge must fail")
	}
	if telemetry.DialFailures.Load() != before+1 {
		t.Fatal("failed cold dial must record one dial failure")
	}
}

func TestHandleLocalConnectionEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	upstream, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p := NewWarmPool(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.pipes <- upstream

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		p.HandleLocalConnection(server)
		close(done)
	}()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleLocalConnection did not return after the client closed")
	}
}

func TestHandleLocalConnectionWithoutStart(t *testing.T) {
	// Regression test: HandleLocalConnection used p.ctx, which was nil
	// until Start() — a never-started pool panicked on the first
	// connection. NewWarmPool now initialises the context, so the call
	// must work (and echo) without Start(), exactly like the started pool.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	upstream, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p := NewWarmPool(nil)
	// NOTE: Start() is deliberately never called.
	defer p.Close()
	p.pipes <- upstream

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		p.HandleLocalConnection(server)
		close(done)
	}()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleLocalConnection did not return after the client closed")
	}
}

func TestCloseDrainsPool(t *testing.T) {
	p := NewWarmPool(nil)
	a, b := net.Pipe()
	defer b.Close()
	p.pipes <- a
	p.Close()
	if len(p.pipes) != 0 {
		t.Fatal("Close must drain the pool")
	}
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("seeded pipe was not closed, err = %v", err)
	}
}

func TestPoolReplenishesAgainstMockWorker(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("mock-worker-ok"))
	}))
	defer target.Close()
	mock, err := mockworker.Start(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	prof := &config.CombatProfile{
		Modules: config.ModulesConfig{
			StealthFactory: config.StealthFactoryConfig{
				DefaultWSPath:      mockworker.DefaultWSPath,
				AllowInsecureCerts: true,
			},
			WarmPool: config.WarmPoolConfig{TargetCapacity: 2},
		},
		PrimaryRoute: config.RouteCandidate{
			TargetIP:    "127.0.0.1",
			TargetPort:  uint16(mock.Port()),
			CleanSNI:    "localhost",
			StealthMode: factory.ModeTLSFrag,
			WSPath:      mockworker.DefaultWSPath,
		},
	}
	p := NewWarmPool(prof)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	before := telemetry.PoolHealthyPipes.Load()
	deadline := time.Now().Add(10 * time.Second)
	for telemetry.PoolHealthyPipes.Load() <= before {
		if time.Now().After(deadline) {
			t.Fatal("maintainer did not warm any pipes against the mock Worker")
		}
		time.Sleep(50 * time.Millisecond)
	}
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire after warm-up: %v", err)
	}
	_ = conn.Close()
}
