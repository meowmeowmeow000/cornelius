package scanner

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestExpandCIDRIncludesIPv4NetworkAndBroadcast(t *testing.T) {
	got, err := ExpandCIDR("192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandCIDR() = %v, want %v", got, want)
	}
}

func TestExpandCIDRIPv6(t *testing.T) {
	got, err := ExpandCIDR("2001:db8::/126")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandCIDR() = %v, want %v", got, want)
	}
}

func TestExpandCIDRRejectsOversizedRange(t *testing.T) {
	if _, err := ExpandCIDR("192.0.2.0/23"); err == nil {
		t.Fatal("expected oversized CIDR to be rejected")
	}
}

func TestExpandCIDRHandlesSingleAddressRanges(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		want []string
	}{
		{"192.0.2.10/32", []string{"192.0.2.10"}},
		{"2001:db8::1/128", []string{"2001:db8::1"}},
		{"192.0.2.0/31", []string{"192.0.2.0", "192.0.2.1"}},
	} {
		got, err := ExpandCIDR(tc.cidr)
		if err != nil {
			t.Fatalf("ExpandCIDR(%q) returned error: %v", tc.cidr, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("ExpandCIDR(%q) = %v, want %v", tc.cidr, got, tc.want)
		}
	}
}

// TestRunCancelsPromptly proves a cancelled context tears the scan down
// fast instead of letting in-flight probes run to their per-probe
// timeout — and that no worker goroutine hangs on a full results
// channel after the collector stops listening.
func TestRunCancelsPromptly(t *testing.T) {
	// A listener that accepts TCP but never speaks TLS: probes hang in
	// the handshake until the per-probe timeout or cancellation. Needs
	// :443, which needs privilege — skip where it cannot bind.
	ln, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:443: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				<-done // hold the connection open; never speak TLS
			}(c)
		}
	}()

	cart := NewCartographer(2, 30*time.Second)
	cart.Mode = ScanMode{
		Name:            "cancel-test",
		Concurrency:     2,
		PerProbeTimeout: 30 * time.Second,
		Deadline:        60 * time.Second,
		TargetSuccesses: 6,
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	rep := cart.Run(ctx, []string{"127.0.0.1"}, "worker.example.workers.dev")
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("Run took %v after cancellation; want it to return promptly (<5s)", elapsed)
	}
	if rep.SuccessfulTLS != 0 {
		t.Fatalf("SuccessfulTLS = %d, want 0 (no handshake ever completed)", rep.SuccessfulTLS)
	}
}
