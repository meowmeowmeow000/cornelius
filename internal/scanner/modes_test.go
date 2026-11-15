package scanner

import (
	"testing"
	"time"
)

func TestScanModeTableInvariants(t *testing.T) {
	for name, m := range ScanModes {
		if m.Name != name {
			t.Errorf("ScanModes[%q].Name = %q", name, m.Name)
		}
		if m.Concurrency <= 0 {
			t.Errorf("%s: Concurrency %d, want > 0", name, m.Concurrency)
		}
		if m.PerProbeTimeout <= 0 {
			t.Errorf("%s: PerProbeTimeout %v, want > 0", name, m.PerProbeTimeout)
		}
		if m.Deadline <= m.PerProbeTimeout {
			t.Errorf("%s: Deadline %v must exceed PerProbeTimeout %v", name, m.Deadline, m.PerProbeTimeout)
		}
		if m.QuietWindow < 0 {
			t.Errorf("%s: QuietWindow %v, want >= 0", name, m.QuietWindow)
		}
		if m.TargetSuccesses < 0 {
			t.Errorf("%s: TargetSuccesses %d, want >= 0", name, m.TargetSuccesses)
		}
		if m.EarlyExitFirst && m.TargetSuccesses != 1 {
			t.Errorf("%s: EarlyExitFirst requires TargetSuccesses 1, got %d", name, m.TargetSuccesses)
		}
	}
	if len(ScanModes) != 5 {
		t.Fatalf("ScanModes has %d modes, want 5", len(ScanModes))
	}
	// Turbo is the fastest path, Ironclad the slowest and most careful.
	if ScanModeTurbo.Deadline >= ScanModeBalanced.Deadline {
		t.Errorf("Turbo deadline %v should be shorter than Balanced %v", ScanModeTurbo.Deadline, ScanModeBalanced.Deadline)
	}
	if ScanModeIronclad.Concurrency >= ScanModeBalanced.Concurrency {
		t.Errorf("Ironclad concurrency %d should be lower than Balanced %d", ScanModeIronclad.Concurrency, ScanModeBalanced.Concurrency)
	}
	if ScanModeThorough.TargetSuccesses != 0 {
		t.Errorf("Thorough TargetSuccesses = %d, want 0 (collect all)", ScanModeThorough.TargetSuccesses)
	}
}

func TestLookupScanMode(t *testing.T) {
	for _, name := range []string{"turbo", "balanced", "thorough", "verified", "ironclad"} {
		m, ok := LookupScanMode(name)
		if !ok {
			t.Fatalf("LookupScanMode(%q) = false, want true", name)
		}
		if m.Name != name {
			t.Fatalf("LookupScanMode(%q).Name = %q", name, m.Name)
		}
	}
	// Aether's aliases.
	if m, ok := LookupScanMode("stealth"); !ok || m.Name != "verified" {
		t.Errorf("LookupScanMode(stealth) = %v, %v; want verified, true", m.Name, ok)
	}
	if m, ok := LookupScanMode("quiet"); !ok || m.Name != "verified" {
		t.Errorf("LookupScanMode(quiet) = %v, %v; want verified, true", m.Name, ok)
	}
	if m, ok := LookupScanMode("real"); !ok || m.Name != "ironclad" {
		t.Errorf("LookupScanMode(real) = %v, %v; want ironclad, true", m.Name, ok)
	}
	if _, ok := LookupScanMode("no-such-mode"); ok {
		t.Error("LookupScanMode(no-such-mode) = true, want false")
	}
	if _, ok := LookupScanMode(""); ok {
		t.Error("LookupScanMode(\"\") = true, want false")
	}
}

func TestCapConcurrency(t *testing.T) {
	if got := CapConcurrency(0); got != 1 {
		t.Errorf("CapConcurrency(0) = %d, want 1", got)
	}
	if got := CapConcurrency(-5); got != 1 {
		t.Errorf("CapConcurrency(-5) = %d, want 1", got)
	}
	// The tier cap never exceeds the requested value or maxConcurrency,
	// and never drops below 1. On a small machine (this VM has few CPUs)
	// the tier cap is what binds, not maxConcurrency.
	if got := CapConcurrency(1000); got < 1 || got > maxConcurrency {
		t.Errorf("CapConcurrency(1000) = %d, want within [1, %d]", got, maxConcurrency)
	}
	// The tier cap never exceeds the requested value on a big machine,
	// and never exceeds maxConcurrency anywhere.
	if got := CapConcurrency(16); got > 16 || got < 1 {
		t.Errorf("CapConcurrency(16) = %d, want within [1,16]", got)
	}
	// Per-probe timeouts are sane relative to the verify timeout: a probe
	// must live long enough for at least two NOP resends.
	for name, m := range ScanModes {
		if m.PerProbeTimeout < 2*nopResend+time.Second {
			t.Errorf("%s: PerProbeTimeout %v too short for %d NOP resends", name, m.PerProbeTimeout, nopEchoesNeeded)
		}
	}
}
