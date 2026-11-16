package scanner

import (
	"runtime"
	"time"
)

// ScanMode is one row of the scan strategy table, borrowed from Aether's
// scanner (CluvexStudio/Aether, prober.rs ScanMode::strategy). Cornelius
// used to have exactly one fixed scan; modes give it a fast path (Turbo),
// a careful path (Ironclad), and a sensible default (Balanced).
//
//   - Concurrency: probes in flight at once.
//   - PerProbeTimeout: budget for one candidate (dial + TLS + WS verify).
//   - Deadline: overall budget for the whole scan. The caller's context
//     still bounds the scan — whichever deadline fires first wins.
//   - QuietWindow: after TargetSuccesses is reached, keep collecting for
//     this long in case a faster gateway shows up, then finalize.
//   - TargetSuccesses: stop feeding new candidates once this many
//     succeeded. 0 means collect everything (Thorough).
//   - EarlyExitFirst: return the first successful candidate immediately,
//     no ranking (Turbo).
type ScanMode struct {
	Name            string
	Concurrency     int
	PerProbeTimeout time.Duration
	Deadline        time.Duration
	QuietWindow     time.Duration
	TargetSuccesses int
	EarlyExitFirst  bool
}

var (
	// ScanModeTurbo takes the first working gateway and stops. For when
	// the daemon just needs to get online.
	ScanModeTurbo = ScanMode{
		Name:            "turbo",
		Concurrency:     20,
		PerProbeTimeout: 6 * time.Second,
		Deadline:        45 * time.Second,
		QuietWindow:     0,
		TargetSuccesses: 1,
		EarlyExitFirst:  true,
	}

	// ScanModeBalanced is the default: collect 6 successes, then wait a
	// 20 s quiet window for a faster one, then pick the lowest RTT.
	ScanModeBalanced = ScanMode{
		Name:            "balanced",
		Concurrency:     16,
		PerProbeTimeout: 6 * time.Second,
		Deadline:        120 * time.Second,
		QuietWindow:     20 * time.Second,
		TargetSuccesses: 6,
	}

	// ScanModeThorough collects everything in the candidate list. Slow;
	// the lab mode.
	ScanModeThorough = ScanMode{
		Name:            "thorough",
		Concurrency:     20,
		PerProbeTimeout: 10 * time.Second,
		Deadline:        300 * time.Second,
		QuietWindow:     30 * time.Second,
		TargetSuccesses: 0,
	}

	// ScanModeVerified is Balanced with a shorter quiet window and a
	// lower target — the careful-but-not-slow path.
	ScanModeVerified = ScanMode{
		Name:            "verified",
		Concurrency:     16,
		PerProbeTimeout: 5 * time.Second,
		Deadline:        60 * time.Second,
		QuietWindow:     8 * time.Second,
		TargetSuccesses: 4,
	}

	// ScanModeIronclad goes slow and careful: few concurrent probes, long
	// timeouts, small target. For when nothing else works.
	ScanModeIronclad = ScanMode{
		Name:            "ironclad",
		Concurrency:     4,
		PerProbeTimeout: 15 * time.Second,
		Deadline:        180 * time.Second,
		QuietWindow:     15 * time.Second,
		TargetSuccesses: 3,
	}
)

// ScanModes is the full strategy table, keyed by mode name.
var ScanModes = map[string]ScanMode{
	ScanModeTurbo.Name:    ScanModeTurbo,
	ScanModeBalanced.Name: ScanModeBalanced,
	ScanModeThorough.Name: ScanModeThorough,
	ScanModeVerified.Name: ScanModeVerified,
	ScanModeIronclad.Name: ScanModeIronclad,
}

// LookupScanMode returns the mode for a name, or false when unknown.
// "stealth" and "quiet" are Aether's aliases for Verified; "real" and
// "guaranteed" are its aliases for Ironclad.
func LookupScanMode(name string) (ScanMode, bool) {
	if m, ok := ScanModes[name]; ok {
		return m, true
	}
	switch name {
	case "stealth", "quiet", "proven":
		return ScanModeVerified, true
	case "real", "guaranteed":
		return ScanModeIronclad, true
	}
	return ScanMode{}, false
}

// CapConcurrency applies the resource tier to a mode's concurrency, in
// the spirit of Aether's sysprofile caps (Low 4 / Medium 10 / High
// unlimited). Ours is CPU-only — reading total RAM portably is not worth
// the dependency — and the hard ceiling stays maxConcurrency.
func CapConcurrency(want int) int {
	if want <= 0 {
		return 1
	}
	cpus := runtime.NumCPU()
	switch {
	case cpus <= 2:
		if want > 4 {
			want = 4
		}
	case cpus <= 4:
		if want > 10 {
			want = 10
		}
	}
	if want > maxConcurrency {
		want = maxConcurrency
	}
	return want
}
