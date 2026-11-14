package main

import (
	"fmt"
	"strings"
)

// renderDoctorLines turns daemon health checks into the plain-language
// lines of the doctor panel. Pure function, unit-tested; the panel itself
// is rendered by the main View through the standard modal box.
func renderDoctorLines(checks []HealthCheck, snap VitalSnapshot, innerW int) []string {
	if len(checks) == 0 {
		return []string{"  No health data yet — the daemon did not answer the doctor check."}
	}
	var lines []string
	fails, warns := 0, 0
	for _, c := range checks {
		mark := "[ok]"
		switch c.Status {
		case "warn":
			mark = "[!!]"
			warns++
		case "fail":
			mark = "[xx]"
			fails++
		}
		text := fmt.Sprintf("  %s %s", mark, c.Name)
		if c.Detail != "" {
			text += " — " + c.Detail
		}
		lines = append(lines, truncateText(text, innerW))
	}
	lines = append(lines, strings.Repeat("─", maxInt(8, innerW-2)))
	summary := "  Doctor: all green."
	switch {
	case fails > 0:
		summary = fmt.Sprintf("  Doctor: %d check(s) failing — fix the profile and restart the daemon.", fails)
	case warns > 0:
		summary = fmt.Sprintf("  Doctor: %d warning(s) — healthy, but worth a look.", warns)
	}
	lines = append(lines, summary)
	live := fmt.Sprintf("  Live: %d warm pipe(s) · %d active stream(s) · %d dial failure(s) since start",
		snap.WarmPipes, snap.ActiveStreams, snap.DialFailures)
	lines = append(lines, truncateText(live, innerW))
	return lines
}
