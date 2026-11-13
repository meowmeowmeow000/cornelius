package factory

import (
	"testing"

	"cornelius/internal/config"
)

func TestResolveSNIDirectionHonorsExplicitFrontingMode(t *testing.T) {
	route := config.RouteCandidate{
		CleanSNI:    "worker.example.com",
		StealthMode: ModeSNIFront,
	}

	dir, outer, inner := ResolveSNIDirection(route)
	if dir != config.SNISPFDirectionFronting {
		t.Fatalf("ResolveSNIDirection() direction = %q, want %q", dir, config.SNISPFDirectionFronting)
	}
	if outer != route.CleanSNI {
		t.Fatalf("ResolveSNIDirection() outerSNI = %q, want %q", outer, route.CleanSNI)
	}
	if inner != route.CleanSNI {
		t.Fatalf("ResolveSNIDirection() innerHost = %q, want %q", inner, route.CleanSNI)
	}
}

func TestResolveSNIDirectionUsesSpoofSNIWhenPresent(t *testing.T) {
	route := config.RouteCandidate{
		CleanSNI: "worker.example.com",
		SpoofSNI: "cdn.example.net",
	}

	dir, outer, inner := ResolveSNIDirection(route)
	if dir != config.SNISPFDirectionFronting {
		t.Fatalf("ResolveSNIDirection() direction = %q, want %q", dir, config.SNISPFDirectionFronting)
	}
	if outer != route.SpoofSNI {
		t.Fatalf("ResolveSNIDirection() outerSNI = %q, want %q", outer, route.SpoofSNI)
	}
	if inner != route.CleanSNI {
		t.Fatalf("ResolveSNIDirection() innerHost = %q, want %q", inner, route.CleanSNI)
	}
}
