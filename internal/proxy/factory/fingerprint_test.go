package factory

import (
	"fmt"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func extensionOrder(spec utls.ClientHelloSpec) []string {
	var out []string
	for _, ext := range spec.Extensions {
		out = append(out, fmt.Sprintf("%T", ext))
	}
	return out
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The Chrome spec must shuffle its extension order on every build — that
// is BoringSSL behaviour, and a fixed order would be a learnable
// fingerprint. Two fresh specs should (almost always) disagree.
func TestChromeSpecShufflesPerHandshake(t *testing.T) {
	seenSame := 0
	for i := 0; i < 5; i++ {
		a, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if err != nil {
			t.Fatal(err)
		}
		b, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if err != nil {
			t.Fatal(err)
		}
		if sameOrder(extensionOrder(a), extensionOrder(b)) {
			seenSame++
		}
	}
	if seenSame == 5 {
		t.Fatal("five consecutive Chrome specs had identical extension order — the per-handshake shuffle is not running")
	}
}

// When no real ECH config is offered, the hello must still carry a GREASE
// ECH extension, the way Chrome does — otherwise the absence of any ECH
// extension is itself a signal.
func TestChromeSpecHasGREASEECH(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.GREASEEncryptedClientHelloExtension); ok {
			return
		}
	}
	t.Fatal("Chrome spec has no GREASE ECH extension")
}

// The Chrome spec must offer the post-quantum X25519MLKEM768 key share —
// a Chrome 133 hello without it would stand out.
func TestChromeSpecOffersPostQuantumKeyShare(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range spec.Extensions {
		ks, ok := ext.(*utls.KeyShareExtension)
		if !ok {
			continue
		}
		for _, share := range ks.KeyShares {
			if share.Group == utls.X25519MLKEM768 {
				return
			}
		}
	}
	t.Fatal("Chrome spec offers no X25519MLKEM768 key share")
}

func TestPickFingerprintRotatesChromeVersions(t *testing.T) {
	seen := map[utls.ClientHelloID]bool{}
	for i := 0; i < 20; i++ {
		seen[PickFingerprint("chrome_auto")] = true
	}
	if !seen[utls.HelloChrome_131] || !seen[utls.HelloChrome_133] {
		t.Fatalf("expected rotation across Chrome 131 and 133, saw %v", seen)
	}
	// An empty fingerprint is the default too, so it must also rotate
	// rather than pinning to one version.
	empty := PickFingerprint("")
	if empty != utls.HelloChrome_131 && empty != utls.HelloChrome_133 {
		t.Fatalf("PickFingerprint(\"\") = %v, want a Chrome version", empty)
	}
}

func TestPickFingerprintHonorsExplicit(t *testing.T) {
	cases := map[string]utls.ClientHelloID{
		"firefox_auto": utls.HelloFirefox_Auto,
		"ios_auto":     utls.HelloIOS_Auto,
		"edge_auto":    utls.HelloEdge_Auto,
		"randomized":   utls.HelloRandomized,
		"chrome_131":   utls.HelloChrome_131,
		"chrome_133":   utls.HelloChrome_133,
	}
	for fp, want := range cases {
		if got := PickFingerprint(fp); got != want {
			t.Fatalf("PickFingerprint(%q) = %v, want %v", fp, got, want)
		}
	}
}
