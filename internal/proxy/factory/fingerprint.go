package factory

import (
	"crypto/rand"
	"math/big"

	utls "github.com/refraction-networking/utls"
)

// Fingerprint depth: what the ClientHello says about us, and how stable
// that story is across connections.
//
// The Chrome fingerprint Cornelius uses is already deep, because uTLS
// 1.8.2's HelloChrome specs carry it: extension order is shuffled on
// every handshake (ShuffleChromeTLSExtensions, the way BoringSSL does it),
// a GREASE ECH extension is sent when no real ECH config is offered, and
// the key shares include the post-quantum X25519MLKEM768 group. Those are
// locked in by tests in fingerprint_test.go so a future uTLS upgrade
// cannot silently drop them.
//
// The one thing the spec cannot do on its own is vary across connections:
// HelloChrome_Auto is always Chrome 133. A single static version for
// every flow would be the more learnable fingerprint, so the dial path
// rotates between recent Chrome releases when the route asks for the
// default. A real user's Chrome updates often and a household runs
// several versions, so version diversity across connections is normal
// traffic — and an explicit fingerprint pin is always honoured exactly.

// chromeVersions are the Chrome releases the dialer rotates between for
// the default fingerprint.
var chromeVersions = []utls.ClientHelloID{
	utls.HelloChrome_131,
	utls.HelloChrome_133,
}

// PickFingerprint resolves a route's fingerprint string to the
// ClientHelloID for one dial. Explicit fingerprints — including
// "chrome_131" and "chrome_133" pins — are honoured exactly via
// ResolveFingerprint; the default ("", "chrome_auto") rotates between
// recent Chrome releases.
func PickFingerprint(fp string) utls.ClientHelloID {
	switch fp {
	case "", "chrome_auto":
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chromeVersions))))
		if err != nil {
			return utls.HelloChrome_Auto
		}
		return chromeVersions[n.Int64()]
	default:
		return ResolveFingerprint(fp)
	}
}
