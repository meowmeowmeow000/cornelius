package factory

import (
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"

	"cornelius/internal/telemetry"
)

// The tunnel speaks WebSocket over HTTP/1.1, so the TLS handshake must
// negotiate ALPN "http/1.1" — never "h2". Sending a raw HTTP/1.1
// WebSocket upgrade over an h2-negotiated session makes Cloudflare
// close the connection with an EOF before any 101, which is exactly
// what doctor reported on every edge (and what the scanner's
// ws_verified=false on every route meant): the handshake succeeded,
// the upgrade died.
//
// Setting Config.NextProtos to ["http/1.1"] does NOT do this. uTLS
// applies the fingerprint's ALPN extension after the config, and
// ALPNExtension.writeToUConn overwrites config.NextProtos with the
// fingerprint's list — Chrome 131/133 advertise ["h2", "http/1.1"],
// so the server picks h2 and the upgrade fails. The only way to force
// http/1.1 is to rewrite the ALPN extension inside the fingerprint
// spec itself, then apply that spec with HelloCustom.
//
// Verified live 2026-11-18: the same WebSocket upgrade to the same
// edge (104.18.0.2) returns 101 with -alpn http/1.1 and dies with
// "unexpected eof while reading" with -alpn h2.

// http11ALPN is the only ALPN the tunnel may offer.
var http11ALPN = []string{"http/1.1"}

// forceHTTP11Spec returns a copy of the fingerprint's ClientHelloSpec
// with its ALPN extension rewritten to http/1.1 only. The spec's
// extension pointers are replaced, never mutated in place, so no
// shared state leaks between dials.
func forceHTTP11Spec(id utls.ClientHelloID) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return spec, err
	}
	found := false
	for i, ext := range spec.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: append([]string(nil), http11ALPN...)}
			found = true
		}
	}
	if !found {
		spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: append([]string(nil), http11ALPN...)})
	}
	return spec, nil
}

// NewStealthUConn builds the uTLS connection for a tunnel dial, with
// ALPN forced to http/1.1 inside the fingerprint spec. Randomized
// fingerprints build their spec from cfg.NextProtos, so they take the
// normal path with NextProtos already set to http/1.1. Any other
// fingerprint that cannot be turned into a spec falls back to the
// plain UClient path (the old behaviour) rather than failing the dial.
func NewStealthUConn(conn net.Conn, cfg *utls.Config, id utls.ClientHelloID) (*utls.UConn, error) {
	cfg.NextProtos = append([]string(nil), http11ALPN...)
	if id == utls.HelloRandomized || id == utls.HelloRandomizedALPN || id == utls.HelloRandomizedNoALPN {
		return utls.UClient(conn, cfg, id), nil
	}
	spec, err := forceHTTP11Spec(id)
	if err != nil {
		telemetry.Log.Warn("Could not build http/1.1-only ClientHello spec, dialing with the fingerprint as-is", "id", id.Str(), "err", err.Error())
		return utls.UClient(conn, cfg, id), nil
	}
	uConn := utls.UClient(conn, cfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("apply http/1.1-only ClientHello preset: %w", err)
	}
	return uConn, nil
}
