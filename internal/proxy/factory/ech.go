package factory

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Encrypted ClientHello (ECH) hides the SNI entirely: the outer ClientHello
// carries only the ECH public name (cloudflare-ech.com) while the real
// Worker hostname travels encrypted inside it. Fragmentation hides the SNI
// from a DPI that reads one packet at a time; ECH hides it from one that
// reassembles, too.
//
// The ECH config comes from the DNS HTTPS record for the Worker host,
// fetched over DNS-over-HTTPS so the ISP cannot see or poison the query.
// uTLS v1.8.2 implements the client side (Config.EncryptedClientHelloConfigList);
// v1.6.7 only had the parser and a GREASE extension that explicitly could
// not be configured for real ECH, which is why this needed the upgrade.
//
// Every failure mode falls back to today's behaviour: no config, or a
// server that rejects ECH, means fragmentation without ECH — never a
// failed dial.

// dohEndpoint is the DNS-over-HTTPS resolver used to fetch ECH configs.
// Overridden by tests.
var dohEndpoint = "https://cloudflare-dns.com/dns-query"

// dohHTTPClient performs the DoH queries. It uses the default transport,
// so it honours the machine's proxy environment when one is set.
var dohHTTPClient = &http.Client{Transport: http.DefaultTransport}

type cachedECH struct {
	list    []byte
	expires time.Time
}

type cachedECHFailure struct {
	err error
	at  time.Time
}

// negativeECHCacheTTL is how long a failed fetch is remembered. Successes
// are cached for the DNS TTL (5 minutes–1 hour) but failures were not
// cached at all, so every dial re-fetched DoH against an endpoint that
// cannot answer — live, the ISP hijacks cloudflare-dns.com to a private
// IP, each fetch burns up to 5s, and the daemon fired one roughly every
// 0.5s. 30s keeps the failure visible to the operator (the dialer logs
// each attempt) while ending the churn.
const negativeECHCacheTTL = 30 * time.Second

var (
	echCacheMu   sync.Mutex
	echCache     = map[string]cachedECH{}
	echFailCache = map[string]cachedECHFailure{}
)

// FetchECHConfigList returns the raw serialized ECHConfigList for host,
// ready for utls.Config.EncryptedClientHelloConfigList. Results are cached
// per host for the DNS TTL (clamped to 5 minutes–1 hour). A fetch failure
// is cached briefly too (see negativeECHCacheTTL) and returns the same
// error without hitting the network again; the caller falls back to
// dialing without ECH either way.
func FetchECHConfigList(ctx context.Context, host string) ([]byte, error) {
	echCacheMu.Lock()
	if hit, ok := echCache[host]; ok && time.Now().Before(hit.expires) {
		echCacheMu.Unlock()
		return hit.list, nil
	}
	if fail, ok := echFailCache[host]; ok && time.Since(fail.at) < negativeECHCacheTTL {
		echCacheMu.Unlock()
		return nil, fail.err
	}
	echCacheMu.Unlock()

	list, ttl, err := fetchECHConfigList(ctx, host)
	if err != nil {
		// Never cache a failure caused by the caller's own context:
		// a cancelled or expired ctx (e.g. a SOCKS dialCtx that ran
		// out mid-retry) is caller-local, not a DoH fact. Caching
		// it would poison every dial for 30s — with ECHRequired
		// that breaks dials outright, without it ECH silently
		// turns off. A genuine DoH failure (ctx still alive, the
		// fetch itself failed or timed out) is cached as before.
		if ctx.Err() == nil {
			echCacheMu.Lock()
			echFailCache[host] = cachedECHFailure{err: err, at: time.Now()}
			echCacheMu.Unlock()
		}
		return nil, err
	}
	expires := time.Now().Add(ttl)
	if min := time.Now().Add(5 * time.Minute); expires.Before(min) {
		expires = min
	}
	if max := time.Now().Add(time.Hour); expires.After(max) {
		expires = max
	}
	echCacheMu.Lock()
	echCache[host] = cachedECH{list: list, expires: expires}
	delete(echFailCache, host)
	echCacheMu.Unlock()
	return list, nil
}

// DecodeECHConfigB64 decodes a pasted ECHConfigList (base64) from the
// profile and verifies it parses: a config the dialer cannot read is
// worse than no config, because the operator believes ECH is on. Both
// standard and URL-safe base64 are accepted, matching the DoH parser.
func DecodeECHConfigB64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("pasted ECH config is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("pasted ECH config is not valid base64: %w", err)
		}
	}
	if len(raw) < 4 {
		return nil, errors.New("pasted ECH config is too short")
	}
	if _, err := ECHPublicName(raw); err != nil {
		return nil, fmt.Errorf("pasted ECH config does not parse: %w", err)
	}
	return raw, nil
}

// FetchECHConfigListOverConn fetches the ECH config for host over an
// already-established tunnel stream (conn), instead of a direct DoH
// query: the request travels inside the tunnel, so the ISP sees no DoH
// query at all and the resolver sees the query coming from the
// Worker's egress, not the user's address. The conn must already be
// connected to resolverHost:443 — the caller opens the stream and
// wraps it as a net.Conn; this function performs the TLS handshake over
// it (verified against the system roots with tlsCfg, which must carry
// ServerName resolverHost) and the HTTPS request. Returns the raw
// list and its TTL.
func FetchECHConfigListOverConn(ctx context.Context, host string, conn net.Conn, tlsCfg *tls.Config, resolverHost string) ([]byte, time.Duration, error) {
	if resolverHost == "" {
		return nil, 0, errors.New("DoH over-tunnel resolver host is empty")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// The transport dials nowhere: the tunnel stream IS the connection,
	// and it is single-use — a second dial (a redirect follow, a retry)
	// must fail cleanly instead of writing a second request onto a
	// stream whose TLS session is already in use. TLS is still verified
	// against the system roots — the Worker relays the stream to the
	// real Cloudflare DNS, so its certificate is genuine and a
	// middlebox cannot substitute its own.
	var dialMu sync.Mutex
	dialed := false
	tr := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialMu.Lock()
			defer dialMu.Unlock()
			if dialed {
				return nil, errors.New("DoH over-tunnel connection is single-use and already used")
			}
			dialed = true
			return conn, nil
		},
		TLSClientConfig:   tlsCfg,
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		// Never follow a redirect: there is no second connection to
		// follow it with, and the DoH endpoint answers directly.
		return http.ErrUseLastResponse
	}}
	// The DoH URL names the resolver the stream is already open to:
	// it must agree with tlsCfg.ServerName, or the TLS handshake
	// verifies the wrong name. (It was hardcoded to
	// cloudflare-dns.com; the Worker cannot dial that host at all —
	// its connect() refuses Cloudflare's own IPs — so the request
	// died before any bytes flowed.)
	q := "https://" + resolverHost + "/dns-query?name=" + url.QueryEscape(host) + "&type=HTTPS"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("DoH query for %s through the tunnel failed: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("DoH query for %s through the tunnel returned HTTP %s", host, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, 0, err
	}
	return parseECHConfigFromDoH(body, host)
}

// StoreECHConfig writes a fetched list into the cache with the same
// TTL clamping as a direct fetch, so a config fetched through the
// tunnel is used by the dialer exactly like one fetched directly.
func StoreECHConfig(host string, list []byte, ttl time.Duration) {
	expires := time.Now().Add(ttl)
	if min := time.Now().Add(5 * time.Minute); expires.Before(min) {
		expires = min
	}
	if max := time.Now().Add(time.Hour); expires.After(max) {
		expires = max
	}
	echCacheMu.Lock()
	echCache[host] = cachedECH{list: list, expires: expires}
	delete(echFailCache, host)
	echCacheMu.Unlock()
}

// ECHConfigFresh reports whether a usable cached config exists for host,
// so a refresher can skip the work when the dialer already has one.
func ECHConfigFresh(host string) bool {
	_, ok := CachedECHConfig(host)
	return ok
}

// CachedECHConfig returns the cached config for host, if one exists and
// has not expired.
func CachedECHConfig(host string) ([]byte, bool) {
	echCacheMu.Lock()
	defer echCacheMu.Unlock()
	hit, ok := echCache[host]
	if !ok || !time.Now().Before(hit.expires) {
		return nil, false
	}
	return hit.list, true
}

type dohResponse struct {
	Answer []struct {
		Data string `json:"data"`
		TTL  int    `json:"TTL"`
	} `json:"Answer"`
}

func fetchECHConfigList(ctx context.Context, host string) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	q := dohEndpoint + "?name=" + url.QueryEscape(host) + "&type=HTTPS"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("DoH query for %s failed: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("DoH query for %s returned HTTP %s", host, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, 0, err
	}
	return parseECHConfigFromDoH(body, host)
}

// parseECHConfigFromDoH extracts the raw ECHConfigList and its TTL from
// a DoH JSON body. Shared by the direct fetch and the through-tunnel
// fetch, so both agree on what counts as a usable config.
func parseECHConfigFromDoH(body []byte, host string) ([]byte, time.Duration, error) {
	var doh dohResponse
	if err := json.Unmarshal(body, &doh); err != nil {
		return nil, 0, fmt.Errorf("DoH response for %s is not valid JSON: %w", host, err)
	}
	for _, ans := range doh.Answer {
		for _, field := range strings.Fields(ans.Data) {
			if rest, ok := strings.CutPrefix(field, "ech="); ok {
				raw, err := base64.StdEncoding.DecodeString(rest)
				if err != nil {
					raw, err = base64.RawURLEncoding.DecodeString(rest)
					if err != nil {
						return nil, 0, fmt.Errorf("ECH config for %s is not valid base64", host)
					}
				}
				if len(raw) < 4 {
					return nil, 0, fmt.Errorf("ECH config for %s is too short", host)
				}
				return raw, time.Duration(ans.TTL) * time.Second, nil
			}
		}
	}
	return nil, 0, fmt.Errorf("no ECH config published for %s", host)
}

// ECHPublicName extracts the public name (the outer SNI) from a serialized
// ECHConfigList: a uint16 length-prefixed list of ECHConfigs, each holding
// version, length, then contents — config ID (uint8), KEM ID (uint16),
// length-prefixed public key, length-prefixed cipher suites, maximum name
// length (uint8), then a uint8 length-prefixed public name. Layout mirrors
// uTLS's parseECHConfig; the name is used for the fragmentation cut and
// for the doctor's display only.
func ECHPublicName(list []byte) (string, error) {
	if len(list) < 2 {
		return "", errors.New("ECH config list is too short")
	}
	total := int(binary.BigEndian.Uint16(list[0:2]))
	if total <= 0 || total+2 != len(list) {
		return "", errors.New("ECH config list length is inconsistent")
	}
	cfg := list[2:]
	if len(cfg) < 4 {
		return "", errors.New("ECH config is too short")
	}
	if version := binary.BigEndian.Uint16(cfg[0:2]); version != 0xfe0d {
		return "", fmt.Errorf("unsupported ECH version %#x", version)
	}
	bodyLen := int(binary.BigEndian.Uint16(cfg[2:4]))
	if bodyLen <= 0 || 4+bodyLen > len(cfg) {
		return "", errors.New("ECH config body length is inconsistent")
	}
	rest := cfg[4 : 4+bodyLen]

	skip := func(n int) bool {
		if n < 0 || n > len(rest) {
			return false
		}
		rest = rest[n:]
		return true
	}
	skipPrefixed16 := func() bool {
		if len(rest) < 2 {
			return false
		}
		return skip(2 + int(binary.BigEndian.Uint16(rest[0:2])))
	}

	if !skip(1 + 2) { // config ID (uint8) + KEM ID (uint16)
		return "", errors.New("ECH config has no key config")
	}
	if !skipPrefixed16() { // public key
		return "", errors.New("ECH config has no public key")
	}
	if !skipPrefixed16() { // cipher suites
		return "", errors.New("ECH config has no cipher suites")
	}
	if !skip(1) { // maximum name length
		return "", errors.New("ECH config has no maximum name length")
	}
	if len(rest) < 1 {
		return "", errors.New("ECH config has no public name")
	}
	nameLen := int(rest[0])
	if nameLen <= 0 || 1+nameLen > len(rest) {
		return "", errors.New("ECH config public name length is inconsistent")
	}
	return string(rest[1 : 1+nameLen]), nil
}

// isECHRejection reports whether a handshake error is the server refusing
// ECH. Only then is a retry without ECH correct — any other failure (bad
// cert, dead edge, timeout) must not silently downgrade the connection.
func isECHRejection(err error) bool {
	var rej *utls.ECHRejectionError
	return errors.As(err, &rej)
}
