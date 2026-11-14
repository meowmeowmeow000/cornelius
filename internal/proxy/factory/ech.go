package factory

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

var (
	echCacheMu sync.Mutex
	echCache   = map[string]cachedECH{}
)

// FetchECHConfigList returns the raw serialized ECHConfigList for host,
// ready for utls.Config.EncryptedClientHelloConfigList. Results are cached
// per host for the DNS TTL (clamped to 5 minutes–1 hour). A fetch failure
// is an error; the caller falls back to dialing without ECH.
func FetchECHConfigList(ctx context.Context, host string) ([]byte, error) {
	echCacheMu.Lock()
	if hit, ok := echCache[host]; ok && time.Now().Before(hit.expires) {
		echCacheMu.Unlock()
		return hit.list, nil
	}
	echCacheMu.Unlock()

	list, ttl, err := fetchECHConfigList(ctx, host)
	if err != nil {
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
	echCacheMu.Unlock()
	return list, nil
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
