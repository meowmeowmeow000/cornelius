package factory

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The real ECH config for bold-heart-a6e2.nedaymarg.workers.dev, as
// published in its DNS HTTPS record (fetched 2026-11-14). Public name:
// cloudflare-ech.com.
const testECHBase64 = "AEX+DQBBZQAgACAOj1t+953ib/8pSWcLg5LSAYErxMb1kJVE0R3m/XdmagAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

func testDoHServer(t *testing.T, answer string, status int, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
}

func dohAnswer(data string) string {
	return `{"Status":0,"Answer":[{"name":"h.example","type":65,"TTL":300,"data":"` + data + `"}]}`
}

// clearECHCacheFor removes one host from both ECH caches. The caches are
// process-global, so any test that asserts DoH hit counts must clean up
// or a repeat run (go test -count=2) inherits the first run's entries.
func clearECHCacheFor(host string) {
	echCacheMu.Lock()
	delete(echCache, host)
	delete(echFailCache, host)
	echCacheMu.Unlock()
}

func TestFetchECHConfigList(t *testing.T) {
	answer := dohAnswer(`1 . alpn=h3,h2 ipv4hint=104.21.75.30 ech=` + testECHBase64 + ` ipv6hint=2606:4700:3034::ac43:a703`)
	srv := testDoHServer(t, answer, http.StatusOK, nil)
	defer srv.Close()

	oldEndpoint := dohEndpoint
	dohEndpoint = srv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	list, err := FetchECHConfigList(context.Background(), "ech-ok.example")
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	want, _ := base64.StdEncoding.DecodeString(testECHBase64)
	if string(list) != string(want) {
		t.Fatalf("fetched list does not match the published config (%d bytes vs %d)", len(list), len(want))
	}
	name, err := ECHPublicName(list)
	if err != nil {
		t.Fatalf("public name parse failed: %v", err)
	}
	if name != "cloudflare-ech.com" {
		t.Fatalf("public name = %q, want cloudflare-ech.com", name)
	}
}

func TestFetchECHConfigListCaches(t *testing.T) {
	answer := dohAnswer(`1 . ech=` + testECHBase64)
	var hits atomic.Int32
	srv := testDoHServer(t, answer, http.StatusOK, &hits)
	defer srv.Close()

	oldEndpoint := dohEndpoint
	dohEndpoint = srv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	host := "ech-cache.example"
	defer clearECHCacheFor(host)
	if _, err := FetchECHConfigList(context.Background(), host); err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if _, err := FetchECHConfigList(context.Background(), host); err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("DoH was queried %d times, want 1 (second call should hit the cache)", hits.Load())
	}
}

func TestFetchECHConfigListNegativeCache(t *testing.T) {
	// Fail first, then answer: proves the failure is cached (no second
	// request), that it expires (a re-fetch happens), and that a later
	// success clears the failure and populates the positive cache.
	// Live, the ISP hijacks cloudflare-dns.com, so every dial burned up
	// to 5s on a fetch that cannot succeed — roughly one attempt every
	// 0.5s in the daemon log.
	var hits atomic.Int32
	var mode atomic.Int32 // 0 = fail, 1 = answer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/dns-json")
		if mode.Load() == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(dohAnswer(`1 . ech=` + testECHBase64)))
	}))
	defer srv.Close()

	oldEndpoint := dohEndpoint
	dohEndpoint = srv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	host := "ech-negcache.example"
	ctx := context.Background()
	defer clearECHCacheFor(host)

	if _, err := FetchECHConfigList(ctx, host); err == nil {
		t.Fatal("first fetch must fail")
	}
	if _, err := FetchECHConfigList(ctx, host); err == nil {
		t.Fatal("second fetch must fail too")
	}
	if hits.Load() != 1 {
		t.Fatalf("DoH was queried %d times, want 1: the failure must be cached, not re-fetched", hits.Load())
	}

	// Age the cached failure past the window and let the server answer.
	echCacheMu.Lock()
	f := echFailCache[host]
	f.at = time.Now().Add(-negativeECHCacheTTL - time.Second)
	echFailCache[host] = f
	echCacheMu.Unlock()
	mode.Store(1)
	if _, err := FetchECHConfigList(ctx, host); err != nil {
		t.Fatalf("fetch after expiry failed: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("DoH was queried %d times, want 2: the expired failure must re-fetch", hits.Load())
	}
	// The success must have cleared the failure entry itself, not
	// merely masked it behind the positive cache: check the map
	// directly, or the delete() call could be dropped and the test
	// would still pass.
	echCacheMu.Lock()
	_, stillFailed := echFailCache[host]
	echCacheMu.Unlock()
	if stillFailed {
		t.Fatal("success did not delete the cached failure entry")
	}
	// The success must also have populated the positive cache: a
	// fourth call fetches nothing.
	if _, err := FetchECHConfigList(ctx, host); err != nil {
		t.Fatalf("fourth fetch failed: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("DoH was queried %d times, want 2: the success must be cached", hits.Load())
	}
}

func TestFetchECHConfigListDoesNotCacheCancelledContext(t *testing.T) {
	// A failure caused by the caller's own cancelled context is
	// caller-local, not a DoH fact: it must not be cached, or one
	// expired dialCtx would poison every dial for 30s.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	oldEndpoint := dohEndpoint
	dohEndpoint = srv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	host := "ech-ctx.example"
	defer clearECHCacheFor(host)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FetchECHConfigList(cancelled, host); err == nil {
		t.Fatal("fetch with a cancelled context must fail")
	}
	echCacheMu.Lock()
	_, cached := echFailCache[host]
	echCacheMu.Unlock()
	if cached {
		t.Fatal("a context-cancellation failure was cached")
	}
	// A fresh context must re-query the network, not return the
	// cancelled caller's error from the cache.
	before := hits.Load()
	if _, err := FetchECHConfigList(context.Background(), host); err == nil {
		t.Fatal("fetch with a fresh context must fail against the 500 server")
	}
	if hits.Load() <= before {
		t.Fatalf("DoH was queried %d times before and after, want a fresh query: the cancelled failure must not be cached", hits.Load())
	}
}

func TestFetchECHConfigListNoECH(t *testing.T) {
	answer := dohAnswer(`1 . alpn=h3,h2 ipv4hint=104.21.75.30`)
	srv := testDoHServer(t, answer, http.StatusOK, nil)
	defer srv.Close()

	oldEndpoint := dohEndpoint
	dohEndpoint = srv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	if _, err := FetchECHConfigList(context.Background(), "ech-none.example"); err == nil {
		t.Fatal("expected an error when no ECH config is published")
	} else if !strings.Contains(err.Error(), "no ECH config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchECHConfigListServerError(t *testing.T) {
	srv := testDoHServer(t, `{"Status":2}`, http.StatusInternalServerError, nil)
	defer srv.Close()

	oldEndpoint := dohEndpoint
	dohEndpoint = srv.URL
	defer func() { dohEndpoint = oldEndpoint }()

	if _, err := FetchECHConfigList(context.Background(), "ech-500.example"); err == nil {
		t.Fatal("expected an error on DoH HTTP 500")
	}
}

func TestECHPublicNameInvalid(t *testing.T) {
	for _, bad := range [][]byte{
		{},
		{0x00},
		{0x00, 0x10, 0x00, 0x00},             // claims 16 bytes, has 2
		{0x00, 0x04, 0x00, 0x01, 0x00, 0x00}, // config body too short
	} {
		if _, err := ECHPublicName(bad); err == nil {
			t.Fatalf("ECHPublicName(%x) should fail", bad)
		}
	}
}

func TestDecodeECHConfigB64(t *testing.T) {
	// The real published config decodes and parses.
	list, err := DecodeECHConfigB64(testECHBase64)
	if err != nil {
		t.Fatalf("valid pasted config should decode: %v", err)
	}
	name, err := ECHPublicName(list)
	if err != nil {
		t.Fatalf("decoded config should parse: %v", err)
	}
	if name != "cloudflare-ech.com" {
		t.Fatalf("public name = %q, want cloudflare-ech.com", name)
	}

	for _, bad := range []string{
		"",
		"not-base64!!!",
		base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02}), // too short
		base64.StdEncoding.EncodeToString([]byte("this is not an ECH config list at all, just text........")),
	} {
		if _, err := DecodeECHConfigB64(bad); err == nil {
			t.Fatalf("DecodeECHConfigB64(%q) should fail", bad)
		}
	}
}

func TestFetchECHConfigListOverConn(t *testing.T) {
	answer := dohAnswer(`1 . ech=` + testECHBase64)
	dohSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write([]byte(answer))
	}))
	defer dohSrv.Close()

	raw, err := net.Dial("tcp", dohSrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	list, ttl, err := FetchECHConfigListOverConn(context.Background(), "over-conn.example", raw, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, "doh.test")
	if err != nil {
		t.Fatalf("over-conn fetch failed: %v", err)
	}
	want, _ := base64.StdEncoding.DecodeString(testECHBase64)
	if string(list) != string(want) {
		t.Fatal("fetched list does not match the published config")
	}
	if ttl != 300*time.Second {
		t.Fatalf("ttl = %v, want 300s", ttl)
	}
}

func TestFetchECHConfigListOverConnBadStatus(t *testing.T) {
	dohSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dohSrv.Close()

	raw, err := net.Dial("tcp", dohSrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	if _, _, err := FetchECHConfigListOverConn(context.Background(), "over-conn-500.example", raw, &tls.Config{InsecureSkipVerify: true}, "doh.test"); err == nil {
		t.Fatal("expected an error on DoH HTTP 500 through the tunnel")
	}
}

func TestStoreECHConfigFresh(t *testing.T) {
	want, _ := base64.StdEncoding.DecodeString(testECHBase64)
	StoreECHConfig("fresh.example", want, 300*time.Second)
	if !ECHConfigFresh("fresh.example") {
		t.Fatal("stored config should be fresh")
	}
	got, ok := CachedECHConfig("fresh.example")
	if !ok || string(got) != string(want) {
		t.Fatal("cached config does not match the stored one")
	}
	if ECHConfigFresh("other.example") {
		t.Fatal("a host with no stored config should not be fresh")
	}
}
