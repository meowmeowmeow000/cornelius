package factory

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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
