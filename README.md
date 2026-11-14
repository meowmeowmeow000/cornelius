# Cornelius v1.3.2
*Linux-Native DPI Bypass Proxy, eBPF XDP RST Shield, DPI Hop Echolocation, and btop-Style Tactical TUI.*

## Highlights in v1.3.2
- **Mirrored Dual-Band Braille Oscilloscope:** TrueColor vertical gradients plotting Uplink TX (`▲`) and Downlink RX (`▼`) simultaneously.
- **DPI Hop Echolocation Radar (`[t]`):** Maps intermediate router hops via Linux `IP_TTL` + `IP_RECVERR` (`MSG_ERRQUEUE`) to pinpoint exact middlebox hop distances and auto-calibrate `DecoyTTL`.
- **Interactive Edge Route Matrix (`j`/`k` + `Enter`):** Browse discovered Cloudflare edges with confidence bars and hot-swap active tunnels zero-downtime.
- **In-TUI Cartographer Scout (`[s]`):** Scan `/24`–`/30` subnets live from the dashboard without restarting Cornelius.
- **Doctor panel (`[d]`):** Live health checks inside the TUI — profile, WebSocket path, SNI direction, ECH status, warm tunnels, dial failures — refreshed while open. The route matrix also shows a WS column (✓ = the edge proved the full WebSocket + SMUX tunnel, – = TLS only).
- **4 Live `btop` Themes (`[m]`):** Cycle between *Emerald Matrix*, *Cyberpunk Neon*, *Nordic Frost*, and *Amber Phosphor*.

## Build & Run

```bash
unzip cornelius-v1.3.2-art-tui.zip
cd cornelius

go mod tidy
make ebpf
make all

# Terminal 1: Start Cornelius Daemon
IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
sudo ./bin/cornelius -i "$IFACE" -c configs/combat.profile -l 127.0.0.1:40443

# Terminal 2: Launch Tactical TUI
sudo ./bin/cornelius-tui -s /run/cornelius/ipc.sock
```

## Doctor

If the tunnel does not work, ask Cornelius itself:

```bash
sudo ./bin/cornelius -c configs/combat.profile doctor          # profile + tunnel + end-to-end stream test
sudo ./bin/cornelius -c configs/combat.profile -i eth0 doctor  # also test the XDP shield
```

It prints plain-language checks (`[ok]`, `[!!]`, `[xx]`) and exits 0 when
healthy. On a machine that forces traffic through a proxy it says so and
skips the live test instead of reporting a false failure.

## Advanced evasion

- **Randomized fragmentation** (`internal/tlshandshake`): every connection
  splits the ClientHello at unpredictable cut points, always through the
  SNI itself — fixed cuts are a fingerprint a DPI can learn.
- **Verified routes** (`internal/scanner`): the Cartographer promotes only
  edges that prove the full path — TLS handshake *plus* WebSocket upgrade
  *plus* a SMUX keepalive echo. A fast edge that cannot upgrade never
  becomes primary.
- **Encrypted ClientHello** (`internal/proxy/factory`, `ech_enabled` in the
  profile): the dialer fetches the Worker's ECH config from its DNS HTTPS
  record over DoH and hides the SNI entirely — the outer hello carries
  only the public name (`cloudflare-ech.com`), the real Worker hostname
  travels encrypted inside. Fragmentation hides the SNI from a DPI that
  reads one packet at a time; ECH hides it from one that reassembles.
  Safe by construction: a failed fetch, or a server that rejects ECH,
  falls back to fragmentation without ECH — and a rejection is only
  trusted after the outer certificate verifies, so a middlebox stripping
  ECH cannot silently downgrade the connection. Needs uTLS ≥ 1.8.2
  (v1.6.7 only had the parser and a GREASE extension that could not be
  configured for real ECH).
- **ECH** is the next step: uTLS already supports `ECHConfigs`, so the
  daemon could hide the SNI entirely instead of fragmenting around it.
  It needs the Worker's ECH config fetched over DoH first, with a clean
  fallback to plain fragmentation when no config is available.

## Cloudflare Worker

The daemon tunnels through a Cloudflare Worker (`worker/`). It speaks SMUX v1
over a WebSocket at the secret path — the protocol is specified in
`worker/PROTOCOL.md`, the server code is `worker/worker.js`. Deploy it with
`npx wrangler deploy` from `worker/`; the path in `wrangler.toml` (`WS_PATH`)
must match `default_ws_path` in the combat profiles.

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and pull
request: `gofmt` + `go vet` + `go build` + `go test`, a check that the
committed eBPF objects match `xdp_filter.c`, and a `node --check` of the
Worker.
