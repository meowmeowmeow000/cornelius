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

The daemon runs the same profile checks at startup and refuses to
start with a broken profile (bad WebSocket path, missing Worker host,
no primary target), instead of starting a daemon whose every dial is
doomed. Warnings (ECH off, fronting direction) are logged but never
block startup. A profile file that fails to load at all still starts
empty and waits for routes over IPC, as before.

### Rebuilding the XDP program

The compiled eBPF program (`internal/bpf/*.o`, embedded into the
binary by `bpf2go`) is committed to the repo. If you change
`xdp_filter.c`, regenerate it with `make ebpf` (needs `clang`,
`llvm` and `libbpf-dev`) and commit the result — CI verifies the
committed artifacts match the C source, and a test
(`internal/bpf/loader_test.go`) fails loudly if the artifacts are
ever empty again. The daemon also checks the embedded program at
startup when `-i` is given and refuses to start with a clear error
instead of a raw ELF failure.

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
  - **Strict mode** (`ech_required: true` in the profile) flips the
  default: with no usable ECH config, or a server that rejects ECH, the
  dialer refuses to dial at all instead of falling back — the tunnel
  stays down rather than leak the hostname. `ech_config_b64` carries a
  pasted ECH config (base64) for networks where the DoH fetch itself is
  blocked; when set it replaces the fetch. A pasted config that does not
  decode or parse fails startup validation, and `cornelius doctor`
  reports the mode and the config source. Off by default: strict mode
  trades availability for secrecy, so only turn it on where a failed
  dial is better than a visible SNI.
  - **Refresh through the tunnel:** once a tunnel is up, a refresher
  loop keeps the config fresh through the tunnel itself instead of
  direct DoH — every minute it checks the cache, and when the config is
  stale it opens one stream to cloudflare-dns.com through a warm tunnel
  and fetches it there. The ISP then sees no DoH query at all, and the
  query reaches Cloudflare DNS from the Worker's egress rather than the
  user's address. Cold start still uses direct DoH (or the pasted
  config in strict mode); if DoH is blocked at startup in non-strict
  mode, the first dials fall back to fragmentation, the pool warms, and
  the refresher upgrades later dials to ECH. `cornelius doctor` proves
  the refresh path on the live tunnel.
- **Fingerprint depth** (`internal/proxy/factory`): the Chrome hello is
  already deep in uTLS 1.8.2 — extension order is shuffled on every
  handshake the way BoringSSL does it, a GREASE ECH extension is sent
  when no real ECH config is offered, and the key shares include the
  post-quantum X25519MLKEM768 group. Tests lock all three in so a future
  uTLS upgrade cannot silently drop them. On top of that, the dialer
  rotates between Chrome 131 and 133 per connection when the route asks
  for the default fingerprint (an explicit pin — `chrome_131`,
  `chrome_133`, `firefox_auto`, `ios_auto`, `edge_auto`, `randomized` —
  is always honoured exactly).

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
