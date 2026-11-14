# Cornelius v1.3.2
*Linux-Native DPI Bypass Proxy, eBPF XDP RST Shield, DPI Hop Echolocation, and btop-Style Tactical TUI.*

## Highlights in v1.3.2
- **Mirrored Dual-Band Braille Oscilloscope:** TrueColor vertical gradients plotting Uplink TX (`▲`) and Downlink RX (`▼`) simultaneously.
- **DPI Hop Echolocation Radar (`[t]`):** Maps intermediate router hops via Linux `IP_TTL` + `IP_RECVERR` (`MSG_ERRQUEUE`) to pinpoint exact middlebox hop distances and auto-calibrate `DecoyTTL`.
- **Interactive Edge Route Matrix (`j`/`k` + `Enter`):** Browse discovered Cloudflare edges with confidence bars and hot-swap active tunnels zero-downtime.
- **In-TUI Cartographer Scout (`[s]`):** Scan `/24`–`/30` subnets live from the dashboard without restarting Cornelius.
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
