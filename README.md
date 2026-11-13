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
