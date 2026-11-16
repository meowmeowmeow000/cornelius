# Cornelius Worker

Server side of the Cornelius tunnel. The Go daemon opens a WebSocket to this
Worker at the secret path and multiplexes SOCKS5 streams over it with the
SMUX v1 protocol (see `PROTOCOL.md`).

## Deploy

Needs Node.js and a Cloudflare account (`npx wrangler login` opens the
browser the first time).

```bash
cd worker
npx wrangler login
npx wrangler deploy
```

This deploys to `<name>.<subdomain>.workers.dev`. The daemon's combat
profiles point at the Worker hostname in `worker_host` — if you deploy under
a different name, update `worker_host` in `combat.profile` and
`configs/combat.profile` to match.

## The secret path

`WS_PATH` in `wrangler.toml` (default `/secret-knock-99`) must match
`modules.stealth_factory.default_ws_path` in the combat profiles. Requests
to any other path get a plain 404. Rotate the path in both places at once.

## ECH

Nothing to configure on the Worker side: Cloudflare publishes an ECH
config for the Worker hostname in DNS, and the daemon fetches it over
DoH when ECH is enabled (see the main README). The Worker itself never
sees the real SNI — it arrives encrypted inside the ClientHello.

## Test it

1. Deploy, then start the daemon pointing at the deployed Worker.
2. `curl -x socks5h://127.0.0.1:10808 https://example.com` should return
   the page. If it hangs, check `wrangler tail` for `Invalid SMUX version`
   (framing desync) or connection errors from `cloudflare:sockets`.
3. `npx wrangler tail` streams live logs from the Worker.

## How it works

- Accepts WebSocket upgrades **only** at `WS_PATH`.
- Buffers incoming WebSocket messages and parses SMUX v1 frames
  (`[version][cmd][LE length][LE streamId][payload]`).
- `SYN` opens a stream; the first `PSH` carries the target
  (`[hostLen][host][BE port]`) and the Worker dials it with
  `cloudflare:sockets`. Later `PSH` frames are forwarded to the socket.
- `FIN` closes the stream's socket; `NOP` keepalives are echoed back so
  the daemon's pool stays warm.
- Socket data flows back as `PSH` frames in WebSocket binary messages.
