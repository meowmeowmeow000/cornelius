# SMUX v1 protocol

Single source of truth for the tunnel protocol. Both ends must implement
this exactly: the Go client in `internal/proxy/socks_smux.go` and the
Cloudflare Worker in `worker/worker.js`.

## Transport

- TLS to a Cloudflare edge, ALPN forced to `http/1.1` (see
  `internal/proxy/factory/factory.go` — the Chrome fingerprint advertises
  `h2`, which breaks the HTTP/1.1 WebSocket upgrade).
- Raw HTTP/1.1 WebSocket upgrade at the secret path
  (`default_ws_path`, default `/secret-knock-99`).
- After the 101, both sides exchange **standard WebSocket binary frames**.
  The client masks its frames (RFC 6455); the server sends unmasked binary
  frames. Each WebSocket message carries whole SMUX frames; a SMUX frame
  may be split across messages and several may arrive in one message, so
  both sides buffer and re-parse.

## SMUX frame (8-byte header + payload)

| Byte | Field |
| ---- | ----- |
| 0 | Version, always `1` |
| 1 | Command (opcode) |
| 2–3 | Payload length, **little-endian** uint16 |
| 4–7 | Stream ID, **little-endian** uint32 |

A frame with a version other than `1` is a fatal framing error: the
receiving side must close the WebSocket with code `1002`
(`Invalid SMUX version`) instead of guessing.

## Opcodes

| Op | Name | Meaning |
| -- | ---- | ------- |
| 0 | SYN | Open a stream. Empty payload. Client uses odd stream IDs (1, 3, 5…). |
| 1 | FIN | Close a stream. Empty payload. |
| 2 | PSH | Data. See below. |
| 3 | NOP | Keepalive. Empty payload, stream ID 0. **Must be echoed back.** |

## Stream lifecycle

1. Client sends `SYN` (new stream ID), then a `PSH` whose payload is the
   target header: `[1-byte host length][host bytes][2-byte port, big-endian]`.
2. The Worker dials `host:port` with `cloudflare:sockets`. If the dial
   fails it answers `FIN`.
3. Later `PSH` frames on that stream are raw stream bytes (client chunks
   them at 16 KiB max; the Worker does the same on the way back).
4. Either side sends `FIN` to close; the Worker closes the TCP socket.

## Keepalive

The client sends `NOP` every 10 s and kills the session if it receives
nothing for 25 s. The Worker **must** echo every `NOP` immediately.
A Worker without a `NOP` handler reads the ping as data, loses byte
alignment, and kills the socket with close `1002` — this happened before
(see the Nov 13 post-mortem).
