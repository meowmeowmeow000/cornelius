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
| 1 | FIN | **Half-close**: the sender will send no more data on this stream. Empty payload. The stream stays open in the other direction. |
| 2 | PSH | Data. See below. |
| 3 | NOP | Keepalive. Empty payload, stream ID 0. **Must be echoed back.** |
| 4 | RST | **Full close** of both directions. Empty payload. Receiver tears the stream down at once; no reply. |

## Stream lifecycle

1. Client sends `SYN` (new stream ID), then a `PSH` whose payload is the
   target header: `[1-byte host length][host bytes][2-byte port, big-endian]`.
2. The Worker dials `host:port` with `cloudflare:sockets`
   (`connect(..., { allowHalfOpen: true })`). If the dial fails it answers
   `RST`.
3. Later `PSH` frames on that stream are raw stream bytes (client chunks
   them at 16 KiB max; the Worker does the same on the way back).
4. Each direction closes independently (see below).

## Closing a stream

A stream is two independent halves: client→target and target→client.

- **Client `FIN`** — the client is done sending. The Worker flushes any
  queued writes, then closes **only the write side** of the target socket
  with `writer.close()` on `socket.writable`. It keeps pumping
  `socket.readable` to the client and does **not** call `socket.close()`.
  `PSH` frames that arrive on the stream after the client `FIN` are
  dropped.
- **Worker `FIN`** — sent only when the Worker's `socket.readable` pump
  ends **cleanly** (target EOF). It means read-side EOF **only**: the
  client delivers buffered data, then its `Read` returns EOF, but the
  stream is still open for writing until the client sends `FIN`/`RST`.
  The Worker never sends `FIN` for an error: a `FIN` promises the stream
  is still writable.
- **Worker pump error** — if the socket's readable side errors, the
  stream is dead in both directions, so the Worker sends `RST` (not
  `FIN`), closes the socket and forgets the stream.
- **Client `FIN` before the target header** — there is no socket to
  half-close, so the Worker answers `RST` and forgets the stream.
- **Reaping** — once both halves are done (client `FIN` applied and
  Worker `FIN` sent) the Worker releases the socket (`socket.close()`) and
  forgets the stream.
- **Client-side forgetting** — the client drops a stream when it calls
  `Close()` **or** receives `RST` for it (which also unblocks any pending
  `Read` with EOF once buffered data is drained). A `FIN` alone never
  drops the stream.
- **`RST`** — full close, either direction. Sent by the client's
  `Close()` (unless both halves had already finished with `FIN`), and by
  the Worker on dial failure, a bad target header, a socket write
  failure, a pump error, or a `FIN` before the header. The receiver
  closes the target socket / unblocks reads and drops the stream. Never
  reply to an `RST` and never send `FIN` after receiving one.
- A `FIN` or `RST` for an unknown stream ID is ignored.
- **Client half-closed, target silent** — TCP gives the Go daemon no
  signal when a client that already half-closed later closes silently
  (nothing further is sent on the wire). After a client half-close the
  daemon therefore fully closes (`RST`) a stream when the client socket
  reports an error (e.g. RST) or when no data has arrived from the target
  for 15 s (`halfCloseIdleNanos`). A target that stays silent longer than
  that after the client's `FIN` is cut.

Cloudflare Sockets has no `socket.closeWrite()`; closing only the write
side is `socket.writable.getWriter().close()`. `socket.close()` closes
both sides, which is why it is reserved for `RST`/reaping. By default
(`allowHalfOpen: false`) the runtime also auto-closes the writable side
when the target hits EOF, so the Worker passes `allowHalfOpen: true`.
Reference: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/

Compatibility: an old Worker ignores opcode `4` (unknown opcodes are
skipped) and treats `FIN` as a full close, so the client and Worker must
be deployed together.

## Keepalive

The client sends `NOP` every 10 s and kills the session if it receives
nothing for 25 s. The Worker **must** echo every `NOP` immediately.
A Worker without a `NOP` handler reads the ping as data, loses byte
alignment, and kills the socket with close `1002` — this happened before
(see the Nov 13 post-mortem).
