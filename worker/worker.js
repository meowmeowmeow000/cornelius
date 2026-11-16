// Cornelius Worker — server side of the SMUX v1 tunnel.
//
// The Go daemon (internal/proxy/socks_smux.go) opens a WebSocket to this
// Worker at the secret path, then multiplexes many SOCKS5 streams over it
// using SMUX v1 frames. This file is the other half of that protocol; keep
// it in sync with worker/PROTOCOL.md and socks_smux.go.
//
// Deploy: `npx wrangler deploy` from this directory (see README.md).
// The daemon's profiles point at this Worker's hostname (worker_host), so
// deploy here — or update worker_host in the combat.profile files.

import { connect } from "cloudflare:sockets";

const SMUX_VERSION = 1;
const CMD_SYN = 0;
const CMD_FIN = 1;
const CMD_PSH = 2;
const CMD_NOP = 3;
const SMUX_HDR_SIZE = 8;
const MAX_CHUNK = 16384;

function encodeSmuxFrame(cmd, streamId, payload) {
  const out = new Uint8Array(SMUX_HDR_SIZE + payload.length);
  const view = new DataView(out.buffer);
  out[0] = SMUX_VERSION;
  out[1] = cmd;
  view.setUint16(2, payload.length, true); // little-endian, like the client
  view.setUint32(4, streamId, true); // little-endian
  out.set(payload, SMUX_HDR_SIZE);
  return out;
}

function decodeTarget(payload) {
  // Client's OpenStream sends: [1-byte hostLen][host bytes][2-byte BE port]
  if (payload.length < 3) return null;
  const hostLen = payload[0];
  if (payload.length < 1 + hostLen + 2) return null;
  const host = new TextDecoder().decode(payload.slice(1, 1 + hostLen));
  const port = (payload[1 + hostLen] << 8) | payload[1 + hostLen + 1];
  if (!host || port === 0) return null;
  return { host, port, rest: payload.slice(1 + hostLen + 2) };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const wsPath = env.WS_PATH || "/secret-knock-99";

    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Not Found", { status: 404 });
    }
    if (url.pathname !== wsPath) {
      return new Response("Not Found", { status: 404 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    // Per-connection state.
    let rxBuf = new Uint8Array(0);
    // streamId -> { socket, writer, writeQueue, target, closed }
    const streams = new Map();

    const sendFrame = (cmd, streamId, payload) => {
      try {
        server.send(encodeSmuxFrame(cmd, streamId, payload));
      } catch {
        // Socket already gone; cleanup happens on close/error.
      }
    };

    const closeStream = (id, code) => {
      const st = streams.get(id);
      if (!st) return;
      streams.delete(id);
      st.closed = true;
      try {
        st.socket.close();
      } catch {}
      if (code !== "silent") sendFrame(CMD_FIN, id, new Uint8Array(0));
    };

    const pumpSocketToClient = async (id, socket, target) => {
      const reader = socket.readable.getReader();
      let bytes = 0;
      let outcome = "closed-clean";
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = new Uint8Array(value);
          bytes += chunk.length;
          for (let off = 0; off < chunk.length; off += MAX_CHUNK) {
            sendFrame(CMD_PSH, id, chunk.slice(off, off + MAX_CHUNK));
          }
        }
      } catch (e) {
        // Diagnostic: the pump used to swallow this silently, so a dead
        // egress socket looked exactly like a dead tunnel. Log how the
        // socket ended and how much it forwarded, so `wrangler tail`
        // shows the real reason.
        outcome = "error: " + (e && e.message ? e.message : e);
      } finally {
        reader.releaseLock();
        console.error("cornelius pump ended:", target.host, target.port, "bytes=" + bytes, outcome);
        closeStream(id);
      }
    };

    const openTarget = async (id, target) => {
      const st = streams.get(id);
      if (!st) return;
      let socket;
      try {
        socket = connect({ hostname: target.host, port: target.port });
            } catch (e) {
        // Diagnostic: the catch used to swallow this silently, so a failed
        // dial looked exactly like a dead tunnel. Log it so `wrangler tail`
        // shows the real reason (e.g. plan-gated sockets).
        console.error("cornelius connect failed:", target.host, target.port, e && e.message ? e.message : e);
        closeStream(id);
        return;
      }
      st.socket = socket;
      st.writer = socket.writable.getWriter();
      st.writeQueue = Promise.resolve();
      // Forward anything that arrived after the target header.
      if (target.rest.length > 0) {
        st.writeQueue = st.writeQueue
          .then(() => st.writer.write(target.rest))
          .catch((e) => {
            console.error("cornelius target write failed:", target.host, target.port, e && e.message ? e.message : e);
            closeStream(id);
          });
      }
      ctx.waitUntil(pumpSocketToClient(id, socket, target));
    };

    const handleFrame = (cmd, streamId, payload) => {
      switch (cmd) {
        case CMD_SYN: {
          if (!streams.has(streamId)) {
            streams.set(streamId, {
              socket: null,
              writer: null,
              writeQueue: Promise.resolve(),
              target: null,
              closed: false,
            });
          }
          break;
        }
        case CMD_PSH: {
          const st = streams.get(streamId);
          if (!st || st.closed) break;
          if (!st.target) {
            // First data on a stream is the target header.
            const target = decodeTarget(payload);
            if (!target) {
              closeStream(streamId);
              break;
            }
            st.target = target;
            openTarget(streamId, target);
          } else {
            // Ordered, backpressured writes to the destination socket.
            const data = payload;
            st.writeQueue = st.writeQueue
              .then(() => st.writer.write(data))
              .catch((e) => {
                console.error("cornelius stream write failed:", st.target.host, st.target.port, e && e.message ? e.message : e);
                closeStream(streamId);
              });
          }
          break;
        }
        case CMD_FIN: {
          closeStream(streamId, "silent");
          break;
        }
        case CMD_NOP: {
          // Keepalive: echo it back so the client's pool stays warm and its
          // 25s no-RX watchdog never fires. A missing handler here used to
          // desync the stream and kill the socket with close 1002.
          sendFrame(CMD_NOP, 0, new Uint8Array(0));
          break;
        }
        default:
          // Unknown opcode: ignore, stay in sync.
          break;
      }
    };

    const handleBytes = (bytes) => {
      const next = new Uint8Array(rxBuf.length + bytes.length);
      next.set(rxBuf, 0);
      next.set(bytes, rxBuf.length);
      rxBuf = next;

      for (;;) {
        if (rxBuf.length < SMUX_HDR_SIZE) return;
        if (rxBuf[0] !== SMUX_VERSION) {
          // Lost framing: this is unrecoverable, fail loudly with the code
          // the client logs, instead of silently garbling streams.
          try {
            server.close(1002, "Invalid SMUX version");
          } catch {}
          return;
        }
        const view = new DataView(rxBuf.buffer, rxBuf.byteOffset, rxBuf.byteLength);
        const cmd = rxBuf[1];
        const length = view.getUint16(2, true);
        const streamId = view.getUint32(4, true);
        if (rxBuf.length < SMUX_HDR_SIZE + length) return; // wait for more
        const payload = rxBuf.slice(SMUX_HDR_SIZE, SMUX_HDR_SIZE + length);
        rxBuf = rxBuf.slice(SMUX_HDR_SIZE + length);
        handleFrame(cmd, streamId, payload);
      }
    };

    server.addEventListener("message", (event) => {
      const data = event.data;
      if (typeof data === "string") return; // text frames are not SMUX
      handleBytes(new Uint8Array(data));
    });

    server.addEventListener("close", () => {
      for (const id of [...streams.keys()]) closeStream(id, "silent");
    });
    server.addEventListener("error", () => {
      for (const id of [...streams.keys()]) closeStream(id, "silent");
    });

    return new Response(null, { status: 101, webSocket: client });
  },
};
