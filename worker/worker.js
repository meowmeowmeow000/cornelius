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
const CMD_RST = 4;
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

    // FIN is a HALF-close (see PROTOCOL.md). A stream has two independent
    // halves: the write side (client -> target) ends on a client FIN, the
    // read side (target -> client) ends when the socket's readable pump
    // ends and we send FIN back. The stream is reaped once both are done.
    const finishIfDone = (id, st) => {
      if (!st.readDone || !st.writeClosed) return;
      if (streams.get(id) !== st) return;
      streams.delete(id);
      st.closed = true;
      try {
        if (st.socket) st.socket.close();
      } catch {}
    };

    // Full close of both halves (RST). Sends RST to the client unless the
    // close was driven by the client itself (code === "silent").
    const closeStream = (id, code) => {
      const st = streams.get(id);
      if (!st) return;
      streams.delete(id);
      st.closed = true;
      try {
        if (st.socket) st.socket.close();
      } catch {}
      if (code !== "silent") sendFrame(CMD_RST, id, new Uint8Array(0));
    };

    // Client FIN: close ONLY the write side of the target socket, after any
    // queued writes have been flushed. Cloudflare Sockets has no
    // socket.closeWrite(); the documented way is writer.close() on
    // socket.writable. socket.readable keeps pumping to the client.
    const halfCloseWrite = (id, st) => {
      if (st.writeClosed || st.finRequested) return;
      st.finRequested = true;
      if (!st.writer) return; // dial still pending: openTarget will do it
      st.writeQueue = st.writeQueue
        .then(() => st.writer.close())
        .then(() => {
          st.writeClosed = true;
          finishIfDone(id, st);
        })
        .catch((e) => {
          console.error("cornelius target half-close failed:", st.target.host, st.target.port, e && e.message ? e.message : e);
          closeStream(id);
        });
    };

    const pumpSocketToClient = async (id, st, socket, target) => {
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
        // Only act if the stream is still live; after a client RST or a
        // session close the client no longer tracks it.
        if (streams.get(id) === st) {
          if (outcome === "closed-clean") {
            // Clean target EOF: FIN = "no more data from me", read-side
            // EOF only. The write half stays open until the client's FIN.
            sendFrame(CMD_FIN, id, new Uint8Array(0));
            st.readDone = true;
            finishIfDone(id, st);
          } else {
            // The socket broke: a FIN would claim the stream is still
            // writable while we drop everything after it. Tell the client
            // the truth with RST and tear the stream down.
            closeStream(id);
          }
        }
      }
    };

    const openTarget = async (id, target) => {
      const st = streams.get(id);
      if (!st) return;
      let socket;
      try {
        // allowHalfOpen: with the default (false) the runtime auto-closes
        // the writable side when the target's readable side hits EOF
        // (https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/#socketoptions).
        // We manage each half explicitly, so keep the write side open.
        socket = connect({ hostname: target.host, port: target.port }, { allowHalfOpen: true });
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
      // A client FIN that arrived before the dial finished: apply it now,
      // queued behind the target header remainder above.
      if (st.finRequested) {
        st.finRequested = false;
        halfCloseWrite(id, st);
      }
      ctx.waitUntil(pumpSocketToClient(id, st, socket, target));
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
              writeClosed: false, // client -> target half done (writer closed)
              finRequested: false, // client FIN seen; writer.close() queued
              readDone: false, // target -> client half done (FIN sent)
            });
          }
          break;
        }
        case CMD_PSH: {
          const st = streams.get(streamId);
          if (!st || st.closed) break;
          // Data after the client's FIN violates half-close: drop it.
          if (st.finRequested || st.writeClosed) break;
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
          // Half-close only: the client is done SENDING. Close the
          // socket's write side and keep reading the target's reply.
          const st = streams.get(streamId);
          if (!st || st.closed) break;
          if (!st.target) {
            // FIN before the target header: there is nothing to half-close
            // and no socket will ever be opened. Reject with RST instead
            // of leaking the stream.
            closeStream(streamId);
            break;
          }
          halfCloseWrite(streamId, st);
          break;
        }
        case CMD_RST: {
          // Full close of both halves, driven by the client.
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
