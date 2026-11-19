// Behavioural tests for worker.js's SMUX half-close handling. Run with
// `node --test worker/` (Node's built-in runner, no dependencies).
//
// worker.js imports `cloudflare:sockets`, which only exists in the Workers
// runtime, so the test loads a copy with that import replaced by a fake
// `connect()`. The fake socket records writer.write/writer.close/socket.close
// and exposes the readable's controller, which is enough to drive the
// half-close state machine. It does NOT exercise real Cloudflare sockets.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const CMD = { SYN: 0, FIN: 1, PSH: 2, NOP: 3, RST: 4 };
const here = path.dirname(new URL(import.meta.url).pathname);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function frame(cmd, id, payload = new Uint8Array(0)) {
  const out = new Uint8Array(8 + payload.length);
  const view = new DataView(out.buffer);
  out[0] = 1;
  out[1] = cmd;
  view.setUint16(2, payload.length, true);
  view.setUint32(4, id, true);
  out.set(payload, 8);
  return out;
}
const header = new Uint8Array([11, ...new TextEncoder().encode("example.com"), 0, 80]);
const text = (s) => new TextEncoder().encode(s);

let modPromise;
function loadWorker() {
  if (!modPromise) {
    let src = fs.readFileSync(path.join(here, "worker.js"), "utf8");
    const imp = 'import { connect } from "cloudflare:sockets";';
    assert.ok(src.includes(imp), "worker.js import line changed; update the test shim");
    src = src.replace(imp, "const connect = (...a) => globalThis.__connect(...a);");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cornelius-worker-"));
    const file = path.join(dir, "worker.mjs");
    fs.writeFileSync(file, src);
    modPromise = import(pathToFileURL(file).href);
  }
  return modPromise;
}

// One Worker connection with fakes wired in.
async function session() {
  const sent = [];
  const sockets = [];
  class FakeWS extends EventTarget {
    accept() {}
    send(d) {
      sent.push(new Uint8Array(d));
    }
    close() {}
  }
  let server;
  globalThis.WebSocketPair = class {
    constructor() {
      server = new FakeWS();
      this[0] = {};
      this[1] = server;
    }
  };
  globalThis.Response = class {
    constructor(_b, o) {
      this.status = o && o.status;
    }
  };
  globalThis.__connect = (_addr, opts) => {
    const ev = [];
    let ctrl;
    const readable = new ReadableStream({ start: (c) => (ctrl = c) });
    const writable = new WritableStream({
      write: (c) => void ev.push("write:" + new TextDecoder().decode(c)),
      close: () => void ev.push("writer.close"),
    });
    const sock = {
      ev,
      opts,
      ctrl,
      readable,
      writable,
      close() {
        ev.push("socket.close");
        try {
          ctrl.close();
        } catch {}
      },
    };
    sockets.push(sock);
    return sock;
  };
  const mod = await loadWorker();
  await mod.default.fetch(
    { url: "https://w/p", headers: { get: () => "websocket" } },
    { WS_PATH: "/p" },
    { waitUntil() {} },
  );
  const origError = console.error;
  console.error = () => {}; // silence the "cornelius pump ended" diagnostics
  return {
    sockets,
    deliver: (f) => server.dispatchEvent(Object.assign(new Event("message"), { data: f })),
    frames: () =>
      sent.map((f) => ({
        cmd: f[1],
        id: new DataView(f.buffer, f.byteOffset).getUint32(4, true),
        data: new TextDecoder().decode(f.slice(8)),
      })),
    clearFrames: () => (sent.length = 0),
    done: () => (console.error = origError),
  };
}

test("client FIN half-closes: flushed writes, writer.close(), socket stays open, reply flows, FIN on clean end", async (t) => {
  const s = await session();
  t.after(s.done);
  s.deliver(frame(CMD.SYN, 1));
  s.deliver(frame(CMD.PSH, 1, header));
  await sleep(20);
  const sock = s.sockets[0];
  assert.equal(sock.opts.allowHalfOpen, true);
  s.deliver(frame(CMD.PSH, 1, text("req")));
  s.deliver(frame(CMD.FIN, 1));
  await sleep(30);
  assert.deepEqual(sock.ev, ["write:req", "writer.close"]);

  sock.ctrl.enqueue(text("reply-after-fin"));
  await sleep(20);
  assert.ok(s.frames().some((f) => f.cmd === CMD.PSH && f.data === "reply-after-fin"));
  assert.ok(!s.frames().some((f) => f.cmd === CMD.FIN), "no FIN before the target ends");

  sock.ctrl.close(); // clean target EOF
  await sleep(30);
  assert.ok(s.frames().some((f) => f.cmd === CMD.FIN && f.id === 1), "FIN on clean pump end");
  assert.ok(!s.frames().some((f) => f.cmd === CMD.RST), "no RST on the graceful path");
  assert.ok(sock.ev.includes("socket.close"), "socket reaped once both halves are done");
});

test("pump error sends RST (not FIN) and tears the stream down", async (t) => {
  const s = await session();
  t.after(s.done);
  s.deliver(frame(CMD.SYN, 1));
  s.deliver(frame(CMD.PSH, 1, header));
  await sleep(20);
  const sock = s.sockets[0];
  sock.ctrl.error(new Error("connection reset by peer"));
  await sleep(30);
  const f = s.frames();
  assert.ok(f.some((x) => x.cmd === CMD.RST && x.id === 1), "RST on pump error");
  assert.ok(!f.some((x) => x.cmd === CMD.FIN), "a FIN would lie: the stream is dead, not half-closed");
  assert.ok(sock.ev.includes("socket.close"));
  // The stream is gone: late client data is ignored, nothing more is sent.
  s.clearFrames();
  s.deliver(frame(CMD.PSH, 1, text("late")));
  await sleep(20);
  assert.equal(s.frames().length, 0);
});

test("FIN before the target header is rejected with RST (no leaked stream)", async (t) => {
  const s = await session();
  t.after(s.done);
  s.deliver(frame(CMD.SYN, 5));
  s.deliver(frame(CMD.FIN, 5));
  await sleep(20);
  assert.ok(s.frames().some((x) => x.cmd === CMD.RST && x.id === 5));
  assert.equal(s.sockets.length, 0, "no socket was ever dialled");
});

test("client RST fully closes the socket and emits nothing back", async (t) => {
  const s = await session();
  t.after(s.done);
  s.deliver(frame(CMD.SYN, 3));
  s.deliver(frame(CMD.PSH, 3, header));
  await sleep(20);
  s.deliver(frame(CMD.RST, 3));
  await sleep(30);
  assert.ok(s.sockets[0].ev.includes("socket.close"));
  assert.equal(s.frames().length, 0, "no FIN/RST echoed back after a client RST");
});
