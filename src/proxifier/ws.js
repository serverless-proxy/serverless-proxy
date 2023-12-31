// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "../base/cfg.js";
import * as modres from "../base/res.js";
import * as log from "../base/log.js";

/** @typedef {{rx: number, tx: number, p: number}} BandwidthStats */

/**
 * @param {Request} req
 * @returns {boolean}
 */
export function isWs(req) {
  const upgrade = req.headers.get(cfg.upgradeHeader);
  return upgrade && upgrade === "websocket";
}

/**
 * @param {TransformStream} egress
 * @param {function(Promise)} waiter
 */
export async function accept(egress, waiter) {
  // github.com/cloudflare/websocket-template/blob/main/index.js
  // developers.cloudflare.com/workers/learning/using-websockets
  const [client, server] = Object.values(new WebSocketPair());

  server.accept();
  const ingress = await duplex(server);

  log.d("ws: accept: eg? ing?", egress != null, ingress != null);

  if (ingress) {
    waiter = cfg.useWaiter ? waiter : undefined;
    pipe(ingress, egress, waiter);
    return new Response(null, { status: 101, webSocket: client });
  }

  return modres.r500;
}

/**
 * @param {TransformStream} ingress
 * @param {TransformStream} egress
 * @param {function(Promise)} waiter
 */
export function pipe(ingress, egress, waiter = (p) => p) {
  // 1. pipe without await
  // 2. do not close egress on completion
  waiter(
    ingress.readable
      .pipeTo(egress.writable)
      .catch((ex) => log.e("pipe: in2out err", ex.message))
  );
  // stream the response out
  // blog.cloudflare.com/workers-optimization-reduces-your-bill
  waiter(
    egress.readable
      .pipeTo(ingress.writable)
      .catch((ex) => log.e("pipe: out2in err", ex.message))
  );
}

/**
 * @param {WebSocket} websocket
 * @returns {Promise<{readable: ReadableStream, writable: WritableStream}>}
 */
async function duplex(websocket) {
  try {
    await setup(websocket);
  } catch (ex) {
    log.e("ws: duplex err", ex);
    return null;
  }
  const bw = { rx: 0, tx: 0, p: Date.now() };
  // developer.mozilla.org/en-US/docs/Web/API/ReadableStream/ReadableStream
  const r = new ReadableStream({
    start(rctl) {
      chain(websocket, rctl, bw);
      log.d("ws: readable started");
    },
    cancel(reason) {
      close(websocket, 1014, reason, bw);
    },
  });

  // developer.mozilla.org/en-US/docs/Web/API/WritableStream/WritableStream
  const w = new WritableStream({
    start(wctl) {
      log.d("ws: writable started");
    },
    write(chunk, wctl) {
      const ok = wsok(websocket);
      const n = len(chunk);
      bw.tx += n;
      log.v("ws: write?", ok, "d?", n, "total", bw.tx);
      // developer.mozilla.org/en-US/docs/Web/API/WritableStreamDefaultController
      if (ok) {
        websocket.send(chunk);
      } else if (wctl) {
        log.w("ws: write err, ws closed");
        wctl.error("websocket closed");
      }
    },
    close(wctl) {
      close(websocket, 1000, "remote closed", bw);
      // on workers, wctl is undefined?
      if (wctl) wctl.close();
    },
    abort(reason) {
      close(websocket, 1014, reason, bw);
    },
  });

  return { readable: r, writable: w };
}

/**
 * @param {WebSocket} websocket
 * @returns {Promise<void>}
 */
function setup(websocket) {
  // developers.cloudflare.com/workers/platform/compatibility-dates/#global-navigator
  if (navigator.userAgent === "Cloudflare-Workers") {
    // on workers, open never gets called, so skip
    return Promise.resolve();
  }

  log.d("ws: wait until open");
  let yes, no, timer;
  const promise = new Promise((resolve, reject) => {
    yes = resolve.bind(this);
    no = reject.bind(this);
    timer = setTimeout(() => no("timeout"), cfg.wsConnTimeoutMs);
  });
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket
  websocket.addEventListener("open", (event) => {
    log.d("ws: open", event != null, yes, timer);
    if (timer) clearTimeout(timer);
    timer = null;
    yes();
  });
  websocket.addEventListener("error", (event) => {
    // log.d("ws: err event?", event != null, "t?", timer != null);
    if (event != null) log.e("ws: error", event.message, event.error);
    // no() has no effect if yes() has already been called
    if (timer) clearTimeout(timer);
    timer = null;
    no(event.message);
  });
  return promise;
}

/**
 * @param {WebSocket} websocket
 * @param {ReadableByteStreamController} reader
 * @param {BandwidthStats} bw
 */
function chain(websocket, reader, bw) {
  // developers.cloudflare.com/workers/runtime-apis/websockets
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/message_event
  websocket.addEventListener("message", (what) => {
    const { data, type } = what;
    const n = len(data);
    bw.rx += n;
    log.v("ws: recv", n, type, "total", bw.rx);
    if (data) reader.enqueue(data);
  });
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/close_event
  websocket.addEventListener("close", (why) => {
    const { code, reason, wasClean } = why;
    endlog(bw);
    log.d("ws: close", code, reason, "clean?", wasClean);
    // already done: close(websocket, code, reason, bw);
    reader.close();
  });
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/error_event
  websocket.addEventListener("error", (event) => {
    log.e("ws: err", event.message);
    reader.close();
  });
}

/**
 * @param {WebSocket} websocket
 * @returns {boolean}
 */
function wsok(websocket) {
  log.v("ws: state?", websocket.readyState);
  // WebSocket.OPEN is undefined on Workers
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState
  // 0 = CONNECTING, 1 = OPEN, 2 = CLOSING, 3 = CLOSED
  return websocket.readyState === 1;
}

/**
 * @param {WebSocket} websocket
 * @param {number} code
 * @param {string} reason
 * @param {BandwidthStats} bw
 */
function close(websocket, code = 1000, why = "ok", bw) {
  // developers.cloudflare.com/workers/runtime-apis/websockets/#close
  // developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code
  endlog(bw);
  websocket.close(code, why);
}

/**
 * @param {BandwidthStats} bw
 */
function endlog(bw) {
  const dur = (((Date.now() - bw.p) / 1000) | 0) + "s";
  const rx = (bw.rx / 1024).toFixed(3) + "kb";
  const tx = (bw.tx / 1024).toFixed(3) + "kb";
  log.d("ws: close", code, why, "rx/tx/p", rx, tx, dur);
}

function len(arraylike) {
  if (arraylike == null) return 0;
  if (arraylike.byteLength != null) return arraylike.byteLength;
  if (arraylike.length != null) return arraylike.length;
  return 0;
}
