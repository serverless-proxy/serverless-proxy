// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "../base/cfg.js";
import * as modres from "../base/res.js";
import * as log from "../base/log.js";

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
export async function accept(egress, waiter = (p) => p) {
  // github.com/cloudflare/websocket-template/blob/main/index.js
  // developers.cloudflare.com/workers/learning/using-websockets
  const [client, server] = Object.values(new WebSocketPair());

  server.accept();
  const ingress = await duplex(server);

  log.d("ws: accept: eg? ing?", egress != null, ingress != null);

  if (ingress) {
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
      .catch((ex) => log.e("pipe: out2in", ex.message))
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
  // developer.mozilla.org/en-US/docs/Web/API/ReadableStream/ReadableStream
  const r = new ReadableStream({
    start(rctl) {
      chain(websocket, rctl);
      log.d("ws: readable started");
    },
    cancel(reason) {
      close(websocket, 1014, reason);
    },
  });

  // developer.mozilla.org/en-US/docs/Web/API/WritableStream/WritableStream
  const w = new WritableStream({
    start(wctl) {
      log.d("ws: writable started");
    },
    write(chunk, wctl) {
      const ok = wsok(websocket);
      log.d("ws: write?", ok, "d?", chunk != null, "ctl?", wctl != null);
      // developer.mozilla.org/en-US/docs/Web/API/WritableStreamDefaultController
      if (ok) websocket.send(chunk);
      else if (wctl) wctl.error("websocket closed");
    },
    close(wctl) {
      close(websocket, 1000, "remote closed");
      // on workers, wctl is undefined?
      if (wctl) wctl.close();
    },
    abort(reason) {
      close(websocket, 1014, reason);
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
 */
function chain(websocket, reader) {
  // developers.cloudflare.com/workers/runtime-apis/websockets
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/message_event
  websocket.addEventListener("message", (what) => {
    const { data, type } = what;
    log.d("ws: recv", data, type);
    if (data) reader.enqueue(data);
  });
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/close_event
  websocket.addEventListener("close", (why) => {
    const { code, reason, wasClean } = why;
    log.d("ws: close", code, reason, "clean?", wasClean);
    close(websocket, code, reason);
    reader.close();
  });
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/error_event
  websocket.addEventListener("error", (event) => {
    log.e("ws: err", event.message);
    reader.error(event);
  });
}

/**
 * @param {WebSocket} websocket
 * @returns {boolean}
 */
function wsok(websocket) {
  log.d("ws: state?", websocket.readyState);
  // WebSocket.OPEN is undefined on Workers
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState
  // 0 = CONNECTING, 1 = OPEN, 2 = CLOSING, 3 = CLOSED
  return websocket.readyState === 1;
}

/**
 * @param {WebSocket} websocket
 * @param {number} code
 * @param {string} reason
 */
function close(websocket, code = 1000, reason = "ok") {
  // developers.cloudflare.com/workers/runtime-apis/websockets/#close
  // developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code
  log.d("ws: close", code, reason);
  websocket.close(code, reason);
}
