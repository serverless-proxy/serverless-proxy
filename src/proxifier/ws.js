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
export function accept(egress, waiter = (p) => p) {
  // developers.cloudflare.com/workers/learning/using-websockets
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  // github.com/cloudflare/websocket-template/blob/main/index.js
  pipe(duplex(server), egress, waiter);
  return Response(null, {
    status: 101,
    webSocket: client,
  });
}

/**
 * @param {TransformStream} ingress
 * @param {TransformStream} egress
 * @param {function(Promise)} waiter
 * @returns {Response}
 */
export async function pipe(ingress, egress, waiter = (p) => p) {
  try {
    // 1. pipe without await
    // 2. do not close egress on completion
    waiter(ingress.readable.pipeTo(egress.writable, { preventClose: true }));
    // stream the response out
    // blog.cloudflare.com/workers-optimization-reduces-your-bill
    waiter(egress.readable.pipeTo(ingress.writable, { preventClose: true }));
  } catch (ex) {
    log.e("pipe: err", ex);
    return modres.r500;
  }
}

/**
 * @param {WebSocket} websocket
 * @returns {{r: ReadableStream, w: WritableStream}}
 */
function duplex(websocket) {
  const ok = setup(websocket);
  // developer.mozilla.org/en-US/docs/Web/API/ReadableStream/ReadableStream
  const r = new ReadableStream({
    async start(rctl) {
      await ok;
      chain(websocket, rctl);
    },
    cancel(reason) {
      close(websocket, 1014, reason);
    },
  });

  // developer.mozilla.org/en-US/docs/Web/API/WritableStream/WritableStream
  const w = new WritableStream({
    async start(wctl) {
      return await ok;
    },
    async write(chunk, wctl) {
      // developer.mozilla.org/en-US/docs/Web/API/WritableStreamDefaultController
      if (wsok(websocket)) websocket.send(chunk);
      else wctl.error("websocket closed");
    },
    close(wctl) {
      close(websocket, 1000, "remote closed");
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
  let yes, no, timer;
  const promise = new Promise((resolve, reject) => {
    yes = resolve.bind(this);
    no = reject.bind(this);
    timer = setTimeout(no, cfg.wsConnTimeoutMs);
  });
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket
  websocket.addEventListener("open", (event) => {
    log.d("ws: open", event);
    clearTimeout(timer);
    yes();
  });
  websocket.addEventListener("error", (event) => {
    log.e("ws: error", event);
    // no() has no effect if yes() has already been called
    clearTimeout(timer);
    no();
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
    log.d("ws: message", type, data);
    const { data, type } = what;
    reader.enqueue(data);
  });
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/close_event
  websocket.addEventListener("close", (why) => {
    const { code, reason, wasClean } = why;
    log.d("ws: close", code, reason, "clean?", wasClean);
    close(websocket);
    reader.close();
  });
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/error_event
  websocket.addEventListener("error", (event) => {
    log.e("ws: error", event);
    reader.error(what);
  });
}

function wsok(websocket) {
  // developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState
  return websocket.readyState === WebSocket.OPEN;
}

function close(websocket, code = 1000, reason = "ok") {
  // developers.cloudflare.com/workers/runtime-apis/websockets/#close
  // developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code
  log.d("ws: close", code, reason);
  websocket.close(code, reason);
}
