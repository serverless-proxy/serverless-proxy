// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "../base/cfg.js";
import * as modres from "../base/res.js";
import * as log from "../base/log.js";

/**
 * Sends a preset str to socket, writing the output to a Response.
 * @param {TransformStream} socket
 * @returns {Response}
 */
export async function echo(socket) {
  try {
    const enc = new TextEncoder();
    const u8 = enc.encode("GET-IPADDR\r\n");
    const writer = socket.writable.getWriter();
    await writer.ready;
    await writer.write(u8);

    log.d("echo: write done");

    return new Response(socket.readable, { headers: cfg.h2header });
  } catch (ex) {
    log.e("fixed: err", ex);
    return modres.r500;
  }
}

/**
 * Stream req.body to egress, writing the output into res.body.
 * @param {Request} req
 * @param {TransformStream} egress
 * @param {function(Promise)} waiter
 * @returns {Promise<Response>}
 */
export async function pipe(req, egress, waiter = (p) => p) {
  // ingress is null when request is GET or HEAD
  const ingress = req.body;
  if (ingress == null) {
    log.d("ingress missing");
    return modres.r400;
  }

  try {
    // 1. pipe without await
    // 2. do not close egress on completion
    waiter(ingress.pipeTo(egress.writable, { preventClose: true }));
    // stream the response out
    // blog.cloudflare.com/workers-optimization-reduces-your-bill
    return new Response(egress.readable, { headers: cfg.h2header });
  } catch (ex) {
    log.e("pipe: err", ex);
    return modres.r500;
  }
}
