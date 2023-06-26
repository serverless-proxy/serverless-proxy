// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors
import * as auth from "./base/auth.js";
import * as net from "cloudflare:sockets";
import * as cfg from "./base/cfg.js";
import * as h2 from "./proxifier/h2.js";
import * as svc from "./base/svc.js";
import * as ws from "./proxifier/ws.js";
import * as modres from "./base/res.js";
import * as log from "./base/log.js";

export default {
  async fetch(req, env, ctx) {
    const authres = await svc.allow(req, env, ctx);
    if (authres !== auth.ok) {
      log.d("auth failed");
      return modres.r503;
    }

    const dispatch = ctx.waitUntil.bind(ctx);
    const u = new URL(req.url);
    const [what, addr] = svc.intent(u);

    try {
      if (what.startsWith("ws")) {
        if (!ws.isWs(req)) {
          return new modres.r426();
        }
        log.d("ws: connect", addr);
        const sock = mksocket(addr);
        return ws.accept(sock, dispatch);
      } else if (what.startsWith("h2")) {
        log.d("pipe: connect", addr);
        const sock = mksocket(addr);
        return h2.pipe(req, sock, dispatch);
      } else if (what.startsWith("echo")) {
        log.d("echo: start");
        const sock = mksocket(addr);
        return h2.echo(sock);
      }
    } catch (err) {
      log.e("fetch:", err);
    }
    return modres.r400;
  },
};

function mksocket(addr) {
  // ref: developers.cloudflare.com/workers/runtime-apis/tcp-sockets
  return net.connect(addr, cfg.tcpOpts);
}