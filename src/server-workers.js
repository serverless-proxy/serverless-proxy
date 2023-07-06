// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as auth from "./core/auth.js";
import * as net from "cloudflare:sockets";
import * as cfg from "./base/cfg.js";
import * as h2 from "./proxifier/h2.js";
import * as svc from "./core/svc.js";
import * as wsvc from "./workers/wsvc.js";
import * as ws from "./proxifier/ws.js";
import * as modres from "./base/res.js";
import * as log from "./base/log.js";

export default {
  async fetch(req, env, ctx) {
    log.key(env.LOG_LEVEL);
    log.d(env.LOG_LEVEL, "fetch: serving", req.url);
    const dispatch = ctx.waitUntil.bind(ctx);
    const u = new URL(req.url);
    const [what, addr] = svc.intent(u);

    if (what.startsWith("yo")) {
      log.d("svc: test");
      return svc.tester(req, addr.hostname);
    } else if (what.startsWith("sign")) {
      log.d("auth: sign");
      return wsvc.sign(req, env, ctx);
    } else if (what.startsWith("iss")) {
      log.d("auth: issue");
      return wsvc.issue(req, env, ctx);
    }

    const authres = await wsvc.allow(req, env, ctx);
    if (authres !== auth.ok) {
      log.d("auth: failed");
      return modres.r503;
    }

    try {
      if (what.startsWith("ws")) {
        if (!ws.isWs(req)) {
          return modres.r426();
        }
        log.d("ws: connect", addr);
        const sock = mksocket(addr);
        return ws.accept(sock, dispatch);
      } else if (what.startsWith("h3") || what.startsWith("h2")) {
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
