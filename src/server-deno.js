// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

import * as cfg from "./base/cfg.js";
import * as h2 from "./proxifier/h2.js";
import * as svc from "./core/svc.js";
import * as ws from "./proxifier/ws.js";
import * as modres from "./base/res.js";
import * as log from "./base/log.js";

serve(handle);

/**
 * @param {Request} req
 * @returns {Response}
 */
async function handle(req) {
  log.d("fetch: serving", req.url);
  const u = new URL(req.url);
  const [what, addr] = svc.intent(u);

  if (what.startsWith("yo")) {
    log.d("svc: test");
    return svc.tester(req, addr.hostname);
  }

  // todo: impl auth
  try {
    if (what.startsWith("ws")) {
      if (!ws.isWs(req)) {
        return modres.r426();
      }
      log.d("ws: connect", addr);
      const sock = await mksocket(addr);
      return ws.accept(sock);
    } else if (what.startsWith("h2")) {
      log.d("pipe: connect", addr);
      const sock = await mksocket(addr);
      return h2.pipe(req, sock);
    } else if (what.startsWith("echo")) {
      log.d("echo: start");
      const sock = await mksocket(addr);
      return h2.echo(sock);
    }
  } catch (err) {
    log.e("fetch:", err);
  }
  return modres.r400;
}

async function mksocket(addr) {
  // ref: developers.cloudflare.com/workers/runtime-apis/tcp-sockets
  return Deno.connect(addr, cfg.tcpOpts);
}
