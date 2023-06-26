// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "./cfg.js";
import * as log from "./log.js";
import * as auth from "./auth.js";

/**
 * @param {URL} u
 * @returns {[string, any]}
 */
export function intent(u) {
  const p = u.pathname.split("/");
  if (p.length < 3) {
    // default to echo
    return ["echo", cfg.echoServerAddr];
  }

  const w = p[1];
  const dst = p[2];
  const dstport = p[3] || "443";
  const proto = p[4] || "tcp";
  if (!dst) {
    log.d("dst empty");
    return ["", null];
  }

  const addr = { hostname: dst, port: dstport, transport: proto };
  return [w, addr];
}

export async function allow(r, env) {
  const h = r.headers.get(cfg.headerClaim);
  const msg = r.headers.get(cfg.headerMsg);

  if (cfg.bypassAuth) {
    log.w("auth: bypass", "claim?", h, "msg?", msg);
    return auth.ok;
  }

  if (!h || !msg) {
    log.d("auth: no claim or msg");
    return auth.notok;
  }

  const sk = await auth.keygen(env.SECRET_KEY_MAC_A, cfg.authContext);
  if (!sk) {
    log.e("auth: no sk");
    return auth.notok;
  }

  const [tok, sig, mac] = h.replace(auth.claimPrefix).split(auth.claimDelim);
  return await auth.verifyClaim(sk, tok, sig, msg, mac);
}
