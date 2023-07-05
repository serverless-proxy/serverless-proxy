// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "../base/cfg.js";
import * as log from "../base/log.js";
import * as modres from "../base/res.js";

/**
 * @typedef {{ hostname: string, port: number, transport: string }} Addr
 */

/**
 * @param {URL} u
 * @returns {[string, Addr]}
 */
export function intent(u) {
  const p = u.pathname.split("/");
  if (p.length < 3) {
    // default to echo
    return ["echo", cfg.echoServerAddr];
  }

  const w = p[1];
  let dst = p[2];
  if (w === "yo") {
    dst = dst || cfg.g204Url;
  } else if (!dst) {
    log.d("dst empty");
    return ["", null];
  }

  const dstport = p[3] || "443";
  const proto = p[4] || "tcp";
  const addr = { hostname: dst, port: dstport, transport: proto };

  return [w, addr];
}

/**
 * @param {Request} req
 * @param {string} host
 * @returns {Promise<Response>}
 */
export function tester(req, host) {
  if (req.method === "HEAD") {
    return fetch(host, { method: "HEAD" });
  } else if (req.method === "GET") {
    return fetch(host, { method: "GET" });
  }
  return modres.r405;
}
