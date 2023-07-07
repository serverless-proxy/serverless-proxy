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
  // /[yo|ws|h2|h3]/rsasig/hostname/port/proto
  const p = u.pathname.split("/");
  if (p.length < 3) {
    // default to echo
    return ["echo", cfg.echoServerAddr];
  }

  const w = p[1];
  // const sig = p[2];
  let dst = p[3];
  if (w === "yo") {
    dst = dst || cfg.g204Url;
  } else if (!dst) {
    log.d("dst empty");
    return ["", null];
  }

  const dstport = p[4];
  const proto = p[5];
  if (!dstport || !proto) {
    log.d("dstport or proto empty");
    return ["", null];
  }

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
