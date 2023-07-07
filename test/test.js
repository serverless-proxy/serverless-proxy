#!/usr/bin/env -S deno run --allow-all
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors
const verbose = false;
const proxybase = "https://proxy.nile.workers.dev/";
const enc = new TextEncoder();
const dec = new TextDecoder();

test(proxybase, "echo");
test(proxybase, "h2/nosig/midway.fly.dev/5001");

// also: echo "POSTBODY" | nc midway.fly.dev 5001
async function test(url, path) {
  const u = url + path;
  // deno supports full duplex req / res with fetch
  const b = enc.encode(path + ":POSTBODY\r\n");
  const r = new Request(u, { method: "POST", body: b });
  console.log(u, "send");
  const w = await fetch(r);

  if (verbose) console.debug(u, "req", req, "res", w);

  let con = "";
  for await (const x of w.body) {
    con += dec.decode(x);
  }
  console.log("---  ---  ---  ---");
  console.log(u, "recv", con, "len", con.length);
}
