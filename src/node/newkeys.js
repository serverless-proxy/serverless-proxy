// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "../base/cfg.js";
import * as fs from "node:fs";
import * as brsa from "../webcrypto/blindrsa.js";

const jfs = "rsakeys.json";

export async function saveRsaKey() {
  const x = await brsa.genkey();
  const privstr = JSON.stringify(x[0]);
  const pubstr = JSON.stringify(x[1]);
  const t = (Date.now() / 1000) | 0;
  const skname = cfg.wenvBlindRsaPrivateKeyPrefix + t;
  const pkname = cfg.wenvBlindRsaPublicKeyPrefix + t;
  const json = { [skname]: privstr, [pkname]: pubstr };
  fs.writeFileSync(jfs, JSON.stringify(json, null, 2));
}

export async function setWranglerSecrets(prod) {
  // developers.cloudflare.com/workers/wrangler/commands/#secretbulk
  // wrangler secret:bulk <JSON> --env <ENVIRONMENT> --name <WORKER-NAME>
  const cmd = "wrangler";
  const args = ["secret:bulk", jfs];
  if (prod) {
    args.push("--env");
    args.push("prod");
  }
  const ok = sh(cmd, args);
  if (!ok) {
    const ex = "wrangler secret put failed"
    throw new Error(ex);
  }
  // store public key with worker, svc
  if (prod) {
    // const x = JSON.parse(fs.readFileSync("rsakeys.json"));
    // const pkname = Object.keys(x)[1];
    // const pk = x[pkname];
    // developers.cloudflare.com/workers/wrangler/commands/#put-3
    // wrangler secret put <KEY> --env <ENVIRONMENT> --name <WORKER-NAME>
    // const args = ["secret", "put", pkname, pk, "--name", "svc"];
  }
}

function sh(cmd, args) {
  if (!cmd) return false;
  args = args || [];
  const opts = {
    cwd: "/",
    shell: true,
    encoding: "utf8",
  };
  const proc = spawnSync(cmd, args, opts);
  if (proc.error) console.info(cmd, args, opts, "error", proc.error);
  if (proc.stderr) console.error(cmd, args, opts, proc.stderr);
  if (proc.stdout) console.log(proc.stdout);
  return proc.status === 0;
}
