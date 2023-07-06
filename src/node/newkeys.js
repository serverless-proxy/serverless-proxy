// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "../base/cfg.js";
import * as fs from "node:fs";
import * as brsa from "../webcrypto/blindrsa.js";
import * as bin from "../base/buf.js";
import { rand } from "../webcrypto/hmac.js";

const jfs = "rsakeys.json";
const pskfs = "svcpsk.json";

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

export async function savePskSvc() {
  const x = rand(64);
  const hex = bin.buf2hex(x);
  const pskname = cfg.wenvPskSvc;
  fs.writeFileSync(pskfs, JSON.stringify({ [pskname]: hex }, null, 2));
}

export async function setRsaWranglerSecrets(prod) {
  // developers.cloudflare.com/workers/wrangler/commands/#secretbulk
  // wrangler secret:bulk <JSON> --env <ENVIRONMENT> --name <WORKER-NAME>
  const cmd = "wrangler";
  const args0 = ["secret:bulk", jfs];
  if (prod) {
    args0.push("--name");
    args0.push("ken");
  } else {
    args0.push("--name");
    args0.push("proxy");
  }
  const ok = sh(cmd, args0);
  if (!ok) {
    const ex = "wrangler rsa secret put failed";
    throw new Error(ex);
  }

  // store public key with worker, svc
  const x = JSON.parse(fs.readFileSync("rsakeys.json"));
  const pkname = Object.keys(x)[1];
  const pk = x[pkname];
  // developers.cloudflare.com/workers/wrangler/commands/#put-3
  // wrangler secret put <KEY> --env <ENVIRONMENT> --name <WORKER-NAME>
  const args1 = ["secret", "put", pkname, pk];
  if (prod) {
    args1.push("--name");
    args1.push("svc");
  } else {
    args1.push("--name");
    args1.push("redir");
  }
  const ok1 = sh(cmd, args1);
  if (!ok1) {
    throw new Error("svc: wrangler psk secret put failed");
  }
}

export async function setPskWranglerSecrets(prod) {
  // wrangler secret:bulk <JSON> --env <ENVIRONMENT> --name <WORKER-NAME>
  const cmd = "wrangler";
  const args0 = ["secret:bulk", pskfs];
  const ok0 = sh(cmd, args0);
  if (!ok0) {
    throw new Error("sproxy: wrangler psk secret put failed");
  }
  // store public key with worker, svc
  // or: wrangler secret put <KEY> --env <ENVIRONMENT> --name <WORKER-NAME>
  const args1 = ["secret:bulk", pskfs];
  if (prod) {
    args1.push("--name");
    args1.push("svc");
  } else {
    args1.push("--name");
    args1.push("redir");
  }
  const ok1 = sh(cmd, args1);
  if (!ok1) {
    throw new Error("svc: wrangler psk secret put failed");
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
