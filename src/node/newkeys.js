// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "../base/cfg.js";
import * as fs from "node:fs";
import process from "node:process";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import * as brsa from "../webcrypto/blindrsa.js";
import * as bin from "../base/buf.js";
import { rand } from "../webcrypto/hmac.js";

const rsafs = "rsakeys.json";
const pubfs = "rsapubkey.json";
const pskfs = "svcpsk.json";
const prodsvc = "svc";
const prodpx = "ken";
const notprodsvc = "redir";
const notprodpx = "proxy";

export async function saveRsaKey() {
  const x = await brsa.genkey();
  const privstr = JSON.stringify(x[0]);
  const pubstr = JSON.stringify(x[1]);
  const t = (Date.now() / 1000) | 0;
  const skname = cfg.wenvBlindRsaPrivateKeyPrefix + t;
  const pkname = cfg.wenvBlindRsaPublicKeyPrefix + t;
  const keypair = { [skname]: privstr, [pkname]: pubstr };
  fs.writeFileSync(filepath(rsafs), JSON.stringify(keypair, null, 2));
  const pubkey = { [pkname]: pubstr };
  fs.writeFileSync(filepath(pubfs), JSON.stringify(pubkey, null, 2));
}

export async function savePskSvc() {
  const x = rand(64);
  const hex = bin.buf2hex(x);
  const pskname = cfg.wenvPskSvc;
  fs.writeFileSync(
    filepath(pskfs),
    JSON.stringify({ [pskname]: hex }, null, 2)
  );
}

export async function setRsaWranglerSecrets(prod = false) {
  // developers.cloudflare.com/workers/wrangler/commands/#secretbulk
  // wrangler secret:bulk <JSON> --env <ENVIRONMENT> --name <WORKER-NAME>
  const cmd = "wrangler";
  const nom0 = prod ? prodpx : notprodpx;
  const args0 = ["secret:bulk", filepath(rsafs), "--name", nom0];
  const ok = sh(cmd, args0);
  if (!ok) {
    throw new Error("wrangler rsa secret:bulk failed for " + nom0);
  }

  // store public key with worker, svc
  // wrangler has trouble with PUT even if the json value is stringified.
  // const x = JSON.parse(fs.readFileSync(filepath(rsafs)));
  // const pkname = Object.keys(x)[1];
  // const pk = x[pkname];
  // developers.cloudflare.com/workers/wrangler/commands/#put-3
  // wrangler secret put <KEY> --env <ENVIRONMENT> --name <WORKER-NAME>
  // const args1 = ["secret", "put", pkname, pk];
  const nom1 = prod ? prodsvc : notprodsvc;
  const args1 = ["secret:bulk", filepath(pubfs), "--name", nom1];
  const ok1 = sh(cmd, args1);
  if (!ok1) {
    throw new Error("wrangler rsa secret:bulk failed for " + nom1);
  }
}

export async function deleteOlderRsaWranglerSecrets(
  prod = false,
  keep = 3
) {
  if (keep < 1) {
    console.warn("keep min 1 key");
    keep = 1;
  }
  // wrangler secret list --env <ENVIRONMENT> --name <WORKER-NAME>
  /*[{
    "name": "PRIVATE_KEY_BLINDRSA_1688718046",
    "type": "secret_text"
  },
  {
    "name": "PUBLIC_KEY_BLINDRSA_1688718046",
    "type": "secret_text"
  },
  {
    "name": "SECRET_MAC_KEY_A",
    "type": "secret_text"
  }]*/
  const cmd = "wrangler";
  const nom = prod ? prodpx : notprodpx;
  const args = ["secret", "list", "--name", nom];
  const [ok, out] = shout(cmd, args);
  if (!ok || !out) {
    const err = "wrangler secret list failed for " + nom;
    console.error(err, "output", out);
    throw new Error(err);
  }
  const x = JSON.parse(out);
  const privprefix = cfg.wenvBlindRsaPrivateKeyPrefix;
  const pubprefix = cfg.wenvBlindRsaPublicKeyPrefix;
  const y = x
    .filter((e) => e.name.startsWith(privprefix))
    .map((e) => e.name.slice(privprefix.length));
  if (keep >= y.length) {
    console.warn(`more keys to del than total0: ${keep} >= ${y.length}`);
    return;
  }
  const ascend = y.sort((a, b) => {
    const l = parseInt(a);
    const r = parseInt(b);
    return l - r;
  });
  if (keep >= ascend.length) {
    console.warn(`more keys to del than total1: ${keep} >= ${ascend.length}`);
    return;
  }
  const del = ascend.slice(0, -keep);
  if (del.length < 1) {
    console.warn("no keys to delete");
    return;
  }
  // wrangler secret delete <KEY> --env <ENVIRONMENT> --name <WORKER-NAME>
  for (const e of del) {
    const sk = privprefix + e;
    const pk = pubprefix + e;
    const nom0 = prod ? prodpx : notprodpx;
    const nom1 = prod ? prodsvc : notprodsvc;
    const argssk0 = ["secret", "delete", sk, "--name", nom0];
    const argspk0 = ["secret", "delete", pk, "--name", nom0];
    const argspk1 = ["secret", "delete", pk, "--name", nom1];
    // cannot execute wrangler delete as it is interactive (y/n)
    console.log("deleting", sk, pk, "for", nom0, "&", nom1);
    shin(cmd, argssk0, "Y"); // Y/n
    shin(cmd, argspk0, "Y"); // Y/n
    shin(cmd, argspk1, "Y"); // Y/n
  }
}

export async function setPskWranglerSecret(prod) {
  // wrangler secret:bulk <JSON> --env <ENVIRONMENT> --name <WORKER-NAME>
  const cmd = "wrangler";
  const nom0 = prod ? prodpx : notprodpx;
  const args0 = ["secret:bulk", filepath(pskfs), "--name", nom0];
  const ok0 = sh(cmd, args0);
  if (!ok0) {
    throw new Error("sproxy: wrangler psk secret:bulk failed");
  }
  // store public key with worker, svc
  // or: wrangler secret put <KEY> --env <ENVIRONMENT> --name <WORKER-NAME>
  const nom1 = prod ? prodsvc : notprodsvc;
  const args1 = ["secret:bulk", filepath(pskfs), "--name", nom1];
  const ok1 = sh(cmd, args1);
  if (!ok1) {
    throw new Error("svc: wrangler psk secret:bulk failed");
  }
}

function sh(cmd, args) {
  const [ok, out] = shout(cmd, args);
  if (!ok) console.error(cmd, args, "error", out);
  else console.debug(out);
  return ok;
}

function shout(cmd, args) {
  if (!cmd) return false;
  args = args || [];
  const opts = {
    cwd: "/",
    shell: true,
    encoding: "utf8",
  };
  const proc = spawnSync(cmd, args, opts);
  const ok = proc.status === 0;
  if (proc.stderr) return [ok, proc.stderr];
  if (proc.error) return [ok, proc.error];
  if (proc.stdout) return [ok, proc.stdout];
  return [ok, ""];
}

function shin(cmd, args, line) {
  if (!cmd) return false;
  args = args || [];
  const opts = {
    cwd: "/",
    shell: true,
    encoding: "utf8",
  };
  const proc = spawn(cmd, args, opts);

  proc.stdout.pipe(process.stdout);
  proc.stderr.pipe(process.stderr);

  proc.stdin.cork();
  if (line) proc.stdin.write(line + "\n");
  proc.stdin.uncork(); // flush
  proc.stdin.end();

  proc.addListener("error", (err) => {
    console.error("shin error", cmd, args, err);
  });
  proc.addListener("exit", (code, signal) => {
    console.log("shin exit", cmd, args, code, signal);
  });
}

function filepath(f) {
  if (typeof f !== "string" || !f) throw new Error("filepath: invalid arg");
  return path.join(process.cwd(), f);
}
