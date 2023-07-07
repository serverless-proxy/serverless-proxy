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
const notprodpx = "redir";

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
    const ex = "wrangler rsa secret put failed";
    throw new Error(ex);
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
    throw new Error("svc: wrangler psk secret put failed");
  }
}

export async function deleteOlderRsaWranglerSecrets(
  prod = false,
  max = 3,
  min = 2
) {
  if (min < 1) {
    console.warn("min keys cannot be less than 1");
    min = 1;
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
    const err = "wrangler secret list failed";
    console.error(err, "output", out);
    throw new Error(err);
  }
  const x = JSON.parse(out);
  const privprefix = cfg.wenvBlindRsaPrivateKeyPrefix;
  const pubprefix = cfg.wenvBlindRsaPublicKeyPrefix;
  const y = x
    .filter((e) => e.name.startsWith(privprefix))
    .map((e) => e.name.slice(privprefix.length));
  if (y.length <= max) {
    return;
  }
  const ascend = y.sort((a, b) => {
    const l = parseInt(a);
    const r = parseInt(b);
    return l - r;
  });
  if (max > ascend.length) {
    max = ascend.length;
  }
  let del = ascend.slice(0, max);
  const rem = del.length + min - ascend.length;
  if (rem < 0) {
    del = del.slice(0, rem);
    const l = del.length;
    console.warn(`can't del ${max} keys, need atleast ${min}; new size ${l}`);
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
    console.log("deleting", sk, pk);
    shin(cmd, argssk0, "Y"); // Y/n
    shin(cmd, argspk0, "Y"); // Y/n
    shin(cmd, argspk1, "Y"); // Y/n
  }
}

export async function setPskWranglerSecret(prod) {
  // wrangler secret:bulk <JSON> --env <ENVIRONMENT> --name <WORKER-NAME>
  const cmd = "wrangler";
  const args0 = ["secret:bulk", filepath(pskfs)];
  const ok0 = sh(cmd, args0);
  if (!ok0) {
    throw new Error("sproxy: wrangler psk secret put failed");
  }
  // store public key with worker, svc
  // or: wrangler secret put <KEY> --env <ENVIRONMENT> --name <WORKER-NAME>
  const nom1 = prod ? prodsvc : notprodsvc;
  const args1 = ["secret:bulk", filepath(pskfs), "--name", nom1];
  const ok1 = sh(cmd, args1);
  if (!ok1) {
    throw new Error("svc: wrangler psk secret put failed");
  }
}

function sh(cmd, args) {
  const [ok, out] = shout(cmd, args);
  if (!ok) console.error(cmd, args, opts, "error", out);
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
