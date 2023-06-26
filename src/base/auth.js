// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as log from "./log.js";

const ZEROBUF = new Uint8Array(0);
const hkdfalgkeysz = 32; // sha256

export const claimPrefix = "pip_";
export const claimDelim = ":";

const tencoder = new TextEncoder();
const tdecoder = new TextDecoder();

export const ok = 1;
export const notok = 2;

export async function keygen(seed, ctx) {
  if (!emptyStr(seed) && !emptyString(ctx)) {
    try {
      const sk = hex2buf(seed);
      const sk256 = sk.slice(0, hkdfalgkeysz);
      const info512 = await sha512(str2byte(ctx));
      return await gen(sk256, info512);
    } catch (ignore) {}
  }
  return null;
}

export async function verifyClaim(sk, thex, shex, msg, mac) {
  try {
    const y0 = verifyExpiry(thex);
    if (!y0) {
        log.d("verifyClaim: expired");
        return notok;
    }
    const y1 = await verifyIssue(sk, thex, shex);
    if (!y1) {
      log.d("verifyClaim: invalid tok/sig");
      return notok;
    }
    const y2 = await verifyMessage(shex, msg, mac);
    if (!y2) {
      log.d("verifyClaim: invalid msg/mac");
      return notok;
    }
    return ok;
  } catch (ignore) {
    log.d("verifyClaim: err", ignore);
  }
  return notok;
}

// Scenario 4: privacypass.github.io/protocol
export async function issue(hmackey, thex) {
  // expires in 30days
  const expiryMs = Date.now() + 30 * 24 * 60 * 60 * 1000;
  // expiryHex will not exceed 11 chars until 17592186044415 (year 2527)
  // 17592186044415 = 0xfffffffffff
  const expiryHex = expiryMs.toString(16);
  if (!emptyString(thex) && thex.length === 64) {
    thex = expiryHex + thex;
  } else {
    thex = expiryHex + buf2hex(rand(32));
  }
  const token = hex2buf(thex);
  const sig = await crypto.subtle.sign("HMAC", hmackey, token);
  const shex = buf2hex(sig);
  return [thex, shex];
}

async function verifyIssue(hmackey, thex, shex) {
  // verify a signed token
  const token = hex2buf(thex);
  const sig = hex2buf(shex);
  return await crypto.subtle.verify("HMAC", hmackey, sig, token);
}

export async function message(shex, msgstr) {
  const sig = hex2buf(shex);
  const sigkey = await hmackey(sig);
  const msg = hex2buf(msgstr);
  const mac = await crypto.subtle.sign("HMAC", sigkey, msg);
  const machex = buf2hex(mac);
  return machex;
}

async function verifyMessage(shex, msgstr, msgmachex) {
  const sig = hex2buf(shex);
  const sigkey = await hmackey(sig);
  const msg = hex2buf(msgstr);
  const mac = await crypto.subtle.sign("HMAC", sigkey, msg);
  const machex = buf2hex(mac);
  return machex === msgmachex;
}

function verifyExpiry(thex) {
  // expect expiry in hex, at the start of thex; see issue()
  const expiryHex = thex.slice(0, 11);
  const expiryMs = hex2num(expiryHex);
  return expiryMs >= Date.now();
}

function rand(sz = 16) {
  const t = new Uint8Array(sz);
  crypto.getRandomValues(t);
  return t;
}

// salt for hkdf can be zero: stackoverflow.com/a/64403302
async function gen(secret, info, salt = ZEROBUF) {
  if (emptyBuf(secret) || emptyBuf(info)) {
    throw new Error("auth: empty secret/info");
  }

  // exportable: crypto.subtle.exportKey("raw", key);
  return (key = await hkdfhmac(secret, info, salt));
}

// with hkdf, salt is optional and public, but if used,
// for a given secret (Z) it needn't be unique per use,
// but it *must* be random:
// cendyne.dev/posts/2023-01-30-how-to-use-hkdf.html
// info adds entropy to extracted keys, and must be unique:
// see: soatok.blog/2021/11/17/understanding-hkdf
async function hkdfhmac(skmac, usectx, salt = ZEROBUF) {
  const dk = await hkdf(skmac);
  return await crypto.subtle.deriveKey(
    hkdf256(salt, usectx),
    dk,
    hmac256opts(),
    true, // extractable? can be true for sign, verify
    ["sign", "verify"] // usage
  );
}

async function hmackey(sk) {
  return await crypto.subtle.importKey(
    "raw",
    sk,
    hmac256opts(),
    false, // extractable? always false for use as derivedKey
    ["sign", "verify"] // usage
  );
}

async function hkdf(sk) {
  return await crypto.subtle.importKey(
    "raw",
    sk,
    "HKDF",
    false, // extractable? always false for use as derivedKey
    ["deriveKey"] // usage
  );
}

function hmac256opts() {
  return { name: "HMAC", hash: "SHA-256" };
}

function hkdf256(salt, usectx) {
  return { name: "HKDF", hash: "SHA-256", salt: salt, info: usectx };
}

async function sha512(buf) {
  const ab = await crypto.subtle.digest("SHA-512", buf);
  return new Uint8Array(ab);
}

function str2byte(s) {
  return tencoder.encode(s);
}

function byte2str(b) {
  return tdecoder.decode(b);
}

// given a buffer b, returns the underlying array buffer
function raw(b) {
  if (emptyBuf(b)) return ZEROBUF.buffer;
  if (b instanceof ArrayBuffer) return b;
  return b.buffer;
}

function buf2hex(b) {
  const u8 = new Uint8Array(raw(b));
  return Array.from(u8)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hex2buf(h) {
  return new Uint8Array(h.match(/.{1,2}/g).map((w) => parseInt(w, 16)));
}

function num2hex(n) {
  return n.toString(16).padStart(2, "0");
}

function hex2num(h) {
  return parseInt(h, 16);
}

// check if Buffer is empty
function emptyBuf(b) {
  return !b || b.byteLength === 0;
}

function emptyString(s) {
  if (typeof s === "string") {
    // todo: trim
    return !s || s.length === 0;
  } else {
    return false;
  }
}
