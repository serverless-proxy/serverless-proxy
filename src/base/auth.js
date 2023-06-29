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
  if (!emptyString(seed) && !emptyString(ctx)) {
    try {
      const sk = hex2buf(seed);
      const sk256 = sk.slice(0, hkdfalgkeysz);
      const info512 = await sha512(str2byte(ctx));
      return await gen(sk256, info512);
    } catch (ignore) {}
  }
  return null;
}

// Scenario 4: privacypass.github.io/protocol
export async function verifyClaim(sk, fullthex, msghex, msgmachex) {
  try {
    const y1 = verifyExpiry(fullthex);
    if (!y1) {
        log.d("verifyClaim: expired");
        return notok;
    }
    const [hashedthex, shex] = await deriveIssue(sk, fullthex);
    if (!hashedthex || !shex) {
      log.d("verifyClaim: cannot derive tok/sig");
      return notok;
    }
    const y2 = await verifyMessage(shex, msghex, msgmachex);
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
export async function issue(sigkey, hashedthex) {
  if (emptyString(hashedthex) || hashedthex.length !== 64) {
    return null;
  }
  // expires in 30days
  const expiryMs = Date.now() + 30 * 24 * 60 * 60 * 1000;
  // expiryHex will not exceed 11 chars until 17592186044415 (year 2527)
  // 17592186044415 = 0xfffffffffff
  const expiryHex = expiryMs.toString(16);
  hashedthex = expiryHex + hashedthex;
  const hashedtoken = hex2buf(hashedthex);
  const sig = await hmacsign(sigkey, hashedtoken);
  const shex = buf2hex(sig);
  return [hashedthex, shex];
}

async function deriveIssue(sigkey, fullthex) {
  const expiryHex = fullthex.slice(0, 11);
  const userthex = fullthex.slice(11);
  const usertoken = hex2buf(userthex);
  const userhashedtoken = await sha256(usertoken);
  const hashedthex =  expiryHex + buf2hex(userhashedtoken);
  const hashedtoken = hex2buf(hashedthex);
  const sig = await hmacsign(sigkey, hashedtoken);
  const shex = buf2hex(sig);
  return [hashedthex, shex];
}

export async function message(shex, msghex) {
  const sig = hex2buf(shex);
  const sigkey = await hmackey(sig);
  const msg = hex2buf(msghex);
  const mac = await hmacsign(sigkey, msg);
  const machex = buf2hex(mac);
  return machex;
}

async function verifyMessage(shex, msgstr, msgmachex) {
  const sig = hex2buf(shex);
  const sigkey = await hmackey(sig);
  const msg = hex2buf(msgstr);
  const mac = hex2buf(msgmachex);
  return hmacverify(sigkey, mac, msg);
}

function verifyExpiry(thex) {
  // expect expiry in hex, at the start of thex; see issue()
  const expiryHex = thex.slice(0, 11);
  const expiryMs = hex2num(expiryHex);
  return expiryMs >= Date.now();
}

export function rand(sz = 16) {
  const t = new Uint8Array(sz);
  crypto.getRandomValues(t);
  return t;
}

async function hmacsign(ck, m) {
  return crypto.subtle.sign("HMAC", ck, m);
}

async function hmacverify(ck, mac, m) {
  return crypto.subtle.verify("HMAC", ck, mac, m);
}

// salt for hkdf can be zero: stackoverflow.com/a/64403302
async function gen(secret, info, salt = ZEROBUF) {
  if (emptyBuf(secret) || emptyBuf(info)) {
    throw new Error("auth: empty secret/info");
  }

  // exportable: crypto.subtle.exportKey("raw", key);
  return hkdfhmac(secret, info, salt);
}

// with hkdf, salt is optional and public, but if used,
// for a given secret (Z) it needn't be unique per use,
// but it *must* be random:
// cendyne.dev/posts/2023-01-30-how-to-use-hkdf.html
// info adds entropy to extracted keys, and must be unique:
// see: soatok.blog/2021/11/17/understanding-hkdf
async function hkdfhmac(skmac, usectx, salt = ZEROBUF) {
  const dk = await hkdf(skmac);
  return crypto.subtle.deriveKey(
    hkdf256(salt, usectx),
    dk,
    hmac256opts(),
    true, // extractable? can be true for sign, verify
    ["sign", "verify"] // usage
  );
}

async function hmackey(sk) {
  return crypto.subtle.importKey(
    "raw",
    sk,
    hmac256opts(),
    false, // extractable? always false for use as derivedKey
    ["sign", "verify"] // usage
  );
}

async function hkdf(sk) {
  return crypto.subtle.importKey(
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

async function sha256(buf) {
  const ab = await crypto.subtle.digest("SHA-256", buf);
  return byt(ab);
}

async function sha512(buf) {
  const ab = await crypto.subtle.digest("SHA-512", buf);
  return byt(ab);
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

// given a buffer b, returns its uint8array view
function byt(b) {
  if (emptyBuf(b)) return ZEROBUF;
  const ab = raw(b);
  return new Uint8Array(ab);
}

function buf2hex(b) {
  const u8 = byt(b);
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
