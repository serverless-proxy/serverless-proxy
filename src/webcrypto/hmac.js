// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors.

import * as bin from "../base/buf.js";

export const hkdfalgkeysz = 32; // sha256

export function rand(sz = 16) {
  const t = new Uint8Array(sz);
  crypto.getRandomValues(t);
  return t;
}

export async function hmacsign(ck, m) {
  return crypto.subtle.sign("HMAC", ck, m);
}

export async function hmacverify(ck, mac, m) {
  return crypto.subtle.verify("HMAC", ck, mac, m);
}

// with hkdf, salt is optional and public, but if used,
// for a given secret (Z) it needn't be unique per use,
// but it *must* be random:
// cendyne.dev/posts/2023-01-30-how-to-use-hkdf.html
// info adds entropy to extracted keys, and must be unique:
// see: soatok.blog/2021/11/17/understanding-hkdf
export async function hkdfhmac(skmac, usectx, salt = bin.ZEROBUF) {
  const dk = await hkdf(skmac);
  return crypto.subtle.deriveKey(
    hkdf256(salt, usectx),
    dk,
    hmac256opts(),
    true, // extractable? can be true for sign, verify
    ["sign", "verify"] // usage
  );
}

export async function hmackey(sk) {
  return crypto.subtle.importKey(
    "raw",
    sk,
    hmac256opts(),
    false, // extractable? always false for use as derivedKey
    ["sign", "verify"] // usage
  );
}

export async function hkdf(sk) {
  return crypto.subtle.importKey(
    "raw",
    sk,
    "HKDF",
    false, // extractable? always false for use as derivedKey
    ["deriveKey", "deriveBits"] // usage
  );
}

export function hmac256opts() {
  return { name: "HMAC", hash: "SHA-256" };
}

export function hkdf256(salt, usectx) {
  return { name: "HKDF", hash: "SHA-256", salt: salt, info: usectx };
}

export async function sha256(b) {
  const ab = await crypto.subtle.digest("SHA-256", b);
  return bin.byt(ab);
}

export async function sha512(b) {
  const ab = await crypto.subtle.digest("SHA-512", b);
  return bin.byt(ab);
}
