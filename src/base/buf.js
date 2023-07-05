// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

export const ZEROBUF = new Uint8Array(0);

const tencoder = new TextEncoder();
const tdecoder = new TextDecoder();

export function str2byte(s) {
  return tencoder.encode(s);
}

export function byte2str(b) {
  return tdecoder.decode(b);
}

// given a buffer b, returns the underlying array buffer
function raw(b) {
  if (emptyBuf(b)) return ZEROBUF.buffer;
  if (b instanceof ArrayBuffer) return b;
  return b.buffer;
}

// given a buffer b, returns its uint8array view
export function byt(b) {
  if (emptyBuf(b)) return ZEROBUF;
  const ab = raw(b);
  return new Uint8Array(ab);
}

export function buf2hex(b) {
  const u8 = byt(b);
  return Array.from(u8)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function hex2buf(h) {
  if (emptyString(h)) return ZEROBUF;
  return new Uint8Array(h.match(/.{1,2}/g).map((w) => parseInt(w, 16)));
}

export function num2hex(n) {
  if (typeof n !== "number") return "";
  return n.toString(16).padStart(2, "0");
}

export function hex2num(h) {
  if (typeof h !== "string") return 0;
  return parseInt(h, 16);
}

// check if Buffer is empty
export function emptyBuf(b) {
  return !b || b.byteLength === 0;
}

export function emptyString(s) {
  if (typeof s === "string") {
    // todo: trim
    return !s || s.length === 0;
  } else {
    return false;
  }
}
