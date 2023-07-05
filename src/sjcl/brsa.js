// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors.
// Copyright (c) 2017-2022, Privacy Pass Team, Cloudflare, Inc., and other contributors. All rights reserved.

import * as b64 from "./b64.js";
import * as bignum from "./bignum.js";
import * as bitarray from "./bitarray.js";
import * as bytes from "./bytes.js";

const sjcl = {
  ...b64.sjcl,
  ...bignum.sjcl,
  ...bitarray.sjcl,
  ...bytes.sjcl,
};

// rfc: datatracker.ietf.org/doc/html/draft-irtf-cfrg-rsa-blind-signatures-13
// ref: cathieyun.medium.com/adventures-with-rsa-blind-signing-397035585121
// from: github.com/privacypass/challenge-bypass-extension/blob/732205c052/src/blindrsa/blindrsa.ts
/**
 * Blind a message using RSA-PSS.
 * @param {CryptoKey} publicKey RSA public key.
 * @param {Uint8Array} msg Message to be blinded.
 * @param {number} saltLength Length of the salt to be used in the PSS encoding.
 * @returns {Promise<{blindedMsg: Uint8Array, blindInv: Uint8Array}>} Blinded message and blinding inverse.
 * @throws {Error} If the key is not RSA-PSS or is not extractable.
 */
export async function blind(publicKey, msg, saltLength = 16) {
  if (publicKey.type !== "public" || publicKey.algorithm.name !== "RSA-PSS") {
    throw new Error("key is not RSA-PSS");
  }
  if (!publicKey.extractable) {
    throw new Error("key is not extractable");
  }
  /** @type {{modulusLength: number, hash: Algorithm}} */
  const { modulusLength, hash: hashFn } = publicKey.algorithm;
  const kBits = modulusLength;
  const kLen = Math.ceil(kBits / 8);
  const hash = hashFn.name;

  // 1. encoded_msg = EMSA-PSS-ENCODE(msg, kBits - 1)
  //    with MGF and HF as defined in the parameters
  // 2. If EMSA-PSS-ENCODE raises an error, raise the error and stop
  const encoded_msg = await emsa_pss_encode(msg, kBits - 1, {
    sLen: saltLength,
    hash,
  });

  // 3. m = bytes_to_int(encoded_msg)
  const m = os2ip(encoded_msg);
  const jwkKey = await crypto.subtle.exportKey("jwk", publicKey);
  if (!jwkKey.n || !jwkKey.e) {
    throw new Error("key has invalid parameters");
  }
  const n = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.n));
  const e = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.e));

  // 4. r = random_integer_uniform(1, n)
  /** @type {sjcl.bn} */
  let r;
  do {
    r = os2ip(crypto.getRandomValues(new Uint8Array(kLen)));
  } while (r.greaterEquals(n));

  // 5. r_inv = inverse_mod(r, n)
  // 6. If inverse_mod fails, raise an "invalid blind" error
  //    and stop
  /** @type {sjcl.bn} */
  let r_inv;
  try {
    r_inv = r.inverseMod(n);
  } catch (e) {
    throw new Error("invalid blind");
  }
  // 7. x = RSAVP1(pkS, r)
  const x = rsavp1({ n, e }, r);

  // 8. z = m * x mod n
  const z = m.mulmod(x, n);

  // 9. blinded_msg = int_to_bytes(z, kLen)
  const blindedMsg = i2osp(z, kLen);

  // 10. inv = int_to_bytes(r_inv, kLen)
  const blindInv = i2osp(r_inv, kLen);

  // 11. output blinded_msg, inv
  return { blindedMsg, blindInv };
}

/**
 * @param {CryptoKey} publicKey
 * @param {Uint8Array} msg
 * @param {Uint8Array} blindInv
 * @param {Uint8Array} blindSig
 * @param {number} saltLength
 * @returns {Promise<Uint8Array>}
 */
export async function finalize(
  publicKey,
  msg,
  blindInv,
  blindSig,
  saltLength = 16
) {
  if (publicKey.type !== "public" || publicKey.algorithm.name !== "RSA-PSS") {
    throw new Error("key is not RSA-PSS");
  }
  if (!publicKey.extractable) {
    throw new Error("key is not extractable");
  }
  // RsaHashedKeyGenParams
  const { modulusLength } = publicKey.algorithm;
  const kLen = Math.ceil(modulusLength / 8);

  // 1. If len(blind_sig) != kLen, raise "unexpected input size" and stop
  // 2. If len(inv) != kLen, raise "unexpected input size" and stop
  if (blindSig.length != kLen || blindInv.length != kLen) {
    throw new Error("unexpected input size");
  }

  // 3. z = bytes_to_int(blind_sig)
  const z = os2ip(blindSig);

  // 4. r_inv = bytes_to_int(inv)
  const r_inv = os2ip(blindInv);

  // 5. s = z * r_inv mod n
  const jwkKey = await crypto.subtle.exportKey("jwk", publicKey);
  if (!jwkKey.n) {
    throw new Error("key has invalid parameters");
  }
  const n = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.n));
  const s = z.mulmod(r_inv, n);

  // 6. sig = int_to_bytes(s, kLen)
  const sig = i2osp(s, kLen);

  // 7. result = RSASSA-PSS-VERIFY(pkS, msg, sig)
  // 8. If result = "valid signature", output sig, else
  //    raise "invalid signature" and stop
  const ok = await verify(publicKey, msg, sig, saltLength);
  if (!ok) {
    throw new Error("invalid signature");
  }
  return sig;
}

/**
 * @param {CryptoKey} publicKey
 * @param {AlgorithmIdentifier} algorithm
 * @param {Uint8Array} msg
 * @param {Uint8Array} sig
 * @param {number} saltLength
 * @returns {Promise<boolean>}
 */
export async function verify(publicKey, msg, sig, saltLength = 16) {
  const alg = { name: "RSA-PSS", saltLength };
  return crypto.subtle.verify(alg, publicKey, sig, msg);
}

/**
 * @param {CryptoKey} privateKey
 * @param {Uint8Array} blindMsg
 * @returns {Promise<Uint8Array>}
 */
export async function blindSign(privateKey, blindMsg) {
  if (
    privateKey.type !== "private" ||
    privateKey.algorithm.name !== "RSA-PSS"
  ) {
    throw new Error("key is not RSA-PSS");
  }
  if (!privateKey.extractable) {
    throw new Error("key is not extractable");
  }
  const { modulusLength } = privateKey.algorithm;
  const kLen = Math.ceil(modulusLength / 8);

  // 1. If len(blinded_msg) != kLen, raise "unexpected input size"
  //    and stop
  if (blindMsg.length != kLen) {
    throw new Error("unexpected input size");
  }

  // 2. m = bytes_to_int(blinded_msg)
  const m = os2ip(blindMsg);

  // 3. If m >= n, raise "invalid message length" and stop
  const jwkKey = await crypto.subtle.exportKey("jwk", privateKey);
  if (!jwkKey.n || !jwkKey.d) {
    throw new Error("key is not a private key");
  }
  const n = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.n));
  const d = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwkKey.d));
  if (m.greaterEquals(n)) {
    throw new Error("invalid message length");
  }

  // 4. s = RSASP1(skS, m)
  const s = rsasp1({ n, d }, m);

  // 5. blind_sig = int_to_bytes(s, kLen)
  // 6. output blind_sig
  return i2osp(s, kLen);
}

// from: github.com/privacypass/challenge-bypass-extension/blob/732205c052/src/blindrsa/util.ts

// RSAVP1
// https://www.rfc-editor.org/rfc/rfc3447.html#section-5.2.2
/**
 * @param {{ n: sjcl.bn; e: sjcl.bn }} pkS
 * @param {sjcl.bn} s
 * @returns {sjcl.bn}
 */
export function rsavp1(pkS, s) {
  //  1. If the signature representative s is not between 0 and n - 1,
  //    output "signature representative out of range" and stop.
  if (!s.greaterEquals(new sjcl.bn(0)) || s.greaterEquals(pkS.n) == 1) {
    throw new Error("sig out of range");
  }
  // 2. Let m = s^e mod n.
  const m = s.powermod(pkS.e, pkS.n);
  // 3. Output m.
  return m;
}

// RSASP1
// https://www.rfc-editor.org/rfc/rfc3447.html#section-5.2.1
/**
 *
 * @param {{ n: sjcl.bn; d: sjcl.bn }} skS
 * @param {sjcl.bn} m
 * @returns {sjcl.bn}
 */
export function rsasp1(skS, m) {
  // 1. If the message representative m is not between 0 and n - 1,
  //    output "message representative out of range" and stop.
  if (!m.greaterEquals(new sjcl.bn(0)) || m.greaterEquals(skS.n) == 1) {
    throw new Error("signature representative out of range");
  }
  // 2. The signature representative s is computed as follows.
  //    If the first form (n, d) of K is used, let s = m^d mod n.
  const s = m.powermod(skS.d, skS.n);
  //   3. Output s.
  return s;
}

/**
 * @param {Uint8Array} bytes
 * @returns {sjcl.bn}
 */
export function os2ip(bytes) {
  return sjcl.bn.fromBits(sjcl.codec.bytes.toBits(bytes));
}

/**
 * @param {sjcl.bn} num
 * @param {number} byteLength
 * @returns {Uint8Array}
 */
export function i2osp(num, byteLength) {
  if (Math.ceil(num.bitLength() / 8) > byteLength) {
    throw new Error(`number does not fit in ${byteLength} bytes`);
  }
  const bytes = new Uint8Array(byteLength);
  const unpadded = new Uint8Array(
    sjcl.codec.bytes.fromBits(num.toBits(undefined), false)
  );
  bytes.set(unpadded, byteLength - unpadded.length);
  return bytes;
}

// EMSA-PSS-ENCODE (M, emBits)
//
// https://www.rfc-editor.org/rfc/rfc3447.html#section-9.1.1
//
// Input:
// M        message to be encoded, an octet string
// emBits   maximal bit length of the integer OS2IP (EM) (see Section
//          4.2), at least 8hLen + 8sLen + 9
// MGF      mask generation function
//
// Output:
// EM       encoded message, an octet string of length emLen = \ceil
//          (emBits/8)
//
// Errors:  "encoding error"; "message too long"
/**
 * @param {Uint8Array} msg
 * @param {number} emBits
 * @param {{ hash: string; sLen: number }} opts
 * @param {MGFFn} mgf
 * @returns {Promise<Uint8Array>}
 */
export async function emsa_pss_encode(msg, emBits, opts, mgf = mgf1) {
  const { hash, sLen } = opts;
  const hashParams = getHashParams(hash);
  const { hLen } = hashParams;
  const emLen = Math.ceil(emBits / 8);

  // 1.  If the length of M is greater than the input limitation for the
  //     hash function (2^61 - 1 octets for SHA-1), output "message too
  //     long" and stop.
  //
  // 2.  Let mHash = Hash(M), an octet string of length hLen.
  const mHash = new Uint8Array(await crypto.subtle.digest(hash, msg));
  // 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
  if (emLen < hLen + sLen + 2) {
    throw new Error("encoding error");
  }
  // 4.  Generate a random octet string salt of length sLen; if sLen = 0,
  //     then salt is the empty string.
  const salt = crypto.getRandomValues(new Uint8Array(sLen));
  // 5.  Let
  //       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
  //
  //     M' is an octet string of length 8 + hLen + sLen with eight
  //     initial zero octets.
  //
  const mPrime = concat([new Uint8Array(8), mHash, salt]);
  // 6.  Let H = Hash(M'), an octet string of length hLen.
  const h = new Uint8Array(await crypto.subtle.digest(hash, mPrime));
  // 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
  //     zero octets. The length of PS may be 0.
  const ps = new Uint8Array(emLen - sLen - hLen - 2);
  // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
  //     emLen - hLen - 1.
  const db = concat([ps, Uint8Array.of(0x01), salt]);
  // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
  const dbMask = await mgf(hashParams, h, emLen - hLen - 1);
  // 10. Let maskedDB = DB \xor dbMask.
  const maskedDB = xor(db, dbMask);
  // 11.  Set the leftmost 8emLen - emBits bits of the leftmost octet
  //      in maskedDB to zero.
  maskedDB[0] &= 0xff >> (8 * emLen - emBits);
  // 12.  Let EM = maskedDB || H || 0xbc.
  const em = concat([maskedDB, h, Uint8Array.of(0xbc)]);

  // 13. Output EM.
  return em;
}

/**
 *
 * @param {string} hash
 * @returns {HashParams}
 */
function getHashParams(hash) {
  switch (hash) {
    case "SHA-1":
      return { name: hash, hLen: 20 };
    case "SHA-256":
      return { name: hash, hLen: 32 };
    case "SHA-384":
      return { name: hash, hLen: 48 };
    case "SHA-512":
      return { name: hash, hLen: 64 };
    default:
      throw new Error(`unexpected hash id: ${hash}`);
  }
}

/**
 * @param {Uint8Array[]} a
 * @returns {Uint8Array}
 */
export function concat(a) {
  let size = 0;
  for (let i = 0; i < a.length; i++) {
    size += a[i].length;
  }
  const ret = new Uint8Array(new ArrayBuffer(size));
  for (let i = 0, offset = 0; i < a.length; i++) {
    ret.set(a[i], offset);
    offset += a[i].length;
  }
  return ret;
}

/**
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array}
 */
export function xor(a, b) {
  if (a.length !== b.length || a.length === 0) {
    throw new Error("arrays of different length");
  }
  const n = a.length;
  const c = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    c[i] = a[i] ^ b[i];
  }
  return c;
}

/**
 * @param {Uint8Array} c
 */
function incCounter(c) {
  c[3]++;
  if (c[3] != 0) {
    return;
  }
  c[2]++;
  if (c[2] != 0) {
    return;
  }
  c[1]++;
  if (c[1] != 0) {
    return;
  }
  c[0]++;
}

/**
 * @typedef {(h: HashParams, seed: Uint8Array, mLen: number) => Promise<Uint8Array>} MGFFn
 * @typedef { name: string; hLen: number } HashParams
 */

// MGF1 (mgfSeed, maskLen)
//
// https://www.rfc-editor.org/rfc/rfc8017#appendix-B.2.1
//
// Options:
// Hash     hash function (hLen denotes the length in octets of
//          the hash function output)
//
// Input:
// mgfSeed  seed from which mask is generated, an octet string
// maskLen  intended length in octets of the mask, at most 2^32 hLen
//
// Output:
// mask     mask, an octet string of length maskLen
//
// Error: "mask too long"
/**
 *
 * @param {HashParams} h
 * @param {Uint8Array} seed
 * @param {number} mLen
 * @returns {Promise<Uint8Array>}
 */
async function mgf1(h, seed, mLen) {
  // 1.  If maskLen > 2^32 hLen, output "mask too long" and stop.
  const n = Math.ceil(mLen / h.hLen);
  if (n > Math.pow(2, 32)) {
    throw new Error("mask too long");
  }

  // 2.  Let T be the empty octet string.
  let T = new Uint8Array();

  // 3.  For counter from 0 to \ceil (maskLen / hLen) - 1, do the
  //     following:
  const counter = new Uint8Array(4);
  for (let i = 0; i < n; i++) {
    //     A.  Convert counter to an octet string C of length 4 octets (see
    //         Section 4.1):
    //
    //            C = I2OSP (counter, 4) .
    //     B.  Concatenate the hash of the seed mgfSeed and C to the octet
    //         string T:
    //
    //            T = T || Hash(mgfSeed || C) .
    const hash = new Uint8Array(
      await crypto.subtle.digest(h.name, concat([seed, counter]))
    );
    T = concat([T, hash]);
    incCounter(counter);
  }

  // 4.  Output the leading maskLen octets of T as the octet string mask.
  return T.subarray(0, mLen);
}
