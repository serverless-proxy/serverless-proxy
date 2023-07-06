// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors.

import * as cfg from "../base/cfg.js";
import * as log from "../base/log.js";
import * as auth from "../core/auth.js";
import * as modres from "../base/res.js";
import * as brsa from "../sjcl/brsa.js";
import * as krsa from "../webcrypto/blindrsa.js";
import * as bin from "../base/buf.js";
import { sha256 } from "../webcrypto/hmac.js";

const KEYS = {
  // todo: use lfu cache
  /** @type {Map<string, CryptoKey>} */
  ckmacs: new Map(),
  /** @type {CryptoKey} */
  ckpriv0: null,
  /** @type {CryptoKey} */
  ckpub0: null,
  /** @type {CryptoKey} */
  ckpriv1: null,
  /** @type {CryptoKey} */
  ckpub1: null,
};

// todo: use lfu cache
/** @type {Set<string>} */
const TOKAUTH = new Set();

const enc = new TextEncoder();

/**
 * Given a blind message, return a blind signature.
 * @param {Request} r
 * @param {any} env
 * @param {any} ctx
 * @return {Promise<string>}
 * @throws
 */
export async function sign(r, env, ctx) {
  if (r.method !== "POST" || r.method !== "PUT") return modres.r405;

  if (!superuser(r, env)) return modres.r401;

  const blindMsgHex = await r.text();
  if (!blindMsgHex) return modres.r400;

  const blindMsg = bin.hex2buf(blindMsgHex);
  const ck = await currentrsasecrets(env);
  const blindSig = await brsa.blindSign(ck[0], blindMsg);
  const blindSigHex = bin.buf2hex(blindSig);
  return new Response(blindSigHex, { ...modres.txthdr });
}

/**
 * If unblinded msg and signature are verified, issue a data token
 * against a hashed client-id token.
 * @param {Request} r
 * @param {any} env
 * @param {any} ctx
 */
export async function issue(r, env, ctx) {
  if (r.method !== "POST" || r.method !== "PUT") return modres.r405;

  if (!superuser(r, env)) return modres.r401;

  const txt = await r.text();
  if (!txt) return modres.r400;

  // unblindedMsgHex, unblindedSigHex, hashedthex
  const msgsig = txt.split(auth.claimDelim);
  if (msgsig.length < 3) return modres.r401;

  const rsamsghex = msgsig[0];
  const rsasighex = msgsig[1];
  const hashedthex = msgsig[2];
  if (!rsamsghex || !rsasighex || !hashedthex) return modres.r401;

  const msg = bin.hex2buf(rsamsghex);
  const sig = bin.hex2buf(rsasighex);
  const ck0 = await currentrsasecrets(env);

  const ok0 = await brsa.verify(ck0[1], msg, sig);
  if (!ok0) {
    const ck1 = await previousrsasecrets(env);
    const ok1 = await brsa.verify(ck1[1], msg, sig);
    if (!ok1) return modres.r401;
  }

  const sk = await macsecret(env);
  if (!seed || !sk) return modres.r500;

  const expsig = await auth.issue(sk, hashedthex);
  if (!expsig || expsig.length <= 0) return modres.r500;
  // todo: no-cache headers
  return new Response(expsig.join(auth.claimDelim), { ...modres.txthdr });
}

/**
 * @param {Request} r
 * @param {any} env
 * @param {any} ctx
 */
export async function allow(r, env, ctx) {
  const url = new URL(r.url);
  const tok = r.headers.get(cfg.headerClaim);
  const mac = r.headers.get(cfg.headerMac);
  // msg is hex(sha256(url.pathname))
  // const msg = r.headers.get(cfg.headerMsg);
  const msg = await grabMsg(url);
  const info = grabRsaSig(url);

  if (cfg.bypassAuth && notprod(env)) {
    log.w("auth: bypass", "claim?", mac, "msg?", msg);
    return auth.ok;
  }

  if (!tok || !mac || !msg || !info) {
    log.d("auth: no claim or msg");
    return auth.notok;
  }

  if (auth.verifyExpiry(tok)) {
    log.d("auth: expired claim");
    return auth.notok;
  }

  const tokcachekey = tok + msg + mac + info;
  if (TOKAUTH.has(tokcachekey)) {
    log.d("auth: cached claim: ok");
    return auth.ok;
  }

  // todo: cache auth result
  const sk = await macsecret(env, info);
  if (!sk) {
    log.e("auth: no sk");
    return auth.notok;
  }

  const authres = await auth.verifyClaim(sk, tok, msg, mac);
  if (authres == auth.ok) {
    TOKAUTH.add(tokcachekey);
  }
  return authres;
}

/**
 * @param {any} env
 * @param {string} ctx
 * @returns {Promise<CryptoKey?>}
 */
async function macsecret(env, ctx) {
  let sk = KEYS.ckmacs.get(ctx);
  if (sk == null) {
    const seed = env.SECRET_KEY_MAC_A;
    sk = await auth.keygen(seed, ctx);
    KEYS.ckmacs.set(ctx, sk);
  }
  return sk;
}

/**
 * @param {any} env
 * @returns {Promise<CryptoKey[]>}
 * @throws when rsa-pss pub/priv keys are missing
 */
async function previousrsasecrets(env) {
  const curprev = await rsasecrets(env);
  return curprev[1];
}

/**
 * @param {any} env
 * @returns {Promise<CryptoKey[]>}
 * @throws when rsa-pss pub/priv keys are missing
 */
async function currentrsasecrets(env) {
  const curprev = await rsasecrets(env);
  return curprev[0];
}

/**
 * @param {any} env
 * @returns {Promise<Array<CryptoKey[]>>}
 * @throws when rsa-pss pub/priv keys are missing
 */
async function rsasecrets(env) {
  // todo: should not be cached for more than 3 days
  if (
    KEYS.ckpriv0 != null &&
    KEYS.ckpub0 != null &&
    KEYS.ckpriv1 != null &&
    KEYS.ckpub1 != null
  ) {
    const latest = [KEYS.ckpriv0, KEYS.ckpub0];
    const previous = [KEYS.ckpriv1, KEYS.ckpub1];
    return [latest, previous];
  }
  // see: redir's rsapubkey fn
  const privprefix = cfg.wenvBlindRsaPrivateKeyPrefix;
  const pubprefix = cfg.wenvBlindRsaPublicKeyPrefix;
  // default key name
  let kpriv0 = privprefix + "A";
  let kpub0 = pubprefix + "A";
  let kpriv1 = privprefix + "B";
  let kpub1 = pubprefix + "B";
  const descend = Object.keys(env)
    .filter((k) => k.startsWith(privprefix))
    .sort((a, b) => {
      const l = parseInt(a.slice(privprefix.length));
      const r = parseInt(b.slice(privprefix.length));
      return r - l;
    });
  if (descend.length > 0) {
    kpriv0 = privprefix + descend[0];
    kpub0 = pubprefix + descend[0];
  }
  if (descend.length > 1) {
    kpriv1 = privprefix + descend[1];
    kpub1 = pubprefix + descend[1];
  }
  const privjwkstr0 = env[kpriv0];
  const pubjwkstr0 = env[kpub0];
  const privjwkstr1 = env[kpriv1];
  const pubjwkstr1 = env[kpub1];
  const cks0 = await krsa.importkey(privjwkstr0, pubjwkstr0);
  const cks1 = await krsa.importkey(privjwkstr1, pubjwkstr1);

  KEYS.ckpriv0 = cks0[0];
  KEYS.ckpub0 = cks0[1];
  KEYS.ckpriv1 = cks1[0];
  KEYS.ckpub1 = cks1[1];
  return [cks0, cks1];
}

/**
 * @param {URL} u
 * @returns {string}
 */
function grabRsaSig(u) {
  try {
    const p = u.pathname.split("/");
    return p[2];
  } catch (ex) {
    log.w("wsvc: grabRsaSig", ex);
  }
  return null;
}

/**
 * @param {URL} u
 * @returns {Promise<string>}
 */
async function grabMsg(u) {
  try {
    const p = enc.encode(u.pathname);
    const d = await sha256(p);
    return bin.buf2hex(d);
  } catch (ex) {
    log.w("wsvc: grabMsg", ex);
  }
  return null;
}

/**
 * @param {Request} r
 * @param {any} env
 * @returns {boolean}
 */
function superuser(r, env) {
  const svcpskhex = r.headers.get(cfg.headerSvcPsk);
  if (!svcpskhex) return false;

  const svcauthres = auth.verifySvcPsk(env, svcpskhex);
  return svcauthres === auth.ok;
}

/**
 * @param {any} env
 * @returns {boolean}
 */
function notprod(env) {
  return env["WENV"] !== "prod";
}
