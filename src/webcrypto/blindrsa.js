// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors.

export async function genkey() {
  // generate the private key for rsa-pss
  const ck = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048, //can be 1024, 2048, or 4096
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-384" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    },
    true, //whether the key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"] //can be any combination of "sign" and "verify"
  );
  const privjwk = await crypto.subtle.exportKey("jwk", ck.privateKey);
  const pubjwk = await crypto.subtle.exportKey("jwk", ck.publicKey);
  const privstr = JSON.stringify(privjwk);
  const pubstr = JSON.stringify(pubjwk);
    return [privstr, pubstr];
}

export async function importkey(privjwkstr, pubjwkstr) {
    const privjwk = JSON.parse(privjwkstr);
    const pubjwk = JSON.parse(pubjwkstr);
    const privkey = await crypto.subtle.importKey(
        "jwk",
        privjwk,
        {
        name: "RSA-PSS",
        hash: { name: "SHA-384" },
        },
        true,
        ["sign"]
    );
    const pubkey = await crypto.subtle.importKey(
        "jwk",
        pubjwk,
        {
        name: "RSA-PSS",
        hash: { name: "SHA-384" },
        },
        true,
        ["verify"]
    );
    return [privkey, pubkey];
}
