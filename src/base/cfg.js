// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

export const debug = false;
// echo udp/tcp server
// echo "hello" | nc midway.fly.dev 5001
export const echoServerAddr = { hostname: "midway.fly.dev", port: 5001 };
export const g204Url = "https://static.googleusercontent.com/generate_204";
// socket options on workers
export const tcpOpts = { secureTransport: "off", allowHalfOpen: true };
export const h2header = {
  "Content-Type": "application/octet-stream",
  "Cache-Control": "no-cache",
};
// auth token
export const headerClaim = "x-nile-pip-claim";
// msg is a nonce for the claim
export const headerMsg = "x-nile-pip-msg";
// mac is a hmac of the headerMsg
export const headerMac = "x-nile-pip-mac";
// svc token authenticates our internal services
export const headerSvcPsk = "x-nile-svc-psk";
// dangerous. do not enable. bypass auth?
// not respected when wenv is prod
export const bypassAuth = true;
// websockets upgrade header
export const upgradeHeader = "Upgrade";
// connection timeout for websockets; unused on workers
export const wsConnTimeoutMs = 10000;
// use ctx.waitUntil() to wait for websockets rw streams to close
export const useWaiter = false;
// immutable info context for keygen
export const authContext = "per-client-pip-key";

export const wenvBlindRsaPrivateKeyPrefix = "PRIVATE_KEY_BLINDRSA_";
export const wenvBlindRsaPublicKeyPrefix = "PUBLIC_KEY_BLINDRSA_";
export const wenvPskSvc = "PRE_SHARED_KEY_SVC";
