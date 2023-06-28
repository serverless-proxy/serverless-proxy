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
// dangerous. do not enable. bypass auth?
// not respected when wenv is prod
export const bypassAuth = true;
// immutable info context for keygen
export const authContext = "per-client-pip-key";
// websockets upgrade header
export const upgradeHeader = "Upgrade";
// connection timeout for websockets; unused on workers
export const wsConnTimeoutMs = 10000;
