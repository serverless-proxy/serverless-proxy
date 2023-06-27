// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

export const debug = true;
// echo udp/tcp server
// echo "hello" | nc midway.fly.dev 5001
export const echoServerAddr = { hostname: "midway.fly.dev", port: 5001 };
export const g204Url = "https://static.googleusercontent.com/generate_204";
export const tcpOpts = { secureTransport: "off", allowHalfOpen: true };
export const h2header = {
  "Content-Type": "application/octet-stream",
  "Cache-Control": "no-cache",
};
export const headerClaim = "x-nile-pip-claim";
export const headerMsg = "x-nile-pip-msg";
export const bypassAuth = true;
export const authContext = "per-client-pip-key";
export const upgradeHeader = "Upgrade";
export const wsConnTimeoutMs = 10000;
