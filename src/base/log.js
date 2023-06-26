// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "./cfg.js";

export function d(...args) {
  if (cfg.debug) console.debug(...args);
}

export function g(...args) {
  console.log(...args);
}

export function i(...args) {
  console.info(...args);
}

export function w(...args) {
  console.warn(...args);
}

export function e(...args) {
  console.error(...args);
}
