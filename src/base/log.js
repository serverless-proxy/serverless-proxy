// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "./cfg.js";

let levels = { v: 0, d: 1, log: 2, g: 2, i: 3, w: 4, e: 5 };
let wh = (cfg.debug) ? levels["d"] : levels["i"];

export function key(k = "info") {
  if (cfg.debug) k = "d";
  switch (k) {
    case "v":
    case "verbose":
      k = "v";
      break;
    case "d":
    case "debug":
      k = "d";
      break;
    case "g":
    case "log":
      k = "g";
      break;
    case "i":
    case "info":
      k = "i";
      break;
    case "w":
    case "warn":
      k = "w";
      break;
    case "e":
    case "error":
      k = "e";
      break;
    default:
      k = "i";
  }
  wh = levels[k];
}

export function v(...args) {
  if (wh <= levels["v"]) console.debug(...args);
}

export function d(...args) {
  if (wh <= levels["d"]) console.debug(...args);
}

export function g(...args) {
  if (wh <= levels["g"]) console.log(...args);
}

export function i(...args) {
  if (wh <= levels["i"]) console.info(...args);
}

export function w(...args) {
  if (wh <= levels["w"]) console.warn(...args);
}

export function e(...args) {
  if (wh <= levels["e"]) console.error(...args);
}
