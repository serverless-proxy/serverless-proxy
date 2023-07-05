// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors.
// Copyright (c) 2009-2015, Emily Stark, Mike Hamburg, and Dan Boneh at Stanford University. All rights reserved.

// from: github.com/bitwiseshiftleft/sjcl/blob/85caa53c281e/core/codecBytes.js

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

import * as bitarray from "./bitarray.js";
import * as b64 from "./b64.js";

 export const sjcl = {
  ...b64.sjcl,
  ...bitarray.sjcl,
 };

/**
 * Arrays of bytes
 * @namespace
 */
sjcl.codec.bytes = {
  /** Convert from a bitArray to an array of bytes. */
  fromBits: function (arr) {
    var out = [],
      bl = sjcl.bitArray.bitLength(arr),
      i,
      tmp;
    for (i = 0; i < bl / 8; i++) {
      if ((i & 3) === 0) {
        tmp = arr[i / 4];
      }
      out.push(tmp >>> 24);
      tmp <<= 8;
    }
    return out;
  },
  /** Convert from an array of bytes to a bitArray. */
  toBits: function (bytes) {
    var out = [],
      i,
      tmp = 0;
    for (i = 0; i < bytes.length; i++) {
      tmp = (tmp << 8) | bytes[i];
      if ((i & 3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i & 3) {
      out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
    }
    return out;
  },
};
