// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

export const txthdr = { headers: { "Content-Type": "application/text" } };

export const r400 = new Response(null, { status: 400 }); // Bad Request
export const r401 = new Response(null, { status: 401 }); // Authorization Required
export const r405 = new Response(null, { status: 405 }); // Method Not Allowed
export const r426 = new Response(null, { status: 426 }); // Upgrade Required
export const r500 = new Response(null, { status: 500 }); // Internal Server Error
export const r503 = new Response(null, { status: 503 }); // Service Unavailable
export const r504 = new Response(null, { status: 504 }); // Gateway Timeout
