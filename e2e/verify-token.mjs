// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Verify a Mythic decision token with the JS SDK against a live mythicd JWKS.
// Usage: node verify-token.mjs <base-url> <token>
// Prints {"dec","risk","sid"} as JSON.
import { parsePublicKey, verifyToken } from "../sdk/js/dist/index.js";

const [base, token] = process.argv.slice(2);
if (!base || !token) {
  console.error("usage: node verify-token.mjs <base-url> <token>");
  process.exit(1);
}

const jwks = await (await fetch(`${base}/v1/.well-known/jwks.json`)).json();

let claims;
for (const k of jwks.keys) {
  try {
    claims = verifyToken(parsePublicKey(k.x), token);
    break;
  } catch {
    // try next key (multi-key rotation: kid selects, we brute-force)
  }
}
if (!claims) {
  console.error("no JWKS key verified the token");
  process.exit(1);
}
console.log(JSON.stringify({ dec: claims.dec, risk: claims.risk, sid: claims.sid }));
