// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

/**
 * Mythic origin verification helper for Node.js.
 *
 * Verifies Mythic decision tokens on your origin backend, locally —
 * no dependency on the mythicd runtime.
 *
 * ```ts
 * import { parsePublicKey, verifyToken } from "./verify";
 *
 * const pub = parsePublicKey(jwkX); // from mythicd JWKS endpoint
 * const claims = verifyToken(pub, token);
 * if (claims.dec !== "allow") {
 *   // handle challenge/deny per your policy
 * }
 * ```
 *
 * Token format: `base64url(payload).base64url(signature)` where payload
 * is JSON: {v, sid, dec, risk, kid, jti, iat, exp} and signature is
 * Ed25519 over the raw payload bytes.
 */

import { createPublicKey, verify, type KeyObject } from "node:crypto";
import type { Decision } from "./types";

export type { Decision };
export interface TokenClaims {
  v: number; // token format version
  sid: string; // site key the challenge was issued for
  dec: Decision; // allow | challenge | deny
  risk: number; // 0-100 risk score at decision time
  kid: string; // signing key id
  jti: string; // unique token id (revocation-ready)
  iat: number; // unix seconds
  exp: number; // unix seconds
}

export class TokenError extends Error {
  constructor(message: string) {
    super(`mythic: ${message}`);
    this.name = "TokenError";
  }
}

/**
 * Decode a JWKS "x" value (base64url raw Ed25519 public key) into
 * a Node.js KeyObject usable with verifyToken.
 */
export function parsePublicKey(x: string): KeyObject {
  let raw: Buffer;
  try {
    raw = Buffer.from(x, "base64url");
  } catch {
    throw new TokenError("bad public key encoding");
  }
  if (raw.length !== 32) {
    throw new TokenError(`public key must be 32 bytes, got ${raw.length}`);
  }
  // Wrap raw Ed25519 public key in DER SubjectPublicKeyInfo.
  // DER prefix for Ed25519: 302a300506032b6570032100 + 32-byte key.
  const derPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([derPrefix, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/**
 * Verify a decision token's signature and expiry, returning its claims.
 *
 * Callers must still enforce site key and decision per their own policy —
 * verification only proves mythicd signed these claims.
 */
export function verifyToken(pub: KeyObject, token: string): TokenClaims {
  const dot = token.indexOf(".");
  if (dot === -1) throw new TokenError("malformed token");

  const payloadPart = token.slice(0, dot);
  const sigPart = token.slice(dot + 1);

  let payload: Buffer;
  let sig: Buffer;
  try {
    payload = Buffer.from(payloadPart, "base64url");
    sig = Buffer.from(sigPart, "base64url");
  } catch {
    throw new TokenError("bad token encoding");
  }

  // Canonical encodings only: re-encoding must reproduce the input exactly.
  if (
    payload.toString("base64url") !== payloadPart ||
    sig.toString("base64url") !== sigPart
  ) {
    throw new TokenError("non-canonical encoding");
  }

  // Ed25519 signs the raw payload (no pre-hash); algorithm is null.
  if (!verify(null, payload, pub, sig)) {
    throw new TokenError("signature mismatch");
  }

  let claims: TokenClaims;
  try {
    claims = JSON.parse(payload.toString("utf8"));
  } catch {
    throw new TokenError("bad claims JSON");
  }

  if (claims.v !== 1) throw new TokenError(`unsupported version ${claims.v}`);
  if (Math.floor(Date.now() / 1000) > claims.exp) {
    throw new TokenError("token expired");
  }

  return claims;
}
