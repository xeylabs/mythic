// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

import { describe, expect, test } from "bun:test";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { parsePublicKey, verifyToken, TokenError } from "../src/verify";

function makeToken(priv: KeyObject, claims: Record<string, unknown>): string {
  const payload = Buffer.from(JSON.stringify(claims), "utf8");
  const sig = sign(null, payload, priv);
  return `${payload.toString("base64url")}.${sig.toString("base64url")}`;
}

function keypair(): { x: string; priv: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const x = spki.subarray(12).toString("base64url"); // strip DER prefix
  return { x, priv: privateKey };
}

const claims = () => ({
  v: 1,
  sid: "test-site",
  dec: "allow",
  risk: 15,
  kid: "k1",
  jti: "j1",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
});

describe("verify", () => {
  test("accepts a valid token", () => {
    const { x, priv } = keypair();
    const pub = parsePublicKey(x);
    const got = verifyToken(pub, makeToken(priv, claims()));
    expect(got.sid).toBe("test-site");
    expect(got.dec).toBe("allow");
    expect(got.risk).toBe(15);
  });

  test("rejects wrong key", () => {
    const { priv } = keypair();
    const { x: x2 } = keypair();
    const pub2 = parsePublicKey(x2);
    expect(() => verifyToken(pub2, makeToken(priv, claims()))).toThrow(TokenError);
  });

  test("rejects expired token", () => {
    const { x, priv } = keypair();
    const pub = parsePublicKey(x);
    const c = claims();
    c.exp = Math.floor(Date.now() / 1000) - 10;
    expect(() => verifyToken(pub, makeToken(priv, c))).toThrow(/expired/);
  });

  test("rejects malformed token", () => {
    const { x } = keypair();
    const pub = parsePublicKey(x);
    expect(() => verifyToken(pub, "not-a-token")).toThrow(/malformed/);
  });

  test("rejects bad public key", () => {
    expect(() => parsePublicKey("!!!")).toThrow(TokenError);
    expect(() => parsePublicKey("aGk=")).toThrow(/32 bytes/);
  });

  test("rejects tampered payload", () => {
    const { x, priv } = keypair();
    const pub = parsePublicKey(x);
    const token = makeToken(priv, claims());
    const [p, s] = token.split(".");
    const tampered = Buffer.from(
      JSON.stringify({ ...claims(), risk: 0 }),
      "utf8",
    ).toString("base64url");
    expect(() => verifyToken(pub, `${tampered}.${s}`)).toThrow(/signature/);
    void p;
  });
});

void createPrivateKey;
void createPublicKey;
