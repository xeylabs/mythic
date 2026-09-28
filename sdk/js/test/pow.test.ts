import { describe, expect, test } from "bun:test";
import { leadingZeroBits, solve, sha256 } from "../src/pow";
import type { Challenge } from "../src/types";

const encoder = new TextEncoder();

describe("leadingZeroBits", () => {
  test("SHA-256('hello') starts with 0x2c — two zero bits", async () => {
    // SHA-256("hello") = 2cf24dba… → 0b00101100 → 2 leading zeros
    const sum = await sha256(encoder.encode("hello"));
    expect(leadingZeroBits(sum)).toBe(2);
  });

  test("counts bits within bytes", () => {
    expect(leadingZeroBits(new Uint8Array([0b0010_0000, 0xff]))).toBe(2);
    expect(leadingZeroBits(new Uint8Array([0b0000_0100, 0xff]))).toBe(5);
    expect(leadingZeroBits(new Uint8Array([0x00, 0x01]))).toBe(15);
    expect(leadingZeroBits(new Uint8Array([0x00, 0x00]))).toBe(16);
    expect(leadingZeroBits(new Uint8Array([0xff, 0x00]))).toBe(0);
  });
});

describe("solve", () => {
  test("finds a nonce meeting the difficulty", async () => {
    const ch: Challenge = {
      id: "test-id",
      site_key: "site",
      salt: "deadbeef",
      difficulty: 12,
      algorithm: "sha256",
      expires_at: 0,
    };
    const sol = await solve(ch);
    const sum = await sha256(encoder.encode(`${ch.id}:${ch.salt}:${sol.nonce}`));
    expect(leadingZeroBits(sum)).toBeGreaterThanOrEqual(ch.difficulty);
    expect(sol.challenge_id).toBe(ch.id);
  });

  test("rejects unknown algorithms", async () => {
    const ch = {
      id: "x",
      site_key: "s",
      salt: "s",
      difficulty: 8,
      algorithm: "sha3" as unknown as "sha256",
      expires_at: 0,
    };
    expect(solve(ch)).rejects.toThrow("unsupported algorithm");
  });

  test("rejects implausible difficulties", () => {
    const ch: Challenge = {
      id: "x",
      site_key: "s",
      salt: "s",
      difficulty: 99,
      algorithm: "sha256",
      expires_at: 0,
    };
    expect(solve(ch)).rejects.toThrow("implausible difficulty");
  });

  test("aborts via signal", async () => {
    const ch: Challenge = {
      id: "x",
      site_key: "s",
      salt: "s",
      difficulty: 24, // too hard to finish quickly; abort will fire first
      algorithm: "sha256",
      expires_at: 0,
    };
    const controller = new AbortController();
    controller.abort();
    expect(solve(ch, { signal: controller.signal })).rejects.toThrow();
  });
});
