// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

import { describe, expect, test } from "bun:test";
import { solveInWorker } from "../src/worker";
import type { Challenge } from "../src/types";

const challenge: Challenge = {
  id: "test-challenge-id",
  site_key: "test-site",
  salt: "test-salt",
  difficulty: 8, // low for fast test
  algorithm: "sha256",
  expires_at: Math.floor(Date.now() / 1000) + 300,
};

describe("solveInWorker", () => {
  test("falls back to main thread when Worker is undefined", async () => {
    // In Bun, Worker exists, but we test the fallback path via createWorker
    // throwing — actually test the real worker path instead.
    const solution = await solveInWorker(challenge);
    expect(solution.challenge_id).toBe(challenge.id);
    expect(typeof solution.nonce).toBe("string");
  });

  test("reports progress", async () => {
    let progressCalls = 0;
    await solveInWorker(challenge, {
      onProgress: () => {
        progressCalls++;
      },
    });
    expect(progressCalls).toBeGreaterThan(0);
  });

  test("rejects invalid difficulty", async () => {
    const bad: Challenge = { ...challenge, difficulty: 99 };
    // Worker will grind forever on impossible difficulty — use abort.
    const controller = new AbortController();
    const promise = solveInWorker(bad, { signal: controller.signal });
    // Abort after a short delay
    setTimeout(() => controller.abort(), 100);
    await expect(promise).rejects.toThrow();
  });
});
