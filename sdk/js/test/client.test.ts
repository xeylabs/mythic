// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

import { describe, expect, test, mock, afterEach } from "bun:test";
import { MythicClient } from "../src/client";
import type { Challenge, Solution } from "../src/types";

// Minimal window stub so BehavioralCollector activates in Node/Bun.
function stubWindow() {
  (globalThis as any).window = {
    addEventListener: () => {},
    removeEventListener: () => {},
  };
}
function unstubWindow() {
  delete (globalThis as any).window;
}

const challenge: Challenge = {
  id: "test-challenge-id",
  site_key: "test-site",
  salt: "test-salt",
  difficulty: 8,
  algorithm: "sha256",
  expires_at: Math.floor(Date.now() / 1000) + 300,
};
const solution: Solution = { challenge_id: challenge.id, nonce: "abc123" };

describe("MythicClient behavioral hints", () => {
  afterEach(() => {
    unstubWindow();
    (globalThis as any).fetch = undefined;
  });

  test("verify() sends a behavioral snapshot when the collector is active", async () => {
    stubWindow();
    let sentBody: any = null;
    (globalThis as any).fetch = mock(async (_url: string, init: any) => {
      sentBody = JSON.parse(init.body);
      return new Response(JSON.stringify({ token: "tok", decision: "allow", risk: 5 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const client = new MythicClient({ endpoint: "http://127.0.0.1:1", siteKey: "s" });
    await client.verify(challenge, solution);

    expect(sentBody).not.toBeNull();
    expect(sentBody.hints).toBeDefined();
    // Regression: verify() previously sent only collectSignals() with no
    // behavioral data, leaving the server's verify-stage parsing dead.
    expect(sentBody.hints.behavioral).toBeDefined();
    expect(sentBody.hints.behavioral.v).toBe(1);
  });

  test("verify() omits behavioral when collection is disabled", async () => {
    stubWindow();
    let sentBody: any = null;
    (globalThis as any).fetch = mock(async (_url: string, init: any) => {
      sentBody = JSON.parse(init.body);
      return new Response(JSON.stringify({ token: "tok", decision: "allow", risk: 5 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const client = new MythicClient({
      endpoint: "http://127.0.0.1:1",
      siteKey: "s",
      collectBehavior: false,
    });
    await client.verify(challenge, solution);

    expect(sentBody.hints).toBeDefined();
    expect(sentBody.hints.behavioral).toBeUndefined();
  });
});
