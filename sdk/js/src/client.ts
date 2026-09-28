// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

import { solve } from "./pow";
import { collectSignals } from "./signals";
import type { Challenge, ClientSignals, Decision, Solution, VerifyResult } from "./types";

export interface XProtectOptions {
  /** XProtect server base URL, e.g. "https://protect.example.com". */
  endpoint: string;
  /** Site key issued for your site (allowlisted server-side). */
  siteKey: string;
  /** AbortSignal forwarded to every fetch and to the PoW grind. */
  signal?: AbortSignal;
}

export class XProtectError extends Error {
  constructor(
    /** Machine-readable error code from the API (e.g. "invalid_solution"). */
    public readonly code: string,
    message: string,
    /** HTTP status, when the error came from a response. */
    public readonly status?: number,
  ) {
    super(message);
    this.name = "XProtectError";
  }
}

interface ChallengeResponse {
  challenge: Challenge;
  decision: Decision;
  risk: number;
}

export class XProtectClient {
  constructor(private readonly opts: XProtectOptions) {}

  private url(path: string): string {
    return `${this.opts.endpoint.replace(/\/+$/, "")}${path}`;
  }

  async requestChallenge(hints?: ClientSignals): Promise<ChallengeResponse> {
    const res = await fetch(this.url("/v1/challenge"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ site_key: this.opts.siteKey, hints: hints ?? collectSignals() }),
      signal: this.opts.signal,
    });
    if (!res.ok) throw await toError(res);
    return (await res.json()) as ChallengeResponse;
  }

  async verify(ch: Challenge, sol: Solution): Promise<VerifyResult> {
    const res = await fetch(this.url("/v1/verify"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ challenge_id: ch.id, nonce: sol.nonce, hints: collectSignals() }),
      signal: this.opts.signal,
    });
    if (!res.ok) throw await toError(res);
    return (await res.json()) as VerifyResult;
  }

  /** Full flow: request challenge → grind PoW → redeem → signed token. */
  async getToken(): Promise<VerifyResult> {
    const { challenge } = await this.requestChallenge();
    const solution = await solve(challenge, { signal: this.opts.signal });
    return this.verify(challenge, solution);
  }
}

async function toError(res: Response): Promise<XProtectError> {
  let code = "http_error";
  let message = `HTTP ${res.status}`;
  try {
    const body = (await res.json()) as { error?: string; message?: string };
    if (body.error) code = body.error;
    if (body.message) message = body.message;
  } catch {
    // non-JSON body — keep defaults
  }
  return new XProtectError(code, message, res.status);
}
