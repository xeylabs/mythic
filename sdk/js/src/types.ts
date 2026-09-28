// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

/** Verdict issued by the Mythic risk engine. */
export type Decision = "allow" | "challenge" | "deny";

/** A proof-of-work challenge issued by mythicd. */
export interface Challenge {
  id: string;
  site_key: string;
  salt: string;
  /** Required leading zero bits of SHA-256("id:salt:nonce"). */
  difficulty: number;
  algorithm: "sha256";
  /** Unix seconds — challenge is worthless after this. */
  expires_at: number;
}

/** A solved challenge. */
export interface Solution {
  challenge_id: string;
  nonce: string;
}

/** Result of a successful verification. */
export interface VerifyResult {
  /** Ed25519-signed decision token. Pass it to your origin backend. */
  token: string;
  decision: Decision;
  /** 0-100 risk score at decision time. */
  risk: number;
}

/**
 * Advisory client-reported hints. FORGEABLE BY DESIGN — the server caps their
 * weight and they can never decide alone (ADR-0004). Honest reporting earns a
 * discount; lying only loses it.
 */
export interface ClientSignals {
  /** navigator.webdriver === true — automation by definition. */
  webdriver?: boolean;
  /** Browser identity inconsistencies common in headless defaults. */
  headless?: boolean;
  /** navigator.languages empty — typical of headless default profiles. */
  no_languages?: boolean;
  [key: string]: unknown;
}
