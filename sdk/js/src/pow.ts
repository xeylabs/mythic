// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

import type { Challenge, Solution } from "./types";

/** SHA-256 over bytes, using the platform Web Crypto (browser and Node ≥18). */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(digest);
}

/** Counts leading zero bits of a digest. */
export function leadingZeroBits(sum: Uint8Array): number {
  let bits = 0;
  for (const byte of sum) {
    for (let i = 7; i >= 0; i--) {
      if ((byte >> i) & 1) return bits;
      bits++;
    }
  }
  return bits;
}

export interface SolveOptions {
  /** Abort once this fires — wire it to user navigation. */
  signal?: AbortSignal;
  /** Called every 1024 grinds with the current iteration count. */
  onProgress?: (iterations: number) => void;
}

/**
 * Grind a nonce so that SHA-256("id:salt:nonce") starts with `difficulty`
 * zero bits. Expected work is 2^difficulty hashes.
 *
 * Runs on the calling thread: in browsers, call this inside a Web Worker to
 * keep the page responsive. `onProgress`/`signal` only take effect between
 * iterations for exactly that reason.
 */
export async function solve(ch: Challenge, opts: SolveOptions = {}): Promise<Solution> {
  if (ch.algorithm !== "sha256") {
    throw new Error(`mythic: unsupported algorithm ${ch.algorithm}`);
  }
  if (!Number.isInteger(ch.difficulty) || ch.difficulty < 0 || ch.difficulty > 32) {
    throw new Error(`mythic: implausible difficulty ${ch.difficulty}`);
  }
  const encoder = new TextEncoder();
  const prefix = `${ch.id}:${ch.salt}:`;
  for (let n = 0; ; n++) {
    if (n % 1024 === 0) {
      opts.onProgress?.(n);
      opts.signal?.throwIfAborted();
    }
    const nonce = n.toString(16);
    const sum = await sha256(encoder.encode(prefix + nonce));
    if (leadingZeroBits(sum) >= ch.difficulty) {
      return { challenge_id: ch.id, nonce };
    }
  }
}
