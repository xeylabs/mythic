// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

import type { Challenge, Solution } from "./types";
import { leadingZeroBits, sha256 } from "./pow";

/**
 * Packaged Web Worker for PoW solving (session backup M1 item).
 *
 * The solver runs off the main thread so the page stays responsive at
 * high difficulty. Uses a Blob URL so it works with any bundler setup —
 * no separate worker file to host.
 *
 * Usage:
 * ```ts
 * const solution = await solveInWorker(challenge, {
 *   onProgress: (n) => console.log(`tried ${n}`),
 *   signal: abortController.signal,
 * });
 * ```
 */

interface WorkerRequest {
  type: "solve";
  challenge: Challenge;
}

interface WorkerResponse {
  type: "solution";
  solution: Solution;
}

interface WorkerProgress {
  type: "progress";
  iterations: number;
}

interface WorkerError {
  type: "error";
  message: string;
}

/**
 * The worker body as a self-contained function. Stringified into a Blob.
 * Must not close over module scope — everything it needs is inlined or
 * passed via postMessage.
 */
function workerMain(): void {
  // Inlined SHA-256 and leadingZeroBits (worker has no imports).
  async function sha256w(data: Uint8Array): Promise<Uint8Array> {
    const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
    return new Uint8Array(digest);
  }

  function leadingZeroBitsW(sum: Uint8Array): number {
    let bits = 0;
    for (const byte of sum) {
      for (let i = 7; i >= 0; i--) {
        if ((byte >> i) & 1) return bits;
        bits++;
      }
    }
    return bits;
  }

  self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
    const { challenge } = e.data;
    if (e.data.type !== "solve") return;
    try {
      const encoder = new TextEncoder();
      const prefix = `${challenge.id}:${challenge.salt}:`;
      for (let n = 0; ; n++) {
        if (n % 2048 === 0) {
          (self.postMessage as (m: WorkerProgress) => void)({
            type: "progress",
            iterations: n,
          });
        }
        const nonce = n.toString(16);
        const sum = await sha256w(encoder.encode(prefix + nonce));
        if (leadingZeroBitsW(sum) >= challenge.difficulty) {
          (self.postMessage as (m: WorkerResponse) => void)({
            type: "solution",
            solution: { challenge_id: challenge.id, nonce },
          });
          return;
        }
      }
    } catch (err) {
      (self.postMessage as (m: WorkerError) => void)({
        type: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  };
}

// Reference the imports so TypeScript doesn't flag them as unused —
// the worker body above is self-contained by design (no module scope).
void sha256;
void leadingZeroBits;

export interface SolveInWorkerOptions {
  /** Called every 2048 iterations with the current count. */
  onProgress?: (iterations: number) => void;
  /** Abort the worker. */
  signal?: AbortSignal;
  /** Custom Worker constructor (for testing or non-browser environments). */
  createWorker?: (url: string | URL) => Worker;
}

/**
 * Solve a PoW challenge in a Web Worker, off the main thread.
 *
 * Falls back to main-thread `solve()` when Workers are unavailable
 * (Node.js, SSR) — never fails, just slower.
 */
export async function solveInWorker(
  challenge: Challenge,
  opts: SolveInWorkerOptions = {},
): Promise<Solution> {
  // No Worker API (Node, SSR) → fall back to main thread.
  if (typeof Worker === "undefined") {
    const { solve } = await import("./pow");
    return solve(challenge, opts);
  }

  const workerCode = `(${workerMain.toString()})()`;
  const blob = new Blob([workerCode], { type: "application/javascript" });
  const url = URL.createObjectURL(blob);
  const worker = opts.createWorker
    ? opts.createWorker(url)
    : new Worker(url);

  return new Promise<Solution>((resolve, reject) => {
    const cleanup = () => {
      worker.terminate();
      URL.revokeObjectURL(url);
      opts.signal?.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(new DOMException("Aborted", "AbortError"));
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    worker.onmessage = (
      e: MessageEvent<WorkerResponse | WorkerProgress | WorkerError>,
    ) => {
      const msg = e.data;
      if (msg.type === "solution") {
        cleanup();
        resolve(msg.solution);
      } else if (msg.type === "progress") {
        opts.onProgress?.(msg.iterations);
      } else if (msg.type === "error") {
        cleanup();
        reject(new Error(`mythic worker: ${msg.message}`));
      }
    };
    worker.onerror = (e) => {
      cleanup();
      reject(new Error(`mythic worker error: ${e.message}`));
    };

    const req: WorkerRequest = { type: "solve", challenge };
    worker.postMessage(req);
  });
}
