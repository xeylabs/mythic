# ADR-0003: Hashcash-style SHA-256 proof-of-work with adaptive difficulty

- **Status:** Accepted (2026-09-28)

## Context

The baseline gate must require real work from every client without human
interaction. Candidates: interactive puzzles (image grids), server-computed
secret challenges, hardware attestation, proof-of-work.

## Decision

Hashcash-style PoW: client finds a nonce where `SHA-256(id:salt:nonce)` starts
with `difficulty` zero bits. The risk engine sets difficulty per request
(base 18 ≈ 2^18 hashes; escalates toward a 26 cap as risk grows). Verification
is a single hash server-side.

## Consequences

- Cost asymmetry is the product: one visitor pays ~a second in a Web Worker;
  a farm pays it per request, forever, in the exact currency (compute) that
  makes their operation profitable.
- Zero client dependencies (Web Crypto `SHA-256`), browser and Node alike.
- GPUs and ASICs solve PoW cheaply — PoW alone cannot stop a funded adversary.
  It is the floor of the stack, not the ceiling: behavioral (M2) and
  cryptographic (M4) layers handle what money can brute-force.
- Difficulty floors are calibrated to Web Worker speeds; the risk engine's
  plausibility check compares *server-measured* elapsed time against that
  floor, so native/GPU clients that answer too fast are scored up.
- Energy cost is visible and intentional: difficulty scales with risk, so the
  honest majority stays at base difficulty.
