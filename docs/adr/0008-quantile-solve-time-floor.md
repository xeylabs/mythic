# ADR-0008: Solve-time floors are quantile-calibrated — and delay-defeatable

- **Status:** Accepted (2026-09-29)
- **Amends:** the calibration described in ADR-0003 (its floor choice, not its PoW economics)

## Context

A red-team session (2026-09-29) measured the solve-time plausibility floor
against reality and found it inverted:

1. **The model was slow.** The floor modeled a worker at 50,000 SHA-256/s.
   A real `crypto.subtle` worker measured ~404,000/s in this environment, and
   V8 browsers typically run higher. At difficulty 18 the floor (5.24 s)
   sat ~10–20× above honest solve times — essentially **every honest client
   was scored `solve_time_implausible`** (+35 → decision `challenge`).
2. **The floor equaled the mean.** PoW completion time is geometric: even a
   client running at exactly the modeled rate completes below a mean-derived
   floor 63% of the time. A single-sample floor on an exponential
   distribution is statistically unsound wherever it is placed: any floor
   that catches solve times R-faster than honest also flags the honest tail
   at 1−e^(−R·floor/mean).
3. **Sleep defeats any wall-clock floor.** A client that solves instantly
   and *delays* the verify past the floor pays latency, not compute. The
   floor cannot be repaired against this — it is a property of measuring
   wall-clock time on a schedule the attacker controls.

## Decision

1. **Model the fastest plausible honest worker**, not an average one:
   `OptimisticHashRate` = 2,000,000 SHA-256/s.
2. **Move the floor to a low quantile of honest solve time**: the plausible
   floor is `2^difficulty / (rate × 32)`. Even a client at 4× the modeled
   rate is flagged ≤ ~6% of the time; GPU-class clients (~100× the worker,
   the case the floor exists for) trip it ~96% of the time. CPU-native
   solvers near worker speed partly escape — PoW economics, not the floor,
   are their cost (ADR-0003).
3. **Keep the penalty at 35.** With a quantile floor a trip is now evidence
   of hardware, not of luck, and a single trip steps up the *next*
   difficulty without denying anyone.
4. **Say the quiet part:** the floor detects clients that answer faster than
   any honest worker could. It does **not** detect a client that waits. The
   delay-resistant answers are behavioral signals (M2) and cryptographic
   step-up (M4) — this ADR exists so no document claims otherwise again.

## Consequences

- Honest false positives drop from ~63–100% to ≤ ~6% worst case, ~1% typical.
- Floors at low difficulties truncate to zero by integer division — the
  plausibility check only becomes active where PoW is real work (d ≥ ~15).
  That is fine: below that, the floor has nothing to say.
- The sleep bypass remains, by documented design, until M2. Its cost to an
  attacker is a fixed delay — which the per-challenge TTL and per-identity
  pressure (ADR-0007) still bound.
