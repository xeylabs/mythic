# ADR-0011: M2 behavioral biometrics — privacy-preserving, advisory-only

- **Status:** Proposed (2026-10-06)

## Context

ADR-0008 documented the fundamental limit of solve-time floors: a client
that solves instantly and delays verify defeats wall-clock measurement by
design. The threat model names this the gap M2 must close. Behavioral
biometrics — how the pointer moves, how keys are struck, how pages scroll —
are expensive to fake convincingly at scale, even though a determined
attacker controlling the browser *can* fake them.

## Decision

1. **Feature extraction in-SDK, never raw trajectories.** The SDK collects
   pointer/keyboard/scroll events locally and computes aggregate features:
   no raw coordinates, no key contents, no scroll positions leave the
   device. What the server receives is a feature vector:
   - Mouse: mean velocity, velocity variance, curvature histogram (3 bins),
     direction-change rate, micro-tremor energy (high-freq component)
   - Keystroke: mean dwell time, mean flight time, dwell variance
     (no key identities — only timing)
   - Scroll: event count, mean delta, direction reversals
   All features are quantized to reduce fingerprinting surface.

2. **Server scores plausibility, not identity.** The risk engine checks
   whether the feature vector falls within human-plausible ranges
   (calibrated from published HCI literature, not from tracking users):
   - Zero movement + instant solve = bot (high penalty)
   - Perfectly straight lines at constant velocity = bot (medium penalty)
   - Human-like variance = small discount
   The engine never learns "this specific user" — it checks "does this
   look like a human in general."

3. **Advisory with hard caps (ADR-0004).** Behavioral signals contribute
   at most 20 points combined. They can raise suspicion, never decide
   alone. A sophisticated bot with recorded human trajectories can still
   pass — the cost is recording + replaying + varying the replay, which
   is orders of magnitude more expensive than `curl`.

4. **Graceful degradation.** No behavioral data (JS disabled, SDK not
   loaded, privacy-conscious user) = signal absent = zero contribution,
   not a penalty. Punishing privacy choices would be both wrong and
   create an oracle for attackers to probe.

5. **No persistent identifiers.** Features are per-challenge, never
   stored, never correlated across sessions. The server is stateless
   regarding behavior — each evaluation is independent.

## Bypass analysis (written first, per repo rule)

- **Recorded human trajectories replayed** → passes if the replay has
  natural variance. Cost: recording setup + per-target replay engineering.
  Mitigated by: challenge-bound nonces in the feature vector (replay of
  the *same* vector is detectable via dedup).
- **Synthetic trajectory generation** (Bezier curves with noise) →
  passes basic plausibility. Cost: moderate. Mitigated by: micro-tremor
  analysis (synthetic noise has different spectral properties than
  human motor noise) — future refinement.
- **Real human farm** (click farms) → passes everything. This is the
  fundamental limit: behavioral biometrics detect *automation*, not
  *intent*. A human paid to solve is indistinguishable from a human
  user. Mitigated by: PoW economics (each solve still costs compute)
  + per-IP pressure.
- **No-JS client** → signal absent, zero contribution. The attacker
  loses nothing but gains nothing; PoW + other signals still apply.

## Consequences

- SDK grows: event listeners + feature extraction (~200 lines TS).
  Must not impact page performance (throttled collection, <1% CPU).
- Server risk engine gains a `BehavioralFeatures` input struct and
  plausibility scoring (~150 lines Go + tests).
- Wire format: `hints.behavioral` object in challenge/verify requests.
  Versioned (`v:1`) for future evolution.
- Privacy documentation must clearly state what is collected (timing
  aggregates) and what is NOT (coordinates, keys, content).
- The adversarial test suite (recorded-bot vs human datasets) is
  essential — without it, we're tuning blind.
