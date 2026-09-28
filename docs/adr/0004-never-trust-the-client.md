# ADR-0004: Client signals are advisory, never decisive

- **Status:** Accepted (2026-09-28) — this is the project's first-principles ADR.

## Context

Most captcha/anti-bot products implicitly trust the client: the browser runs
the vendor's script, reports environment facts, and a "pass" is accepted.
Patchright, Camoufox, and solving farms exist precisely because that trust is
exploitable.

## Decision

**Never trust the client.** Every byte that arrives from the browser is
adversarial input. Concretely:

1. Client-reported hints (automation flags, environment consistency checks)
   enter the risk engine as *advisory* signals with hard, capped weights.
2. No advisory signal, alone or in sum, can reach a deny decision.
3. Decisions are driven by server-observed facts: request pressure, challenge
   economics, plausibility of server-measured solve times.
4. The final authority is the server-side engine; the client SDK is a sensor,
   not a judge.

## Consequences

- Forging a hint only forfeits a discount the honest report would have earned —
  a strictly dominated strategy for the bot.
- The architecture is honest about v0: with thin server-side signals, a
  stealth browser + native solver beats the current layers. That is a roadmap
  gap (M1–M3), not a hidden weakness.
- Every future signal (behavioral biometrics, TLS fingerprints) must slot into
  the same advisory weighting, or the ADR must be amended explicitly.
- PR review rule: any change that lets client data become an authority over
  the decision is rejected.
