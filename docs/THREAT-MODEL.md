# Threat Model

Read this before writing any signal, rule, or handler. The model is STRIDE-lite:
who attacks, what they want, what stops them, and what honestly doesn't.

## Core trust assumptions

1. **The client is hostile by default.** The attacker controls their browser,
   its JavaScript environment, the network path, and every byte the SDK emits.
   No client-side check can be an authority. (ADR-0004)
2. **Automation is cheap.** Solving farms sell CAPTCHA answers for under $3 per
   1,000; vision-LLM agents solve interactive challenges; stealth browsers
   (Patchright, Camoufox) defeat naive fingerprinting. Assume all of it.
3. **Economics, not impossibility.** We do not promise "bots cannot pass."
   We promise passing costs more than the abuse earns. Every layer raises the
   per-attempt cost; every layer is independent.

## Assets

| Asset | Why it matters |
|---|---|
| Decision tokens | The thing attackers want without doing the work |
| Ed25519 signing seed | Total compromise — anyone holding it can mint tokens |
| Risk engine weights/thresholds | Knowledge sharpens attacks (obscurity is not security, but leaked tuning helps adversaries) |
| Single-use challenge registry | Replay / double-verification would collapse the PoW economics |

## Actors & capabilities

| Actor | Capability | Examples |
|---|---|---|
| Script kiddie | Plain HTTP clients (curl, requests) | Scraping, spam, vote manipulation |
| Stealth-bot operator | Headless/patched browsers defeating naive checks | Puppeteer + Patchright, Camoufox |
| Solving-farm customer | Human farms + solver APIs | CapSolver, 2Captcha |
| Vision-LLM agent | Screenshot-driven interactive solving | Computer-use agents |
| Credential stuffer | Massive distributed login attempts, residential proxies | ATO campaigns |

## Attack → mitigation matrix

| Attack | Mitigation (v0) | Residual risk & planned layers |
|---|---|---|
| Plain HTTP bot, no PoW | Cannot obtain a token: PoW required, single-use | — |
| PoW solved by script | Difficulty adapts with risk score; per-IP pressure cap | Behavioral layer (M2) raises cost further |
| Replay a challenge/nonce | Atomic single-use `Take` from the store; TTL expiry | Redis store (M1) for multi-node |
| Forged/altered token | Ed25519 signature over payload; origin verifies locally | — |
| Token theft (reuse) | Short TTL (default 5 min); jti (revocation-ready) | Binding tokens to session/origin (M3) |
| Solve-time shortcut (native/GPU solver) | Server-measured plausibility floor per difficulty | Floor is an upper bound on *humanly plausible*, not on hardware — behavioral biometrics closes this (M2) |
| Distributed attack (fresh IPs per request) | Per-IP counters only — weak by design in v0 | Honest gap: needs IP reputation, JA4+ TLS fingerprint, ASN scoring (M1/M3) |
| Solve-farm relay (human solves in browser farm) | Server-side solve-time floor vs. round-trip latency | Behavioral biometrics (M2); cryptographic step-up for high-value actions (M4) |
| Client-hint forgery ("I'm human, honest") | Hints are advisory with hard weight caps; denying `webdriver:true` in a bot just forfeits a discount | — |
| Risk-engine bypass via unknown site key | Site-key allowlist (`MYTHIC_SITES`) | — |
| Flood mythicd itself (DoS) | Per-IP rate limit; stateless handlers | CDN in front; PoW itself is the anti-flood cost (M3: stricter floors under load) |
| Signing-key theft | Seed `0600` on disk, git-ignored, env-configured; time-based rotation bounds any single seed's signing lifetime (multi-key JWKS, [ADR-0006](adr/0006-multi-key-jwks-rotation.md)) | Key revocation on known compromise; HSM (M5) |

## Explicit non-goals

- **Stopping a determined human.** A human clicking through will always pass.
- **DDoS defense.** Capacity problem — put a CDN in front.
- **Replacing authentication.** Decision tokens say "likely human," never
  "this is user X" (that's WebAuthn/passkeys, M4).
- **Perfect recall.** Some bots pass; the product question is at what price.

## Honest limitations of v0

- In-memory store binds mythicd to one node; restarts orphan issued challenges.
- Server-observed signals are thin: solve-time plausibility and per-IP pressure.
  The behavioral and network-fingerprint layers are roadmap, not reality —
  until they ship, a stealth browser with a native solver beats v0.
- Client hints are trivially forgeable. That is *by design* — they exist to
  cheaply classify the honest majority of casual bots, never to decide alone.
- Failure mode is configurable per deployment: the store lives inside the
  process, so an mythicd outage fails closed for protected flows.

## Review triggers

Revisit this document when: a new signal lands, difficulty policy changes,
the store moves to Redis, key revocation replaces time-based rotation as the
recovery path, or a bypass report arrives.
