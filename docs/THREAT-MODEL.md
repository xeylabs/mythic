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
| Replay a challenge/nonce | Atomic single-use `Take` from the store; TTL expiry | Redis backend available for multi-node ([ADR-0009](adr/0009-redis-store-sliding-window.md)) |
| Forged/altered token | Ed25519 signature over payload; origin verifies locally | — |
| Token theft (reuse) | Short TTL (≤ challenge TTL, enforced; default 3 min); jti (revocation-ready) | Binding tokens to session/origin (M3) |
| Solve-time shortcut (native/GPU solver) | Quantile-calibrated solve-time floor ([ADR-0008](adr/0008-quantile-solve-time-floor.md)): GPU-class answers (~100× a worker) trip it ~96%; near-worker native rates partly escape | The floor is wall-clock — a client that *delays* verify defeats it by design; behavioral layer (M2) closes this |
| Distributed attack (fresh IPs per request) | Per-identity counters — IPv6 aggregated to /64 ([ADR-0007](adr/0007-ipv6-slash64-pressure-key.md)), so one line is one identity; IPv4 stays /32 | Honest gap: a /48 still yields 65k identities; needs IP reputation, JA4+ TLS fingerprint, ASN scoring (M1/M3) |
| Solve-farm relay (human solves in browser farm) | Solve-time floor adds nothing against a patient relay — it can simply wait | Behavioral biometrics (M2); cryptographic step-up for high-value actions (M4) |
| Client-hint forgery ("I'm human, honest") | Hints are advisory with hard weight caps; denying `webdriver:true` in a bot just forfeits a discount | — |
| Risk-engine bypass via unknown site key | Site-key allowlist (`MYTHIC_SITES`) | — |
| Flood mythicd itself (DoS) | Per-identity rate limit (/64-aggregated); stateless handlers | CDN in front; PoW itself is the anti-flood cost (M3: stricter floors under load) |
| Signing-key theft | Seed `0600` on disk, git-ignored, env-configured; time-based rotation bounds any single seed's signing lifetime (multi-key JWKS, [ADR-0006](adr/0006-multi-key-jwks-rotation.md)) | Key revocation on known compromise; HSM (M5) |

## Explicit non-goals

- **Stopping a determined human.** A human clicking through will always pass.
- **DDoS defense.** Capacity problem — put a CDN in front.
- **Replacing authentication.** Decision tokens say "likely human," never
  "this is user X" (that's WebAuthn/passkeys, M4).
- **Perfect recall.** Some bots pass; the product question is at what price.

## Honest limitations of v0

- The default in-memory store binds mythicd to one node — set
  `MYTHIC_STORE=redis` for shared challenge/pressure state (fail-closed on
  outage, ADR-0009). **Signing keys stay per-node** (ADR-0006): a token from
  node A does not verify against node B's JWKS, so multi-node deployments
  need same-node JWKS access until a shared keystore (KMS/HSM, M5) lands.
- Server-observed signals are thin: quantile-calibrated solve-time plausibility
  ([ADR-0008](adr/0008-quantile-solve-time-floor.md)) and per-identity pressure.
  The floor catches hardware that answers faster than any honest worker — it
  cannot and does not catch a client that delays its verify. The behavioral
  and network-fingerprint layers are roadmap, not reality —
  until they ship, a stealth browser with a patient native solver beats v0.
- Client hints are trivially forgeable. That is *by design* — they exist to
  cheaply classify the honest majority of casual bots, never to decide alone.
- Failure mode is configurable per deployment: with the in-memory store an
  mythicd outage fails closed for protected flows; with the Redis store the
  same applies to a Redis outage (fail closed by choice, ADR-0009).
- The difficulty ceiling assumes desktop-class workers (~400k H/s measured);
  low-power mobile devices need headroom at high risk scores — calibrate
  against real device data when M2 lands.

## Review triggers

Revisit this document when: a new signal lands, difficulty policy changes,
the store moves to Redis, key revocation replaces time-based rotation as the
recovery path, or a bypass report arrives.
