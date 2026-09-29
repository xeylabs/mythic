# Changelog

All notable changes to Mythic are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `server`: **multi-key JWKS and in-process key rotation**
  ([ADR-0006](docs/adr/0006-multi-key-jwks-rotation.md)) — mythicd keeps a
  key ring with one active signer; when the active key passes
  `MYTHIC_KEY_MAX_AGE` (default 720h) a successor is generated without
  restart, the predecessor stays advertised in the JWKS until
  `MYTHIC_KEY_RETENTION` (default 24h) expires, and the ring persists as a
  JSON keystore (`MYTHIC_KEY_FILE`) written atomically. Legacy bare-seed
  files keep loading and migrate on the first save.
- `server`: risk-engine tuning (difficulty floors and decision thresholds)
  is now deployment-side configuration via `MYTHIC_*` environment
  variables — the public defaults are a starting point, each deployment's
  operating margins stay private.
- `CLA.md`: contributor license agreement keeping the codebase free to
  dual-license commercially; PRs carry a CLA checkbox.
- `server/xtoken`: tamper-resistance property suite — 10,000 deterministic
  byte-mutation attempts per run (all rejected), forged-claim edits
  (deny→allow, risk, site key, expiry) with the original signature (all
  rejected), cross-key verification matrix, and a native fuzz target
  (`FuzzVerifyToken`) that runs a short pass in CI on every push.
- `server`: mythicd — challenge issuance, adaptive SHA-256 proof-of-work,
  rule-based risk engine (solve-time plausibility, per-IP pressure), Ed25519
  signed decision tokens, JWKS endpoint, per-IP rate limiting.
- `server/xtoken`: origin-side token verification package (local, no callback).
- `sdk/js`: browser/Node client — PoW solver (Web Crypto), advisory signal
  collector, token orchestration.
- Docs: architecture, threat model, roadmap, ADR-0001…0004.
- CI: GitHub Actions for server (fmt/vet/test/race) and SDK (typecheck/test/build).

### Changed

- **Licensing unified**: the whole project — server and SDK — ships under
  AGPL-3.0-or-later. Source files carry SPDX identifiers.

### Security

- `server`: **every `/v1` request consumes the caller's rate-limit budget
  before validation** (red-team G2 session, 2026-09-29). Invalid-JSON and
  unknown-site-key floods previously bypassed the limiter entirely — 600
  hostile rounds at 225 req/s, zero 429s. `healthz` stays uncounted for
  load balancers.
- `server`: **response/body timeouts** — `ReadTimeout`/`WriteTimeout`/
  `IdleTimeout` set on the HTTP server; a slow-reading client no longer
  holds its connection and goroutine indefinitely (slow-body hold, PoC'd).
- `server`: **configuration is validated at startup and nonsense refuses to
  serve** — a negative `MYTHIC_BASE_DIFFICULTY` used to issue challenges any
  nonce satisfied (zero-work tokens). Difficulty range, threshold ordering,
  and positivity of limits/TTLs are now enforced.
- `server/internal/api`: **trailing bytes after a JSON value are rejected**
  instead of silently ignored.
- `server/internal/crypto`: **keystore writes refuse to clobber on-disk
  changes** made since load, and temp files are process-unique — two
  processes sharing `MYTHIC_KEY_FILE` previously collided on one `.tmp`
  name (startup failure) or silently split-brained their signing keys
  (each advertised a key the other never listed).
- `server`: **per-identity rate limiting aggregates IPv6 to /64**
  ([ADR-0007](docs/adr/0007-ipv6-slash64-pressure-key.md)). A red-team
  session showed the /128-keyed limiter let a single IPv6 /64 mint 2⁶⁴
  identities — a PoC drove 5,000 requests from one /64 with zero hits on the
  limiter. IPv4 (and IPv4-mapped) addresses stay /32; access logs keep the
  full address.
- `server`: **decision tokens can no longer outlive their challenge.** The
  ADR-0002 contract ("never longer than the challenge TTL") was documented
  but unenforced — a red-team session issued a 1-hour token from a 5-second
  challenge. `api.New` now clamps `TokenTTL` to `ChallengeTTL` with a
  startup warning; defaults change accordingly (token 5m → 3m).
- `server/internal/challenge`: **solve-time floor recalibrated to a low
  quantile of honest solve time** ([ADR-0008](docs/adr/0008-quantile-solve-time-floor.md)).
  The old floor modeled a 50k H/s worker; real `crypto.subtle` workers
  measure ~400k–1.5M H/s, so honest clients were mass-flagged as
  `solve_time_implausible` (and even at the modeled rate, a mean-derived
  floor flags 63% of honest solves on a geometric distribution). The floor
  now models the fastest plausible worker (2M H/s) divided by 32: honest
  false positives ≤ ~6% worst case, GPU-class answers (~100× a worker) trip
  it ~96% of the time. Documented honestly: a wall-clock floor cannot catch
  a client that *delays* its verify — that is M2's (behavioral layer's) job.
- `server`: **X-Forwarded-For is ignored unless `MYTHIC_TRUST_PROXY=1`**.
  An adversarial session against a live server showed blind XFF trust let a
  rotating fake header bypass the per-IP rate limiter 20/20 and erase the
  risk engine's pressure signal. Default now uses RemoteAddr only; regression
  tests pin both modes (ADR-0005).
- `server/xtoken`: decision tokens now **reject non-canonical base64**.
  Go's decoder silently discards the unused low bits of a trailing character,
  so distinct strings could decode to the same token and verify (e.g. the
  last character of a 64-byte signature carries only 2 data bits). Not a
  forgery path — decoded bytes were identical — but it broke string-level
  token identity. Found by the new mutation-storm suite on its first run.
