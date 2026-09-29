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
