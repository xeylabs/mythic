# Changelog

All notable changes to XProtect are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `server/xtoken`: tamper-resistance property suite — 10,000 deterministic
  byte-mutation attempts per run (all rejected), forged-claim edits
  (deny→allow, risk, site key, expiry) with the original signature (all
  rejected), cross-key verification matrix, and a native fuzz target
  (`FuzzVerifyToken`) that runs a short pass in CI on every push.
- `server`: xprotectd — challenge issuance, adaptive SHA-256 proof-of-work,
  rule-based risk engine (solve-time plausibility, per-IP pressure), Ed25519
  signed decision tokens, JWKS endpoint, per-IP rate limiting.
- `server/xtoken`: origin-side token verification package (local, no callback).
- `sdk/js`: browser/Node client — PoW solver (Web Crypto), advisory signal
  collector, token orchestration.
- Docs: architecture, threat model, roadmap, ADR-0001…0004.
- CI: GitHub Actions for server (fmt/vet/test/race) and SDK (typecheck/test/build).

### Security

- `server/xtoken`: decision tokens now **reject non-canonical base64**.
  Go's decoder silently discards the unused low bits of a trailing character,
  so distinct strings could decode to the same token and verify (e.g. the
  last character of a 64-byte signature carries only 2 data bits). Not a
  forgery path — decoded bytes were identical — but it broke string-level
  token identity. Found by the new mutation-storm suite on its first run.
