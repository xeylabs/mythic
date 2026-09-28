# Changelog

All notable changes to XProtect are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `server`: xprotectd — challenge issuance, adaptive SHA-256 proof-of-work,
  rule-based risk engine (solve-time plausibility, per-IP pressure), Ed25519
  signed decision tokens, JWKS endpoint, per-IP rate limiting.
- `server/xtoken`: origin-side token verification package (local, no callback).
- `sdk/js`: browser/Node client — PoW solver (Web Crypto), advisory signal
  collector, token orchestration.
- Docs: architecture, threat model, roadmap, ADR-0001…0004.
- CI: GitHub Actions for server (fmt/vet/test/race) and SDK (typecheck/test/build).
