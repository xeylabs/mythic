# Roadmap

Status markers: ✅ shipped · 🚧 in progress · 📋 planned.

## M0 — Skeleton (current)

- ✅ mythicd: challenge/verify API, JWKS, health
- ✅ Adaptive SHA-256 proof-of-work with plausibility floors
- ✅ Deterministic risk engine (solve-time, per-IP pressure, capped advisory hints)
- ✅ Ed25519 decision tokens + origin-side `xtoken` verification package
- ✅ SDK JS: solver, signal collector, token orchestration
- ✅ Threat model, architecture docs, ADRs, CI

## M1 — Hardening the foundation

- ✅ Redis store (single-use challenges via `GETDEL`, sliding-window IP
  counters) for multi-node ([ADR-0009](adr/0009-redis-store-sliding-window.md))
- ✅ Multi-key JWKS and zero-downtime key rotation ([ADR-0006](adr/0006-multi-key-jwks-rotation.md))
- 📋 Network fingerprints: JA4+/HTTP2 fingerprinting, ASN class scoring
  (datacenter vs residential), optional IP reputation feed
- 📋 Packaged PoW Web Worker in the SDK (off-main-thread by default)
- 📋 Origin verification helpers beyond Go (Node, Python)

## M2 — Behavioral layer

- 📋 Mouse trajectory dynamics (velocity profiles, curvature, micro-tremor)
- 📋 Keystroke dynamics (dwell/flight time distributions)
- 📋 Scroll/pointer entropy; touch pressure & area on mobile
- 📋 Privacy-preserving feature extraction in-SDK (no raw trajectories leave the device)
- 📋 Adversarial test suite: recorded-bot vs human datasets in CI

## M3 — Learning engine

- 📋 Feedback pipeline: decisions + outcomes → labeled corpus
- 📋 Anomaly detection over signal vectors (unsupervised first)
- 📋 Score calibration & drift monitoring; rule/model shadow mode
- 📋 Token binding to session/origin context

## M4 — Cryptographic step-up

- 📋 WebAuthn/passkey challenge as high-assurance layer for sensitive actions
- 📋 Mobile device attestation (Play Integrity / App Attest / DeviceCheck)
- 📋 Policy engine: per-route step-up requirements for origins

## M5 — Platform

- 📋 Dashboard: traffic, risk distribution, rule tuning, site keys
- 📋 Multi-tenant site management, per-site policies & analytics
- 📋 Plugins/SDKs: WordPress, Next.js middleware, reverse-proxy module
- 📋 Security audit + public bug bounty (public launch moment)

<!-- CI trigger note: push events evaluated here -->
