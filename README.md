<div align="center">

# Mythic

**Adaptive bot mitigation. Never trust the client.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![server](https://github.com/xeylabs/mythic/actions/workflows/server-ci.yml/badge.svg)](https://github.com/xeylabs/mythic/actions/workflows/server-ci.yml)
[![sdk-js](https://github.com/xeylabs/mythic/actions/workflows/sdk-ci.yml/badge.svg)](https://github.com/xeylabs/mythic/actions/workflows/sdk-ci.yml)

*The first project by [xeylabs](https://github.com/xeylabs). Status: **pre-alpha**, under active development.*

</div>

---

Today's CAPTCHAs are dead: solving farms sell answers for less than $3 per 1,000,
vision models read image challenges, and stealth browsers walk past fingerprint
checks. Mythic takes a different position — **assume the client is hostile by
default** and make abuse economically irrational instead of pretending it can be
prevented.

## How it works

Mythic replaces the binary "captcha pass/fail" model with a **layered step-up
system** driven by a server-side risk engine:

| Layer | What it does | Status |
|---|---|---|
| Adaptive proof-of-work | Hashcash-style SHA-256 challenge; difficulty scales with risk. Cheap once for humans, millions of times more expensive for bot farms. | ✅ v0 |
| Signed decision tokens | Ed25519-signed, short-TTL tokens your origin backend verifies locally — no callback to Mythic required. | ✅ v0 |
| Risk engine | Weighted scoring of server-observed signals (solve-time plausibility, per-IP challenge pressure) with deterministic, auditable rules. | ✅ v0 |
| Advisory client signals | SDK-collected environment hints (automation flags, consistency checks) — weight-capped, never decisive. | ✅ v0 |
| Behavioral biometrics | Mouse trajectory dynamics, keystroke timing, scroll patterns. | 🚧 Roadmap |
| Cryptographic step-up | WebAuthn/passkey for high-value actions; device attestation on mobile. | 🚧 Roadmap |
| ML scoring + feedback loop | Learned scoring layered over rules, retrained from production outcomes. | 🚧 Roadmap |

> **The one rule above all:** every client-side signal is advisory input to a
> server-side decision. An attacker controls their browser completely — Mythic
> never treats the client as an authority. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

```
┌──────────┐   1. POST /v1/challenge    ┌──────────────────┐
│  Client  │ ─────────────────────────▶ │    mythicd     │
│   SDK    │ ◀───────────────────────── │  (risk engine +  │
│          │   2. challenge + difficulty │   PoW issuer)   │
│          │                            └──────────────────┘
│  solves  │   3. POST /v1/verify                ▲
│  PoW in  │ ─────────────────────────▶          │ signs
│  worker  │ ◀─────────────────────────          │
│          │   4. decision token (Ed25519)       │
└──────────┘                            ┌──────┴──────┐
                                        │ your origin │
                                        │ verifies    │
                                        │ token local │
                                        └─────────────┘
```

## Quick start

**Server:**

```bash
go run ./server/cmd/mythicd
# → mythicd listening on :8080, JWKS at /v1/.well-known/jwks.json
```

**Or with Docker:**

```bash
docker build -t xeylabs/mythic .
docker run -p 8080:8080 -e MYTHIC_SITES=my-site-key xeylabs/mythic
```

**API:**

```bash
curl -s localhost:8080/v1/challenge -d '{"site_key":"my-site-key"}'
# → {"challenge":{"id":"…","salt":"…","difficulty":18,"algorithm":"sha256", …},"decision":"allow"}

curl -s localhost:8080/v1/verify -d '{"challenge_id":"…","nonce":"…"}'
# → {"token":"<Ed25519-signed>","decision":"allow","risk":0}
```

**Client (SDK):**

```ts
import { MythicClient } from "@xeylabs/mythic";

const xp = new MythicClient({ endpoint: "https://protect.example.com", siteKey: "my-site-key" });
const { token } = await xp.getToken(); // challenge → PoW (worker-friendly) → signed token
// attach `token` to the protected request on your site
```

**Origin verification (Go):**

```go
import "github.com/xeylabs/mythic/server/xtoken"

claims, err := xtoken.VerifyToken(publicKey, token) // local, no network call
// claims.Decision, claims.Risk, claims.Exp …
```

## API surface

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/challenge` | POST | Issue an adaptive proof-of-work challenge |
| `/v1/verify` | POST | Redeem a solution, get a signed decision token |
| `/v1/.well-known/jwks.json` | GET | Public key (JWKS) for origin-side token verification |
| `/healthz` | GET | Liveness |

## Configuration

Everything is environment-driven — including the risk-engine tuning, which is
deliberately deployment-side: defaults are public code, but your operating
margins are yours (see [ADR-0003](docs/adr/0003-sha256-adaptive-pow.md) and
[ADR-0005](docs/adr/0005-explicit-proxy-trust.md)).

| Variable | Default | Purpose |
|---|---|---|
| `MYTHIC_ADDR` | `:8080` | Listen address |
| `MYTHIC_KEY_FILE` | ephemeral | Ed25519 keystore path (JSON, created `0600` on first run; legacy bare-seed files migrate on first save) |
| `MYTHIC_KEY_MAX_AGE` | `720h` | Active-key lifetime before in-process rotation; `0` disables auto-rotation |
| `MYTHIC_KEY_RETENTION` | `24h` | How long a retired key stays in the JWKS after rotation |
| `MYTHIC_SITES` | any key (dev mode) | Comma-separated site-key allowlist |
| `MYTHIC_CORS_ORIGINS` | all origins | Comma-separated origins allowed for the browser SDK |
| `MYTHIC_CHALLENGE_TTL` | `3m` | How long a challenge stays redeemable |
| `MYTHIC_TOKEN_TTL` | `5m` | Decision token lifetime — clamped to `MYTHIC_CHALLENGE_TTL` when larger (ADR-0002) |
| `MYTHIC_IP_WINDOW` | `1m` | Per-IP pressure window |
| `MYTHIC_IP_LIMIT` | `120` | Max requests per IP per window |
| `MYTHIC_TRUST_PROXY` | `false` | Honor `X-Forwarded-For` — only behind a proxy that overwrites it |
| `MYTHIC_LOG_LEVEL` | `info` | `info` or `debug` |
| `MYTHIC_BASE_DIFFICULTY` | `18` | Base PoW difficulty (2^N hashes) |
| `MYTHIC_MAX_DIFFICULTY` | `26` | Difficulty ceiling |
| `MYTHIC_STEP_UP_AT` | `30` | Risk score that escalates difficulty |
| `MYTHIC_HEAVY_AT` | `65` | Risk score that triggers heavy challenge |
| `MYTHIC_DENY_AT` | `85` | Risk score that denies outright |
| `MYTHIC_FAST_SOLVE_PENALTY` | `35` | Penalty for implausible solve times |
| `MYTHIC_PRESSURE_PER_REQ` | `2` | Pressure penalty per excess challenge |
| `MYTHIC_PRESSURE_MAX` | `30` | Pressure penalty cap |

## Repository layout

```
mythic/
├── server/     Go — mythicd: challenge API, risk engine, PoW, tokens
├── sdk/js/     TypeScript — browser/Node client SDK
├── dashboard/  Admin console (planned, see roadmap)
├── docs/       ARCHITECTURE, THREAT-MODEL, ROADMAP, ADRs
└── .github/    CI, templates, governance
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — components, request lifecycle, crypto design
- [Threat model](docs/THREAT-MODEL.md) — what we defend against, and what we honestly cannot
- [Roadmap](docs/ROADMAP.md) — from v0 skeleton to behavioral biometrics and ML scoring
- [ADRs](docs/adr/) — why we chose what we chose

## Security

Found a bypass or a vulnerability? **Do not open a public issue.** Follow
[SECURITY.md](SECURITY.md) and use GitHub's private vulnerability reporting.
Bypass reports with reproductions are the most valuable contributions this
project can receive.

## License

The whole project — engine, SDK, everything — is
[AGPL-3.0-or-later](LICENSE) licensed — © 2026 xeylabs. One strong license,
no exceptions: anyone can use, study, and build on Mythic as long as their
derivatives stay equally open, including over a network.

Commercial licensing, hosted deployments, and support arrangements are
available from [xeylabs](https://github.com/xeylabs). Contributions are
welcome under [CLA.md](CLA.md).
