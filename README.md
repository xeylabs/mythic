<div align="center">

# XProtect

**Adaptive bot mitigation. Never trust the client.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![server](https://github.com/xeylabs/xprotect/actions/workflows/server-ci.yml/badge.svg)](https://github.com/xeylabs/xprotect/actions/workflows/server-ci.yml)
[![sdk-js](https://github.com/xeylabs/xprotect/actions/workflows/sdk-ci.yml/badge.svg)](https://github.com/xeylabs/xprotect/actions/workflows/sdk-ci.yml)

*The first project by [xeylabs](https://github.com/xeylabs). Status: **pre-alpha**, under active development.*

</div>

---

Today's CAPTCHAs are dead: solving farms sell answers for less than $3 per 1,000,
vision models read image challenges, and stealth browsers walk past fingerprint
checks. XProtect takes a different position — **assume the client is hostile by
default** and make abuse economically irrational instead of pretending it can be
prevented.

## How it works

XProtect replaces the binary "captcha pass/fail" model with a **layered step-up
system** driven by a server-side risk engine:

| Layer | What it does | Status |
|---|---|---|
| Adaptive proof-of-work | Hashcash-style SHA-256 challenge; difficulty scales with risk. Cheap once for humans, millions of times more expensive for bot farms. | ✅ v0 |
| Signed decision tokens | Ed25519-signed, short-TTL tokens your origin backend verifies locally — no callback to XProtect required. | ✅ v0 |
| Risk engine | Weighted scoring of server-observed signals (solve-time plausibility, per-IP challenge pressure) with deterministic, auditable rules. | ✅ v0 |
| Advisory client signals | SDK-collected environment hints (automation flags, consistency checks) — weight-capped, never decisive. | ✅ v0 |
| Behavioral biometrics | Mouse trajectory dynamics, keystroke timing, scroll patterns. | 🚧 Roadmap |
| Cryptographic step-up | WebAuthn/passkey for high-value actions; device attestation on mobile. | 🚧 Roadmap |
| ML scoring + feedback loop | Learned scoring layered over rules, retrained from production outcomes. | 🚧 Roadmap |

> **The one rule above all:** every client-side signal is advisory input to a
> server-side decision. An attacker controls their browser completely — XProtect
> never treats the client as an authority. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

```
┌──────────┐   1. POST /v1/challenge    ┌──────────────────┐
│  Client  │ ─────────────────────────▶ │    xprotectd     │
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
go run ./server/cmd/xprotectd
# → xprotectd listening on :8080, JWKS at /v1/.well-known/jwks.json
```

**Or with Docker:**

```bash
docker build -t xeylabs/xprotect .
docker run -p 8080:8080 -e XPROTECT_SITES=my-site-key xeylabs/xprotect
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
import { XProtectClient } from "@xeylabs/xprotect";

const xp = new XProtectClient({ endpoint: "https://protect.example.com", siteKey: "my-site-key" });
const { token } = await xp.getToken(); // challenge → PoW (worker-friendly) → signed token
// attach `token` to the protected request on your site
```

**Origin verification (Go):**

```go
import "github.com/xeylabs/xprotect/server/xtoken"

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

## Repository layout

```
xprotect/
├── server/     Go — xprotectd: challenge API, risk engine, PoW, tokens
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

XProtect is [AGPL-3.0](LICENSE) licensed — © 2026 xeylabs.
