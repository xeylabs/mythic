# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` (unreleased) | ✅ |

XProtect is **pre-alpha**. It is not audited and is not production-hardened yet.
Do not rely on it as your only line of defense.

## Reporting a vulnerability

**Never open a public issue for a security problem** — a bypass that is
disclosed before it is fixed protects nobody.

Report privately via [GitHub Security Advisories](https://github.com/xeylabs/xprotect/security/advisories/new)
("Report a vulnerability"). Include:

- A description of the bypass/vulnerability and its impact
- Steps or code to reproduce (a working bypass PoC is the single most useful thing you can send)
- The threat scenario it enables (scraping, credential stuffing, spam, …)

**Response targets:** acknowledgment within 72 hours; triage and severity
assignment within 7 days; fix or mitigation timeline communicated after triage.

## Scope

In scope: anything that lets an attacker obtain a valid decision token without
performing the intended work, forge or replay tokens, degrade or bypass the
risk engine, or compromise the server / signing keys.

Out of scope: DDoS (capacity problem — use a CDN), attacks requiring physical
access, social engineering of xeylabs staff, vulnerability reports about
third-party dependencies without a concrete XProtect impact.

## Design positions relevant to security review

- Every client-side signal is advisory input to server-side scoring — never an
  authority. If you find client signals being trusted, that is a bug.
- Challenge redemption is single-use; tokens are short-TTL and Ed25519-signed.
- Signing seeds are generated at startup and written to disk with `0600`
  (`XPROTECT_KEY_FILE`); they are git-ignored and must never leave the host.

## Hardening checklist before any production use

- [ ] Deploy behind a TLS-terminating proxy that sanitizes `X-Forwarded-For`
- [ ] Set `XPROTECT_SITES` to an explicit site-key allowlist
- [ ] Restrict `XPROTECT_CORS_ORIGINS` to the origins that embed the SDK
- [ ] Persist `XPROTECT_KEY_FILE` on durable storage with strict permissions
- [ ] Rotate the signing key on a schedule (redeploy with a new file)
