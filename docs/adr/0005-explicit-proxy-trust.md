# ADR-0005: Client IP is trusted only behind an explicit proxy opt-in

- **Status:** Accepted (2026-09-28)

## Context

The per-IP rate limiter and the risk engine's pressure signal are keyed on
the client address. To support reverse-proxy deployments, the first version
of `clientIP` blindly preferred `X-Forwarded-For` over `RemoteAddr`.

An adversarial session against a live server (chaos testing, 2026-09-28)
showed what that costs: with one header an attacker fully controls, rotating
`X-Forwarded-For` per request sailed past the rate limiter **20/20** in the
demo — and equally erased the risk engine's per-IP pressure signal, since
every request looked like a brand-new visitor.

## Decision

`X-Forwarded-For` is ignored unless the operator explicitly opts in with
`XPROTECT_TRUST_PROXY=1`. Default derives the client IP from `RemoteAddr`
only.

## Consequences

- Secure by default: header spoofing buys an attacker nothing on a directly
  exposed xprotectd.
- Proxy deployments must set `XPROTECT_TRUST_PROXY=1` **and** ensure the
  proxy overwrites (not appends to) `X-Forwarded-For`; otherwise the first
  value is still attacker-chosen.
- Regression tests pin both sides: spoofing cannot bypass the limiter with
  the flag off, and distinct forwarded addresses get distinct counters with
  the flag on.
