# ADR-0002: Ed25519-signed decision tokens verified at the origin

- **Status:** Accepted (2026-09-28)

## Context

After the SDK passes a challenge, the protected origin must learn the verdict.
Options: (a) origin calls xprotectd to validate (stateful, adds latency and an
uptime dependency), or (b) xprotectd issues a short-lived signed token the
origin verifies locally.

## Decision

Stateless option (b): xprotectd signs a JSON claim set with Ed25519
(`base64url(payload).base64url(signature)`) carrying site key, decision, risk
score, key id, jti, iat, exp. Origins fetch the public key once from
`/v1/.well-known/jwks.json` and verify offline via the public `server/xtoken`
package.

Ed25519 over ECDSA/RSA: 64-byte signatures, tiny keys, deterministic signing,
first-class in the Go stdlib and easy in every modern language.

## Consequences

- Origin uptime is independent of xprotectd uptime for already-issued tokens.
- Short TTL (default 5 min) bounds token-theft damage; jti is reserved for a
  future revocation surface.
- Key rotation needs multi-key JWKS before it is safe (roadmap M1) — until
  then, rotation is a deploy event, not an online operation.
- Claims are informational, not a session: tokens say "likely human", never
  "this is user X".
