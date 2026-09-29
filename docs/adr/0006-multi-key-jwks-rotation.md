# ADR-0006: Multi-key JWKS and in-process key rotation

- **Status:** Accepted (2026-09-29)

## Context

Until now mythicd held exactly one Ed25519 key: the JWKS endpoint advertised a
single key, and rotating it meant regenerating the seed and restarting — a
deploy event that instantly invalidated every unexpired token in the wild and
every origin's cached JWKS. ADR-0002 flagged this explicitly: "Key rotation
needs multi-key JWKS before it is safe — until then, rotation is a deploy
event, not an online operation." The threat model lists long-lived signing
seeds as standing risk: the longer a key signs, the larger the window for its
compromise to matter.

## Decision

1. **Key ring, one active signer.** mythicd holds an ordered set of keys.
   Exactly one is *active* and signs every new token; the others are
   *retired* and exist only so tokens signed before a rotation remain
   verifiable until they naturally expire.
2. **JWKS lists every key.** `/v1/.well-known/jwks.json` advertises the
   active key first, then retired keys, each with its stable `kid`. Origins
   select the verification key by the `kid` claimed inside the token.
3. **Rotation is time-based and in-process.** When the active key is older
   than `MYTHIC_KEY_MAX_AGE` (default 720h), the server generates a successor,
   moves the predecessor to retired, and persists the ring — without dropping
   a request or restarting. `MYTHIC_KEY_MAX_AGE=0` disables auto-rotation.
4. **Retired keys expire.** A retired key leaves the ring once it has been
   retired longer than `MYTHIC_KEY_RETENTION` (default 24h) — far beyond the
   5-minute token TTL plus realistic JWKS cache ages. Pruned keys are
   forgotten: their tokens are expired anyway.
5. **Keystore file, atomic writes.** `MYTHIC_KEY_FILE` becomes a JSON
   keystore: `{"version":1,"keys":[{seed, created_at, retired_at}…]}`.
   Rotation rewrites it via temp-file + rename. A legacy file containing a
   bare 32-byte seed still loads as the active key (created_at from the file
   mtime) and is migrated to the JSON format on the next save.
6. **xtoken does not change.** Origin verification already takes a public key;
   key selection by `kid` is the origin's policy, using whatever JWKS it
   cached.

## Consequences

- Rotation stops being downtime: tokens issued before a rotation verify
  against the retired key for as long as they can still be unexpired.
- Security posture improves by default; operators who want the old
  behavior set `MYTHIC_KEY_MAX_AGE=0`.
- The JWKS payload grows by one entry per retained key — bounded by
  retention ÷ max-age (by default a single retired key).
- Origins that pin a single JWKS entry instead of selecting by `kid` will
  break on rotation. That is the intended pressure: selection by `kid` is
  the contract (token claims carry `kid` since v1).
- Compromise of the active seed still requires out-of-band revocation —
  rotation limits the *lifetime* exposure of any single seed, it is not a
  response to a known compromise.
