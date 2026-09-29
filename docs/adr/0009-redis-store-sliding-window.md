# ADR-0009: Redis-backed store with sliding-window pressure counters

- **Status:** Accepted (2026-09-29)

## Context

The v0 in-memory store bound mythicd to a single node: restarts orphaned
issued challenges, horizontal scaling had no shared state, and the per-IP
pressure counter was a fixed window — a client synchronized to the boundary
doubled its burst. The `Store` interface existed precisely so a Redis backend
could replace the implementation without touching the API layer; this ADR
takes that step (roadmap M1).

## Decision

1. **Same interface, new backend.** `store.NewRedis` implements the existing
   `Store` contract on Redis. Selection is explicit: `MYTHIC_STORE=redis`
   with `MYTHIC_REDIS_ADDR`; the in-memory store remains the zero-deploy
   default for single-node deployments.
2. **Single-use challenges via `GETDEL`.** The challenge record (challenge +
   issue timestamp, solve-time plausibility needs it) is stored as one JSON
   value with a TTL equal to the challenge TTL. `Take` is a single `GETDEL` —
   atomic fetch-and-delete, exactly the memory store's single-use semantics,
   with no Lua needed.
3. **Sliding-window counters via a sorted set.** Each request adds a member
   scored with the current millisecond; one Lua script prunes entries older
   than the window, returns the count including this request, and refreshes
   the key TTL. Both backends now share sliding-window semantics — the
   boundary-burst doubling is closed everywhere, not just on Redis.
4. **Fail closed, at startup and at runtime.** `NewRedis` pings the server
   and mythicd refuses to start when it is unreachable. At runtime a Redis
   outage fails requests — the same fail-closed posture the threat model
   already declares for a mythicd outage.
5. **Tests run against a real wire-compatible server.** A shared contract
   suite exercises both backends; Redis semantics are pinned with miniredis
   (pure Go, in-process) so CI needs no services.

## Consequences

- The store is the only state that becomes shared. **Signing keys do not**:
  each node keeps its own keystore (ADR-0006) and serves its own JWKS, so a
  token signed by node A is not verifiable against node B's JWKS — a
  red-team PoC confirmed exactly that (2026-09-29). Until a shared keystore
  (KMS/HSM, M5) lands, origins must fetch JWKS from the node that signed
  the token, or pin per-node keys. Multi-node token verification is NOT
  solved by this ADR.
- Restart no longer orphans issued challenges; the store outlives the
  process.
- Redis becomes an operational dependency for scaled deployments — its
  availability now bounds challenge issuance (fail closed by choice: a
  verifier that cannot decide should not issue tokens).
- The memory store changes window semantics (fixed → sliding) and counters
  saturate at `IPLimit+1` instead of growing with the flood — a red-team
  PoC showed an uncapped sliding window cost ~16 MB of heap and O(n²) CPU
  per million flooded hits per identity. Both backends share one contract
  suite, so the semantics cannot drift apart again.
