# ADR-0007: Per-IP pressure is keyed on IPv6 /64 aggregation

- **Status:** Accepted (2026-09-29)

## Context

A red-team session (2026-09-29) against a live mythicd showed the per-IP rate
limiter and risk-engine pressure signal are keyed on the exact address —
/128 for IPv6. An attacker holding a single IPv6 /64 (the standard allocation
for a home line, a VPS, or a tunnel) controls 2⁶⁴ distinct addresses. The PoC
drove 5,000 requests from one /64 and observed 5,000 distinct limiter
identities: zero requests rate-limited, and every request looked like a
brand-new visitor to the pressure signal — the same failure class as the
X-Forwarded-For bypass (ADR-0005), obtained without any header at all.

## Decision

The limiter and pressure counters are keyed on an aggregated network
identity:

- **IPv4** (including IPv4-mapped forms): the address as-is (/32).
- **IPv6**: the /64 prefix — the smallest unit ISPs delegate to a single
  subscriber line.

The full address is still used for access logs; only the counter key is
aggregated.

## Consequences

- One /64 can no longer mint unlimited limiter identities; the economics of
  `MYTHIC_IP_LIMIT` survive IPv6.
- Many honest visitors behind a large carrier-grade NAT or a /64 shared by a
  campus share one counter. That is the same trade every per-IP limiter makes
  for IPv4 NAT; the limit is configurable per deployment.
- A /48-holding adversary still gets 65,536 identities — aggregation narrows
  the space, it does not close it. Distributed attacks remain the honest gap
  (threat model; M1/M3 network fingerprints).
