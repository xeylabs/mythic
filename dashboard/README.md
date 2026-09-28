# Dashboard — admin console (planned)

Not started. See [docs/ROADMAP.md](../docs/ROADMAP.md) milestone **M5**.

Planned scope:

- Traffic overview: request volume, challenge pass rate, risk-score distribution
- Per-site key management and per-route step-up policy
- Rule visibility: which signals fired and why (scores are already deterministic — the dashboard makes them auditable)
- Signing key rotation workflow

Stack: React + TypeScript + Vite, consuming the mythicd admin API (to be
designed in an ADR before implementation).
