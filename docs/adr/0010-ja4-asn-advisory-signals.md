# ADR-0010: JA4 TLS fingerprint + ASN as advisory risk signals

- **Status:** Proposed (2026-10-06)

## Context

The threat model names stealth browsers (Patchright, Camoufox) as the
actor class v0 cannot distinguish from honest clients. Server-observed
signals today are thin: solve-time plausibility (ADR-0008, delay-defeatable
by design) and per-identity pressure (ADR-0007). A stealth browser with a
patient native solver beats both — it looks exactly like a human who took
their time.

TLS fingerprinting (JA4) and network origin (ASN) are the two cheapest
server-observable signals that survive this: they describe *how the client
connected*, not what it claims about itself.

## Decision

1. **JA4 via trusted proxy header, never from the client.** mythicd
   typically runs behind a reverse proxy that terminates TLS. The proxy
   computes the JA4 fingerprint and injects it as `X-Mythic-JA4`. mythicd
   reads this header **only when `MYTHIC_TRUST_PROXY=true`** (ADR-0005's
   existing proxy-trust gate). A client-supplied `X-Mythic-JA4` with
   `TrustProxy=false` is ignored entirely — it is attacker-controlled
   input, not a signal.

2. **ASN via local MaxMind database.** Client IP → ASN lookup against a
   bundled or operator-supplied GeoLite2-ASN database
   (`MYTHIC_ASN_DB` path; absent = signal disabled, not an error).
   Datacenter/hosting ASNs score higher risk than residential/ISP ASNs;
   the mapping is a documented heuristic table, not a blocklist.

3. **Both signals are advisory with hard weight caps** (ADR-0004).
   JA4 contributes at most 15 points, ASN at most 10 points, to the
   0–100 risk score. Neither can single-handedly deny. A known-good
   browser JA4 earns a small discount (max −5); an unknown/anomalous
   JA4 adds risk. The caps exist because both signals are spoofable by
   a determined actor — they raise the cost of blending in, they do not
   prove humanity.

4. **No fingerprint allowlist as identity.** JA4 is not a credential.
   We never "trust" a fingerprint — we score its plausibility the same
   way we score solve times.

## Bypass analysis (written first, per repo rule)

- **Stealth browser with real Chrome TLS stack** → JA4 matches honest
  Chrome. Signal adds nothing. This is expected: JA4 catches *lazy*
  bots (curl, Python requests, Go http.Client), not dedicated stealth.
- **JA4 spoofing via custom TLS** (e.g., uTLS with Chrome parroting) →
  attacker picks any fingerprint they want. Cost: moderate engineering.
  Mitigated partially by combining with ASN (datacenter ASN + "Chrome"
  JA4 is itself suspicious) and solve-time.
- **Header injection without proxy trust** → ignored by design
  (TrustProxy=false drops it). With a compromised proxy, all bets are
  off — but then the attacker already controls the network path.
- **Residential proxy rotation** → fresh ASN per request, all residential.
  Defeats ASN scoring; per-identity pressure (ADR-0007) still bounds the
  economics per exit IP.

## Consequences

- Operators behind a TLS-terminating proxy get two new signals for free
  (config + header injection). Operators terminating TLS in mythicd
  directly get nothing until native ClientHello capture lands (future).
- The risk engine gains two capped inputs; existing calibrations are
  unaffected when the signals are absent (zero contribution, not an error).
- ASN database is an operational dependency (periodic refresh); absent DB
  degrades gracefully to "signal unavailable."
- Documentation must show the Caddy/nginx config snippet for JA4 header
  injection — otherwise nobody will wire it up.
