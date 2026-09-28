# ADR-0001: Monorepo with Go server and TypeScript SDK

- **Status:** Accepted (2026-09-28)
- **Deciders:** xeylabs

## Context

XProtect needs a server (challenge issuance, risk engine, token signing) and
client SDKs (PoW solving, signal collection). Options: separate repositories
per component, or a single monorepo.

## Decision

One repository, `xeylabs/xprotect`, containing:

- `server/` — Go module `github.com/xeylabs/xprotect/server`
- `sdk/js/` — npm package `@xeylabs/xprotect`
- `dashboard/`, `docs/` as siblings

## Consequences

- Threat model, ADRs, and CI live next to every change that touches them —
  a repo where the trust model and the code diverge is a repo lying to itself.
- Atomic cross-component changes (wire format updates land with the SDK
  support in the same PR).
- Independent versioning is manual until we add release automation;
  `server/xtoken` is versioned with the server module (Go module paths make
  this the natural unit anyway).
- Go toolchain requires the server module to stay self-contained; the SDK is
  JavaScript-ecosystem only. Neither can accidentally reach across.
