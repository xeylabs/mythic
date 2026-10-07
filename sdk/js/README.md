# @xeylabs/mythic

Mythic client SDK — adaptive proof-of-work, advisory signal collection, and
signed decision tokens, for browsers and Node ≥ 18. Zero runtime dependencies.

```ts
import { MythicClient } from "@xeylabs/mythic";

const xp = new MythicClient({
  endpoint: "https://protect.example.com",
  siteKey: "my-site-key",
});

const { token, decision, risk } = await xp.getToken();
// attach `token` to the protected request; your origin verifies it locally
```

## Threading

`solve()` grinds on the calling thread. In browsers, run it inside a Web
Worker so the page stays responsive — the abort/progress callbacks exist
because the grind only checks between iterations:

```ts
// worker.ts
import { solve } from "@xeylabs/mythic";

self.onmessage = async (e) => {
  const solution = await solve(e.data.challenge);
  self.postMessage(solution);
};
```

A packaged worker ships with the roadmap M1 release.

## Signals are advisory, never decisive

`collectSignals()` reports honest environment hints (automation flags,
headless inconsistencies). They are forgeable by design — the server caps
their weight (see `docs/adr/0004-never-trust-the-client.md`). Faking them
only forfeits the discount honest reports earn.

## API

| Export | Purpose |
|---|---|
| `MythicClient` | `requestChallenge()`, `verify()`, `getToken()` |
| `MythicError` | Typed errors with API `code` and `status` |
| `solve(ch, opts)` | PoW grind (Web Crypto SHA-256) |
| `leadingZeroBits(sum)` | Difficulty check primitive |
| `collectSignals()` | Advisory hint collection |

## Development

```bash
bun install
bun run typecheck
bun test
bun run build
```

## Test coverage — read this before claiming browser support

`bun test` exercises the **real Web Worker code path** (`solveInWorker`)
through **Bun's Worker implementation**. That is a genuine worker thread,
but it is **not** Chromium, Firefox, or Safari.

**Explicitly not covered:** no test in this repository has ever run the
worker inside a real browser. There is no Playwright/headless-browser test.
As of 2026-10-08 the build environment cannot download browser binaries
(CDN blocked), so real-browser verification could not even be attempted
here — this is a known gap, not a passing grade.

If you add real-browser coverage later (Playwright + Chromium is the
intended tool), update this section and remove this paragraph instead of
letting the claim drift.

License: AGPL-3.0-or-later — the whole Mythic project ships under one
license; see [LICENSE](../../LICENSE) at the repository root.
