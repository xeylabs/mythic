## Summary

<!-- What does this PR do? One or two sentences. -->

## Changes

<!-- Bullet list of the meaningful changes. -->

## Checklist

- [ ] I have read and agree to [CLA.md](../../CLA.md)
- [ ] `go vet ./... && go test ./... -race` green (server)
- [ ] `bun run typecheck && bun test && bun run build` green (SDK)
- [ ] `gofmt` clean
- [ ] New signals/thresholds are covered by tests — including a test that tries to defeat them
- [ ] ADR added if the trust model, wire format, storage model, or crypto changed
- [ ] No change makes client-side data authoritative over a decision (ADR-0004)

## Related issues

<!-- Fixes #… -->
