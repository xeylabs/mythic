# Contributing to XProtect

Thanks for your interest — bypass reports, signal ideas, and code are all welcome.

## Development environment

- Go ≥ 1.24 (server)
- [bun](https://bun.sh) ≥ 1.4 (SDK JS/TS)

```bash
# Server
cd server
go vet ./... && go test ./... -race -count=1

# SDK
cd sdk/js
bun install
bun run typecheck && bun test && bun run build
```

## Ground rules

1. **Never trust the client.** Any change that lets client-side data become an
   authority over the decision will be rejected. Client signals are advisory
   inputs with bounded weight — see `docs/THREAT-MODEL.md` and ADR-0004.
2. **Write the bypass first.** If you add a detection signal, add a test that
   tries to defeat it. Signals without adversarial tests are decoration.
3. **Security issues go private.** See [SECURITY.md](SECURITY.md).
4. **Architecture decisions get ADRs.** If a change alters the trust model,
   wire format, storage model, or crypto, add `docs/adr/NNNN-*.md` first.
5. Conventional Commits (`feat(server): …`, `fix(sdk): …`) keep the changelog
   and releases mechanical.

## Pull request checklist

- [ ] `go vet ./... && go test ./... -race` green
- [ ] `bun run typecheck && bun test && bun run build` green (if SDK touched)
- [ ] `gofmt` clean
- [ ] New signals/thresholds covered by tests
- [ ] ADR added if the trust model, wire format, or crypto changed
