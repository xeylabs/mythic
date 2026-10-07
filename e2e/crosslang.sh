#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 xeylabs
#
# Cross-language end-to-end test.
#
# A live mythicd (Go) mints a decision token via the full client flow
# (challenge -> PoW solve -> verify, driven by the JS SDK), then the token
# is independently verified by three implementations:
#   1. Go   (server/xtoken)
#   2. Python (sdk/python)
#   3. JS   (sdk/js)
# All three must agree on dec/risk/sid. Run: ./e2e/crosslang.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
SRVPID=""
cleanup() {
  [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

export GOTMPDIR="${GOTMPDIR:-$HOME/tmp-gobuild}"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
GO="${GO:-$HOME/go/go1.25.1/bin/go}"
PORT="${MYTHIC_E2E_PORT:-18080}"
BASE="http://127.0.0.1:$PORT"

echo "==> building mythicd"
(cd "$ROOT/server" && "$GO" build -trimpath -o "$WORK/mythicd" ./cmd/mythicd)

echo "==> building JS SDK"
if command -v bun >/dev/null 2>&1; then
  (cd "$ROOT/sdk/js" && bun install --frozen-lockfile --silent && bun run build >/dev/null)
else
  (cd "$ROOT/sdk/js" && npm install --silent && npm run build --silent)
fi

echo "==> starting mythicd on $BASE"
MYTHIC_ADDR="127.0.0.1:$PORT" MYTHIC_KEY_FILE="$WORK/keys.json" \
  "$WORK/mythicd" >"$WORK/server.log" 2>&1 &
SRVPID=$!
for _ in $(seq 1 50); do
  if curl -sf "$BASE/v1/.well-known/jwks.json" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -sf "$BASE/v1/.well-known/jwks.json" >/dev/null \
  || { echo "FATAL: server did not become ready"; cat "$WORK/server.log"; exit 1; }

echo "==> JS SDK full client flow (challenge -> solve -> verify)"
export MYTHIC_E2E_BASE="$BASE"
TOKEN="$(node "$ROOT/e2e/get-token.mjs")"
[ -n "$TOKEN" ] || { echo "FATAL: empty token from client flow"; exit 1; }
echo "    token minted: ${TOKEN:0:24}..."

echo "==> verifying in Go / Python / JS"
(cd "$ROOT/e2e/verify-go" && "$GO" run . --base "$BASE" --token "$TOKEN") > "$WORK/go.json"
python3 "$ROOT/e2e/verify-token.py" --base "$BASE" --token "$TOKEN" > "$WORK/py.json"
node "$ROOT/e2e/verify-token.mjs" "$BASE" "$TOKEN" > "$WORK/js.json"

echo "==> checking cross-language agreement"
python3 - "$WORK/go.json" "$WORK/py.json" "$WORK/js.json" <<'EOF'
import json, sys
files = sys.argv[1:]
claims = [json.load(open(p)) for p in files]
for i, (f, c) in enumerate(zip(files, claims)):
    print(f"    [{f.split('/')[-1]}] dec={c['dec']} risk={c['risk']} sid={c['sid']}")
for k in ("dec", "risk", "sid"):
    vals = [c[k] for c in claims]
    assert all(v == vals[0] for v in vals), f"MISMATCH on {k}: {vals}"
print("OK: Go, Python and JS verifiers agree on the live-minted token")
EOF
