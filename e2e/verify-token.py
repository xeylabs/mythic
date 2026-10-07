# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 xeylabs

"""Verify a Mythic decision token with the Python SDK against a live mythicd JWKS.

Usage: python3 verify-token.py --base <url> --token <token>
Prints {"dec","risk","sid"} as JSON.
"""

import argparse
import json
import os
import sys
import urllib.request

# Fall back to the in-repo SDK when the package is not pip-installed
# (local runs). CI installs it via `pip install -e ./sdk/python`.
try:
    from mythic.verify import TokenError, parse_public_key, verify_token
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))
    from mythic.verify import TokenError, parse_public_key, verify_token


def get_jwks(base: str) -> dict:
    with urllib.request.urlopen(base + "/v1/.well-known/jwks.json", timeout=10) as r:
        return json.load(r)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--token", required=True)
    a = p.parse_args()

    jwks = get_jwks(a.base)
    claims = None
    for k in jwks.get("keys", []):
        try:
            claims = verify_token(parse_public_key(k["x"]), a.token)
            break
        except (TokenError, KeyError, ValueError):
            continue
    if claims is None:
        print("no JWKS key verified the token", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"dec": claims.dec, "risk": claims.risk, "sid": claims.sid}))


if __name__ == "__main__":
    main()
