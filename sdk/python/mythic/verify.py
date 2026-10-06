# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 xeylabs

"""
Mythic origin verification helper for Python.

Verifies Mythic decision tokens on your origin backend, locally —
no dependency on the mythicd runtime.

    from mythic.verify import parse_public_key, verify_token

    pub = parse_public_key(jwk_x)  # from mythicd JWKS endpoint
    claims = verify_token(pub, token)
    if claims["dec"] != "allow":
        # handle challenge/deny per your policy
        ...

Token format: ``base64url(payload).base64url(signature)`` where payload
is JSON: {v, sid, dec, risk, kid, jti, iat, exp} and signature is
Ed25519 over the raw payload bytes.

Requires: cryptography (pip install cryptography)
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
except ImportError as e:
    raise ImportError(
        "mythic.verify requires the 'cryptography' package: pip install cryptography"
    ) from e


class TokenError(Exception):
    """Raised for any rejected token."""


@dataclass(frozen=True)
class TokenClaims:
    """Signed payload of a decision token."""

    v: int  # token format version
    sid: str  # site key the challenge was issued for
    dec: str  # allow | challenge | deny
    risk: int  # 0-100 risk score at decision time
    kid: str  # signing key id
    jti: str  # unique token id (revocation-ready)
    iat: int  # unix seconds
    exp: int  # unix seconds


def _b64url_decode(s: str, what: str) -> bytes:
    try:
        # Add padding for urlsafe_b64decode.
        padded = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as e:
        raise TokenError(f"bad {what} encoding") from e


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def parse_public_key(x: str) -> Ed25519PublicKey:
    """
    Decode a JWKS "x" value (base64url raw Ed25519 public key).
    """
    raw = _b64url_decode(x, "public key")
    if len(raw) != 32:
        raise TokenError(f"public key must be 32 bytes, got {len(raw)}")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as e:
        raise TokenError("invalid public key") from e


def verify_token(pub: Ed25519PublicKey, token: str) -> TokenClaims:
    """
    Verify a decision token's signature and expiry, returning its claims.

    Callers must still enforce site key and decision per their own policy —
    verification only proves mythicd signed these claims.
    """
    dot = token.find(".")
    if dot == -1:
        raise TokenError("malformed token")

    payload_part = token[:dot]
    sig_part = token[dot + 1 :]

    payload = _b64url_decode(payload_part, "payload")
    sig = _b64url_decode(sig_part, "signature")

    # Canonical encodings only: re-encoding must reproduce the input exactly.
    if _b64url_encode(payload) != payload_part or _b64url_encode(sig) != sig_part:
        raise TokenError("non-canonical encoding")

    try:
        pub.verify(sig, payload)
    except InvalidSignature as e:
        raise TokenError("signature mismatch") from e

    try:
        data: dict[str, Any] = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise TokenError("bad claims JSON") from e

    try:
        claims = TokenClaims(
            v=int(data["v"]),
            sid=str(data["sid"]),
            dec=str(data["dec"]),
            risk=int(data["risk"]),
            kid=str(data["kid"]),
            jti=str(data["jti"]),
            iat=int(data["iat"]),
            exp=int(data["exp"]),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise TokenError("bad claims") from e

    if claims.v != 1:
        raise TokenError(f"unsupported version {claims.v}")
    if int(time.time()) > claims.exp:
        raise TokenError("token expired")

    return claims
