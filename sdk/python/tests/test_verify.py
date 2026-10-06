# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 xeylabs

"""Tests for mythic.verify."""

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from mythic.verify import (
    TokenError,
    parse_public_key,
    verify_token,
)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    x = _b64url(pub.public_bytes_raw())
    return priv, x


def _claims(**over):
    c = {
        "v": 1,
        "sid": "test-site",
        "dec": "allow",
        "risk": 15,
        "kid": "k1",
        "jti": "j1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    c.update(over)
    return c


def _token(priv, claims):
    payload = json.dumps(claims).encode()
    sig = priv.sign(payload)
    return f"{_b64url(payload)}.{_b64url(sig)}"


def test_valid_token():
    priv, x = _keypair()
    pub = parse_public_key(x)
    claims = verify_token(pub, _token(priv, _claims()))
    assert claims.sid == "test-site"
    assert claims.dec == "allow"
    assert claims.risk == 15


def test_wrong_key():
    priv, _ = _keypair()
    _, x2 = _keypair()
    with pytest.raises(TokenError, match="signature"):
        verify_token(parse_public_key(x2), _token(priv, _claims()))


def test_expired():
    priv, x = _keypair()
    with pytest.raises(TokenError, match="expired"):
        verify_token(
            parse_public_key(x),
            _token(priv, _claims(exp=int(time.time()) - 10)),
        )


def test_malformed():
    _, x = _keypair()
    with pytest.raises(TokenError, match="malformed"):
        verify_token(parse_public_key(x), "not-a-token")


def test_bad_key():
    with pytest.raises(TokenError):
        parse_public_key("!!!")
    with pytest.raises(TokenError, match="32 bytes"):
        parse_public_key(_b64url(b"hi"))


def test_tampered_payload():
    priv, x = _keypair()
    token = _token(priv, _claims())
    payload_b64, sig_b64 = token.split(".")
    tampered = _b64url(json.dumps(_claims(risk=0)).encode())
    with pytest.raises(TokenError, match="signature"):
        verify_token(parse_public_key(x), f"{tampered}.{sig_b64}")
