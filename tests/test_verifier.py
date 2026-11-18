"""Unit tests for the RS256 JWT verifier (invalid token => None, never logs token)."""

from __future__ import annotations

import asyncio
import time

from conftest import ISSUER, RESOURCE, forge_hs256_token, generate_keypair, sign_token

from mcp_secure_server.auth import JwtTokenVerifier
from mcp_secure_server.config import ServerConfig


def _verifier(public_pem: str) -> JwtTokenVerifier:
    config = ServerConfig(
        issuer_url=ISSUER,
        resource_server_url=RESOURCE,
        rsa_public_key_pem=public_pem,
        allowed_hosts=("127.0.0.1",),
    )
    return JwtTokenVerifier(config)


def _verify(public_pem: str, token: str):
    return asyncio.run(_verifier(public_pem).verify_token(token))


def test_valid_token_yields_access_token(make_token, public_pem) -> None:
    result = _verify(public_pem, make_token())
    assert result is not None, "a valid RS256 token must verify"
    assert result.subject == "user-1"
    assert result.client_id == "client-app-1"
    assert result.scopes == ["records:read"]
    assert result.resource == RESOURCE
    assert result.expires_at is not None
    assert result.claims is not None
    assert result.claims["tenant_id"] == "north"


def test_valid_south_tenant_yields_access_token(make_token, public_pem) -> None:
    result = _verify(public_pem, make_token(overrides={"tenant_id": "south"}))
    assert result is not None
    assert result.claims is not None
    assert result.claims["tenant_id"] == "south"


def test_wrong_issuer_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(overrides={"iss": "https://evil.example.test"})) is None


def test_wrong_audience_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(overrides={"aud": "https://other.example.test"})) is None


def test_wrong_signature_rejected(make_token, public_pem) -> None:
    other_private, _ = generate_keypair()
    forged = sign_token(other_private)
    assert _verify(public_pem, forged) is None


def test_alg_none_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(algorithm="none")) is None


def test_alg_hs256_confusion_rejected(public_pem) -> None:
    # Classic confusion attack: HMAC-SHA256 with the RSA public key as secret.
    forged = forge_hs256_token(public_pem)
    assert _verify(public_pem, forged) is None


def test_expired_token_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(overrides={"exp": int(time.time()) - 300})) is None


def test_future_nbf_rejected(make_token, public_pem) -> None:
    now = int(time.time())
    token = make_token(overrides={"nbf": now + 600, "exp": now + 900})
    assert _verify(public_pem, token) is None


def test_missing_sub_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(omit=("sub",))) is None


def test_non_string_sub_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(overrides={"sub": 123})) is None


def test_missing_exp_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(omit=("exp",))) is None


def test_missing_iss_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(omit=("iss",))) is None


def test_missing_aud_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(omit=("aud",))) is None


def test_missing_azp_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(omit=("azp",))) is None


def test_missing_tenant_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(omit=("tenant_id",))) is None


def test_empty_tenant_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(overrides={"tenant_id": "   "})) is None


def test_oversized_tenant_rejected(make_token, public_pem) -> None:
    assert _verify(public_pem, make_token(overrides={"tenant_id": "t" * 65})) is None


def test_garbage_token_rejected(public_pem) -> None:
    assert _verify(public_pem, "not-a-jwt") is None
