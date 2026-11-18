from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://issuer.example.test"
RESOURCE = "https://mcp.example.test"
ALGORITHM = "RS256"


def generate_keypair() -> tuple[str, str]:
    """Generate an ephemeral in-memory RSA keypair (2048 bit), PEM-encoded."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_pem, public_pem


def base_payload() -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": "user-1",
        "azp": "client-app-1",
        "scope": "records:read",
        "tenant_id": "north",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }


def sign_token(
    private_pem: str,
    *,
    overrides: dict[str, Any] | None = None,
    omit: tuple[str, ...] = (),
    algorithm: str = ALGORITHM,
    key: str | None = None,
) -> str:
    """Sign a valid tenant token, applying optional claim overrides/removals."""
    payload: dict[str, Any] = base_payload()
    for claim in omit:
        payload.pop(claim, None)
    if overrides:
        payload.update(overrides)
    if algorithm == "none":
        return pyjwt.encode(payload, None, algorithm="none")
    return pyjwt.encode(payload, key or private_pem, algorithm=algorithm)


def forge_hs256_token(public_pem: str) -> str:
    """Forge an HS256 JWT signed with the RSA public key as HMAC secret.

    This is the algorithm-confusion attack; PyJWT itself refuses to perform
    it, so the token is assembled by hand.
    """

    def b64(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("ascii"))
    payload = b64(json.dumps(base_payload()).encode("ascii"))
    signing_input = header + b"." + payload
    signature = b64(hmac.new(public_pem.encode("ascii"), signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + signature).decode("ascii")


@pytest.fixture()
def rsa_keypair() -> tuple[str, str]:
    return generate_keypair()


@pytest.fixture()
def private_pem(rsa_keypair: tuple[str, str]) -> str:
    return rsa_keypair[0]


@pytest.fixture()
def public_pem(rsa_keypair: tuple[str, str]) -> str:
    return rsa_keypair[1]


@pytest.fixture()
def make_token(private_pem: str):
    def _make(**kwargs: Any) -> str:
        return sign_token(private_pem, **kwargs)

    return _make
