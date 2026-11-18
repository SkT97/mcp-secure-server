"""Configuration validation: HTTPS by default, demo mode adds loopback HTTP only.

All key-validation tests use real ephemeral keys (never dummy PEM strings).
"""

from __future__ import annotations

import pytest
from conftest import ISSUER, RESOURCE
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from mcp_secure_server.config import ConfigError, ServerConfig


def _config(public_key_pem: str, **overrides):
    params = dict(
        issuer_url=ISSUER,
        resource_server_url=RESOURCE,
        rsa_public_key_pem=public_key_pem,
        allowed_hosts=("127.0.0.1",),
    )
    params.update(overrides)
    return ServerConfig(**params)


def _public_pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def test_valid_https_config(public_pem: str) -> None:
    _config(public_pem)  # must not raise


def test_non_https_issuer_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config(public_pem, issuer_url="http://issuer.example.test")


def test_non_https_resource_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config(public_pem, resource_server_url="http://mcp.example.test")


def test_demo_mode_still_allows_https(public_pem: str) -> None:
    # Regression: demo mode must not require both URLs to be HTTP; normal
    # HTTPS must remain valid, demo mode only adds the loopback HTTP option.
    _config(public_pem, demo_mode=True)  # must not raise


def test_demo_mode_rejects_non_loopback_http(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config(public_pem, demo_mode=True, issuer_url="http://evil.example.test")


def test_demo_mode_allows_loopback_http(public_pem: str) -> None:
    _config(
        public_pem,
        demo_mode=True,
        issuer_url="http://127.0.0.1:9090",
        resource_server_url="http://127.0.0.1:9091",
    )


def test_userinfo_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config(public_pem, issuer_url="https://user:secret@issuer.example.test")


def test_fragment_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config(public_pem, resource_server_url="https://mcp.example.test#anchor")


def test_query_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config(public_pem, issuer_url="https://issuer.example.test/?probe=1")


def test_empty_allowed_hosts_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config(public_pem, allowed_hosts=())


def test_empty_required_scopes_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config(public_pem, required_scopes=())


def test_non_pem_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config("not a pem")


def test_malformed_pem_rejected(public_pem: str) -> None:
    with pytest.raises(ConfigError):
        _config("-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n")


def test_non_rsa_public_key_rejected(public_pem: str) -> None:
    ec_public = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(ConfigError):
        _config(_public_pem(ec_public))


def test_weak_public_key_rejected(public_pem: str) -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ConfigError):
        _config(_public_pem(weak.public_key()))
