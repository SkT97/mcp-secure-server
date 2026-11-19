"""Server configuration with strict URL/key validation.

Rules:
- issuer_url and resource_server_url must be HTTPS in normal mode.
- Demo mode keeps HTTPS valid and only adds loopback HTTP (127.0.0.1 /
  localhost / ::1); it never relaxes anything else.
- URLs must not carry userinfo, query strings or fragments.
- The RSA public key is parsed cryptographically: valid PEM, RSA only,
  at least 2048 bits; otherwise startup fails.
- No dev bypasses are enabled by default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
MIN_RSA_KEY_BITS = 2048
_SCOPE_TOKEN = re.compile(r"[!#-[\]-~]+")


class ConfigError(ValueError):
    """Raised when the server configuration is invalid."""


@dataclass(frozen=True)
class ServerConfig:
    """Immutable configuration for the secure MCP server."""

    issuer_url: str
    resource_server_url: str
    rsa_public_key_pem: str | None = None
    allowed_hosts: tuple[str, ...] = ("127.0.0.1",)
    required_scopes: tuple[str, ...] = ("records:read",)
    demo_mode: bool = False
    jwks_url: str | None = None

    def __post_init__(self) -> None:
        if not self.allowed_hosts or any(not h for h in self.allowed_hosts):
            raise ConfigError("allowed_hosts must be a non-empty list of hostnames")
        if not self.required_scopes or any(not s for s in self.required_scopes):
            raise ConfigError("required_scopes must be a non-empty list of scopes")
        if any(not _SCOPE_TOKEN.fullmatch(s) for s in self.required_scopes):
            raise ConfigError(
                "each scope must be an RFC 6749 scope token (no space, quote or backslash)"
            )
        self._validate_url("issuer_url", self.issuer_url)
        self._validate_url("resource_server_url", self.resource_server_url)
        if (self.rsa_public_key_pem is None) == (self.jwks_url is None):
            raise ConfigError("set exactly one of rsa_public_key_pem and jwks_url")
        if self.jwks_url is not None:
            self._validate_url("jwks_url", self.jwks_url)
        if self.rsa_public_key_pem is not None:
            self._validate_public_key(self.rsa_public_key_pem)

    def _validate_url(self, label: str, url: str) -> None:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            raise ConfigError(f"{label} must not include userinfo")
        if parsed.query:
            raise ConfigError(f"{label} must not include a query string")
        if parsed.fragment:
            raise ConfigError(f"{label} must not include a fragment")
        if not parsed.hostname:
            raise ConfigError(f"{label} must include a hostname")
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http":
            if not self.demo_mode:
                raise ConfigError(f"{label} must be https (got 'http')")
            if parsed.hostname not in LOOPBACK_HOSTS:
                raise ConfigError(f"{label} must be loopback http in demo mode")
            return
        raise ConfigError(f"{label} must use https (loopback http only in demo mode)")

    @staticmethod
    def _validate_public_key(pem: str) -> None:
        try:
            key = serialization.load_pem_public_key(pem.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise ConfigError("rsa_public_key_pem must be a valid PEM-encoded public key") from exc
        if not isinstance(key, RSAPublicKey):
            raise ConfigError("rsa_public_key_pem must be an RSA public key")
        if key.key_size < MIN_RSA_KEY_BITS:
            raise ConfigError(f"rsa_public_key_pem key must be at least {MIN_RSA_KEY_BITS} bits")
