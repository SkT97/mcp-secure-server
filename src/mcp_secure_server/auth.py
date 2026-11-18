"""JWT bearer-token verifier for the MCP SDK.

Implements the SDK ``TokenVerifier`` protocol: ``verify_token`` returns an
``AccessToken`` for a valid RS256 JWT and ``None`` for anything invalid.

Security properties:
- Only RS256 is accepted; the RSA public key is explicitly configured
  (no JWKS discovery, no key URLs from the token, no network calls).
- Required claims: exp, iss, aud, sub, plus a non-empty azp (client id)
  and a bounded non-empty signed ``tenant_id`` string.
- ``iss``/``aud`` are checked against the configured issuer and the
  resource server URL; ``nbf`` is verified when present.
- Invalid tokens return None and no token material is ever logged.
"""

from __future__ import annotations

import logging

import jwt
from mcp.server.auth.provider import AccessToken

from .config import ServerConfig

logger = logging.getLogger(__name__)

ALGORITHM = "RS256"
MAX_TENANT_ID_LENGTH = 64
REQUIRED_CLAIMS = ("exp", "iss", "aud", "sub")


class JwtTokenVerifier:
    """Verifies RS256 JWTs against an explicitly configured RSA public key."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return self._reject("malformed token")
        if header.get("alg") != ALGORITHM:
            return self._reject("unexpected algorithm")
        try:
            claims = jwt.decode(
                token,
                self._config.rsa_public_key_pem,
                algorithms=[ALGORITHM],
                audience=self._config.resource_server_url,
                issuer=self._config.issuer_url,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except jwt.PyJWTError:
            return self._reject("token failed validation")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            return self._reject("invalid subject claim")
        client_id = claims.get("azp")
        if not isinstance(client_id, str) or not client_id.strip():
            return self._reject("invalid client id claim")
        tenant_id = claims.get("tenant_id")
        if (
            not isinstance(tenant_id, str)
            or not tenant_id.strip()
            or len(tenant_id) > MAX_TENANT_ID_LENGTH
        ):
            return self._reject("invalid tenant claim")
        scope = claims.get("scope")
        scopes = scope.split() if isinstance(scope, str) else []
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=self._config.resource_server_url,
            subject=subject,
            claims=claims,
        )

    @staticmethod
    def _reject(reason: str) -> None:
        # Constant-string reasons only: never log the token or its claims.
        logger.warning("bearer token rejected: %s", reason)
        return None
