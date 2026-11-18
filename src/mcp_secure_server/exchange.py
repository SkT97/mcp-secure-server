"""RFC 8693 token-exchange adapter (confidential client, httpx 0.28).

A small, standalone adapter: it exchanges a *previously validated* subject
access token for an audience-specific access token from one fixed,
operator-configured token endpoint. It is intentionally NOT a full OAuth
client implementation, and it is not required by (or wired into) the MCP
record tools.

Security properties:
- Endpoint, client id, secret, audience and scopes are fixed in
  ``ExchangeConfig`` at startup; no token or response value can steer the
  request URL.
- HTTPS is required for the endpoint, except loopback HTTP in explicit
  demo mode.
- Redirects are never followed; connect/read timeouts are finite.
- The caller receives only the new access token. Error messages are
  constant strings: credentials, tokens and response bodies are never
  included.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from urllib.parse import quote_plus, urlparse

import httpx

from .config import LOOPBACK_HOSTS

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
ISSUED_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
DEFAULT_TIMEOUT_SECONDS = 10.0


class ExchangeConfigError(ValueError):
    """Raised when the token-exchange configuration is invalid."""


class TokenExchangeError(RuntimeError):
    """Raised when a token exchange fails; message never leaks secrets."""


@dataclass(frozen=True)
class ExchangeConfig:
    """Immutable configuration for the token-exchange adapter."""

    token_endpoint: str
    client_id: str
    client_secret: str
    audience: str
    scopes: tuple[str, ...] = ()
    demo_mode: bool = False
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        self._validate_endpoint()
        for label, value in (
            ("client_id", self.client_id),
            ("client_secret", self.client_secret),
            ("audience", self.audience),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ExchangeConfigError(f"{label} must be a non-empty string")
        if any(not isinstance(s, str) or not s.strip() for s in self.scopes):
            raise ExchangeConfigError("scopes must be non-empty strings")
        timeout = self.timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ExchangeConfigError("timeout_seconds must be a positive finite number")

    def _validate_endpoint(self) -> None:
        parsed = urlparse(self.token_endpoint)
        if parsed.username or parsed.password:
            raise ExchangeConfigError("token_endpoint must not include userinfo")
        if parsed.query:
            raise ExchangeConfigError("token_endpoint must not include a query string")
        if parsed.fragment:
            raise ExchangeConfigError("token_endpoint must not include a fragment")
        if not parsed.hostname or not parsed.path:
            raise ExchangeConfigError("token_endpoint must be an absolute URL with a path")
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http":
            if not self.demo_mode:
                raise ExchangeConfigError(
                    "token_endpoint must be https (loopback http only in demo mode)"
                )
            if parsed.hostname not in LOOPBACK_HOSTS:
                raise ExchangeConfigError("token_endpoint must be loopback http in demo mode")
            return
        raise ExchangeConfigError("token_endpoint must use https (loopback http only in demo mode)")


async def exchange_token(
    config: ExchangeConfig,
    subject_token: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """Exchange ``subject_token`` for an access token and return only that.

    The subject token is supplied by the caller, which is responsible for
    having validated it before the exchange. ``transport`` exists for tests
    (httpx.MockTransport); production callers leave it unset.
    """
    if not isinstance(subject_token, str) or not subject_token.strip():
        raise TokenExchangeError("subject token is missing")

    data: dict[str, str] = {
        "grant_type": GRANT_TYPE,
        "subject_token": subject_token,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "audience": config.audience,
    }
    if config.scopes:
        data["scope"] = " ".join(config.scopes)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.timeout_seconds),
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        try:
            response = await client.post(
                config.token_endpoint,
                data=data,
                auth=httpx.BasicAuth(
                    quote_plus(config.client_id, safe=""), quote_plus(config.client_secret, safe="")
                ),
            )
        except httpx.TimeoutException:
            raise TokenExchangeError("token exchange timed out") from None
        except httpx.HTTPError:
            raise TokenExchangeError("token exchange failed (network error)") from None

    if response.is_redirect:
        raise TokenExchangeError("token exchange redirects are not followed")
    if not response.is_success:
        raise TokenExchangeError("token endpoint returned an error status")
    try:
        body = response.json()
    except ValueError:
        raise TokenExchangeError("token response is not valid JSON") from None
    if not isinstance(body, dict):
        raise TokenExchangeError("token response must be a JSON object")
    token_type = body.get("token_type")
    # RFC 6749 section 7: token type values compare case-insensitively.
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise TokenExchangeError("token response has an unsupported token type")
    if body.get("issued_token_type") != ISSUED_ACCESS_TOKEN_TYPE:
        raise TokenExchangeError("token response did not issue an access token")
    access_token = body.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise TokenExchangeError("token response has no usable access token")
    if access_token == subject_token:
        raise TokenExchangeError("token endpoint returned the subject token unchanged")
    return access_token
