"""Bearer challenges that follow the MCP authorization scope guidance.

The official SDK builds the ``WWW-Authenticate`` header of a 401 or 403 without
the scopes a client should request, and names an error even when the request
carried no credentials. MCP authorization (2026-07-28, Scope Selection
Strategy) says servers SHOULD include ``scope`` in the challenge, and RFC 6750
section 3.1 says a request without authentication information SHOULD NOT get
an error code. This middleware rewrites only that header, and only when it is exactly
the form the SDK emits (one Bearer challenge of quoted parameters without escapes);
any other header is passed through unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

_PARAMETER = re.compile(r'(\w+)="([^"\\]*)"')
# Exactly the form the SDK emits: one Bearer challenge of quoted parameters without escapes.
_CHALLENGE = re.compile(r'(?i:bearer) \w+="[^"\\]*"(?:, \w+="[^"\\]*")*')
_ORDER = ("error", "error_description", "scope", "resource_metadata")


def challenge_with_scopes(value: str, scopes: Sequence[str], had_credentials: bool) -> str:
    """Return the Bearer challenge with ``scope`` added; drop the error if none was sent."""
    if not _CHALLENGE.fullmatch(value):
        return value
    parameters = dict(_PARAMETER.findall(value))
    if not had_credentials:
        parameters.pop("error", None)
        parameters.pop("error_description", None)
    parameters["scope"] = " ".join(scopes)
    keys = [k for k in _ORDER if k in parameters] + [k for k in parameters if k not in _ORDER]
    return "Bearer " + ", ".join(f'{key}="{parameters[key]}"' for key in keys)


class BearerChallengeScopes:
    """ASGI middleware applying :func:`challenge_with_scopes` to 401 and 403 responses."""

    def __init__(self, app, scopes: Sequence[str]) -> None:
        self.app = app
        self.scopes = tuple(scopes)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        had_credentials = any(name == b"authorization" for name, _ in scope["headers"])

        async def rewrite(message) -> None:
            if message["type"] == "http.response.start" and message["status"] in (401, 403):
                message = {
                    **message,
                    "headers": [
                        (
                            name,
                            challenge_with_scopes(
                                value.decode("latin-1"), self.scopes, had_credentials
                            ).encode("latin-1"),
                        )
                        if name.lower() == b"www-authenticate"
                        else (name, value)
                        for name, value in message["headers"]
                    ],
                }
            await send(message)

        await self.app(scope, receive, rewrite)
