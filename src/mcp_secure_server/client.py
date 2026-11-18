"""Small helper: official MCP SDK client with static Bearer auth."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


class BearerAuth(httpx2.Auth):
    """Adds a static Authorization: Bearer header to every request."""

    def __init__(self, token: str) -> None:
        super().__init__()
        self._token = token

    def auth_flow(self, request: httpx2.Request):
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


@asynccontextmanager
async def client_session(
    url: str, token: str, *, demo_mode: bool = False
) -> AsyncIterator[ClientSession]:
    """Yield an initialized official MCP ClientSession over Streamable HTTP."""
    parsed = urlsplit(url)
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
    ):
        raise ValueError("invalid resource URL")
    if parsed.scheme != "https" and not (
        demo_mode
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        raise ValueError("HTTPS required; loopback HTTP requires explicit demo_mode")
    # The SDK does not close a caller-provided http client, so its lifecycle
    # is managed here: it is always closed when the session ends.
    async with httpx2.AsyncClient(
        auth=BearerAuth(token), timeout=httpx2.Timeout(30.0, read=300.0), trust_env=False
    ) as http_client:
        async with streamable_http_client(url, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
