"""No Bearer token may leave over unapproved cleartext transport."""

import asyncio

import pytest

from mcp_secure_server.client import client_session


@pytest.mark.parametrize(
    "url,demo",
    [
        ("http://remote.example.test/mcp", False),
        ("http://remote.example.test/mcp", True),
        ("http://127.0.0.1:1/mcp", False),
        ("https://user:password@example.test/mcp", False),
    ],
)
def test_rejects_before_network(url, demo, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("HTTP client was constructed before URL rejection")

    monkeypatch.setattr("mcp_secure_server.client.httpx2.AsyncClient", forbidden)

    async def scenario():
        with pytest.raises(ValueError):
            async with client_session(url, "opaque", demo_mode=demo):
                pytest.fail("session must not open")

    asyncio.run(scenario())
