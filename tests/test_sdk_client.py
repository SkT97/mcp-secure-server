"""Integration tests with the official MCP SDK Client over real loopback HTTP."""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest
import uvicorn
from conftest import ISSUER, RESOURCE
from mcp.shared.exceptions import MCPError

from mcp_secure_server.client import client_session
from mcp_secure_server.config import ServerConfig
from mcp_secure_server.data import NOT_FOUND
from mcp_secure_server.server import build_server, make_app


@pytest.fixture()
def running_server(rsa_keypair):
    public_pem = rsa_keypair[1]
    config = ServerConfig(
        issuer_url=ISSUER,
        resource_server_url=RESOURCE,
        rsa_public_key_pem=public_pem,
        allowed_hosts=("127.0.0.1:*",),
    )
    app = make_app(build_server(config), config)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.025)
    assert server.started, "uvicorn did not start"
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def _text(result) -> str:
    return result.content[0].text


def test_north_client_lists_and_gets_own_records(running_server, make_token) -> None:
    token = make_token(overrides={"tenant_id": "north"})

    async def scenario():
        async with client_session(running_server + "/mcp", token, demo_mode=True) as session:
            tools = await session.list_tools()
            by_name = {t.name: t for t in tools.tools}
            assert "records_list" in by_name and "records_get" in by_name
            # No tenant parameter: it comes only from the verified principal.
            assert set(by_name["records_get"].input_schema["properties"]) == {"record_id"}

            listing = await session.call_tool("records_list", {"limit": 3})
            records = listing.structured_content["result"]
            assert len(records) == 3
            assert all(r["tenant"] == "north" for r in records)

            own = await session.call_tool("records_get", {"record_id": "rec-north-1"})
            assert json.loads(_text(own))["id"] == "rec-north-1"

            cross = await session.call_tool("records_get", {"record_id": "rec-south-1"})
            unknown = await session.call_tool("records_get", {"record_id": "rec-north-999"})
            assert _text(cross) == NOT_FOUND
            assert _text(unknown) == NOT_FOUND
            assert _text(cross) == _text(unknown)

    asyncio.run(scenario())


def test_south_client_lists_and_gets_own_records(running_server, make_token) -> None:
    token = make_token(overrides={"tenant_id": "south"})

    async def scenario():
        async with client_session(running_server + "/mcp", token, demo_mode=True) as session:
            listing = await session.call_tool("records_list", {"limit": 50})
            records = listing.structured_content["result"]
            assert records
            assert all(r["tenant"] == "south" for r in records)
            own = await session.call_tool("records_get", {"record_id": "rec-south-2"})
            assert json.loads(_text(own))["id"] == "rec-south-2"
            cross = await session.call_tool("records_get", {"record_id": "rec-north-2"})
            assert _text(cross) == NOT_FOUND

    asyncio.run(scenario())


def test_limit_bounds_enforced_by_server(running_server, make_token) -> None:
    token = make_token(overrides={"tenant_id": "north"})

    async def scenario():
        async with client_session(running_server + "/mcp", token, demo_mode=True) as session:
            for bad_limit in (0, 51, 1000):
                result = await session.call_tool("records_list", {"limit": bad_limit})
                assert result.is_error, f"limit {bad_limit} must be rejected"
            ok = await session.call_tool("records_list", {"limit": 1})
            assert not ok.is_error

    asyncio.run(scenario())


def test_invalid_signature_rejected_by_server(running_server, rsa_keypair) -> None:
    from conftest import generate_keypair, sign_token

    other_private, _ = generate_keypair()
    forged = sign_token(other_private)

    async def scenario():
        with pytest.raises(BaseExceptionGroup) as captured:
            async with client_session(running_server + "/mcp", forged, demo_mode=True) as session:
                await session.list_tools()
        matching, remaining = captured.value.split(MCPError)
        assert matching is not None and remaining is None

    asyncio.run(scenario())


def test_client_session_closes_its_http_client(running_server, make_token, monkeypatch) -> None:
    """The SDK does not close a caller-provided client; client_session must."""
    import httpx2

    import mcp_secure_server.client as client_module

    assert client_module.httpx2 is httpx2
    instances: list[httpx2.AsyncClient] = []
    real_client = httpx2.AsyncClient

    class SpyClient(real_client):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)

    monkeypatch.setattr(httpx2, "AsyncClient", SpyClient)
    token = make_token(overrides={"tenant_id": "north"})

    async def scenario():
        async with client_session(running_server + "/mcp", token, demo_mode=True) as session:
            await session.list_tools()

    asyncio.run(scenario())
    assert len(instances) == 1
    assert instances[0].timeout.read == 300.0
    assert instances[0].timeout.connect == 30.0
    assert instances[0].is_closed, "client_session leaked its httpx client"


def test_loopback_demo_does_not_send_tokens_to_ambient_proxy(
    running_server, make_token, monkeypatch
):
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")

    async def scenario():
        async with client_session(running_server + "/mcp", make_token(), demo_mode=True) as session:
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == {"records_list", "records_get"}

    asyncio.run(scenario())
