"""HTTP-level tests over the ASGI app: RFC 9728 metadata, 401 challenge,
403 scope failure, 401 for invalid tokens, DNS-rebinding host rejection."""

from __future__ import annotations

import asyncio

import httpx2
import pytest
from conftest import ISSUER, RESOURCE, generate_keypair, sign_token
from mcp.types import LATEST_PROTOCOL_VERSION

from mcp_secure_server.config import ServerConfig
from mcp_secure_server.server import build_server, make_app

INIT_BODY = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": LATEST_PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "probe", "version": "0.0.0"},
    },
}
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


@pytest.fixture()
def app(public_pem):
    config = ServerConfig(
        issuer_url=ISSUER,
        resource_server_url=RESOURCE,
        rsa_public_key_pem=public_pem,
        allowed_hosts=("127.0.0.1", "127.0.0.1:*"),
    )
    return make_app(build_server(config), config)


@pytest.fixture()
def asgi_request(app):
    """Perform one ASGI request with an async httpx2 client."""

    async def _request(method: str, path: str, **kwargs):
        # Enter the Starlette lifespan (session-manager task group) for the
        # duration of this single ASGI request; the lifespan is not run by
        # httpx's ASGITransport.
        async with app.router.lifespan_context(app):
            transport = httpx2.ASGITransport(app=app)
            async with httpx2.AsyncClient(
                transport=transport, base_url="http://127.0.0.1"
            ) as client:
                return await client.request(method, path, **kwargs)

    def _run(method: str, path: str, **kwargs):
        return asyncio.run(_request(method, path, **kwargs))

    return _run


def test_rfc9728_metadata_served(asgi_request) -> None:
    response = asgi_request("GET", "/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    body = response.json()
    assert body["resource"].rstrip("/") == RESOURCE
    assert any(s.rstrip("/") == ISSUER for s in body["authorization_servers"])


def test_unauthenticated_request_gets_401_challenge(asgi_request) -> None:
    response = asgi_request("POST", "/mcp", json=INIT_BODY, headers=MCP_HEADERS)
    assert response.status_code == 401
    assert "www-authenticate" in response.headers
    assert "Bearer" in response.headers["www-authenticate"]


def test_invalid_signature_gets_401_not_403(asgi_request, rsa_keypair) -> None:
    other_private, _ = generate_keypair()
    forged = sign_token(other_private)
    response = asgi_request(
        "POST",
        "/mcp",
        json=INIT_BODY,
        headers={**MCP_HEADERS, "Authorization": f"Bearer {forged}"},
    )
    assert response.status_code == 401


def test_missing_tenant_claim_gets_401(asgi_request, make_token) -> None:
    token = make_token(omit=("tenant_id",))
    response = asgi_request(
        "POST",
        "/mcp",
        json=INIT_BODY,
        headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_wrong_scope_gets_403(asgi_request, make_token) -> None:
    token = make_token(overrides={"scope": "other:read"})
    response = asgi_request(
        "POST",
        "/mcp",
        json=INIT_BODY,
        headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_valid_token_gets_200(asgi_request, make_token) -> None:
    token = make_token()
    response = asgi_request(
        "POST",
        "/mcp",
        json=INIT_BODY,
        headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


def test_dns_rebinding_host_rejected(asgi_request, make_token) -> None:
    token = make_token()
    response = asgi_request(
        "POST",
        "/mcp",
        json=INIT_BODY,
        headers={**MCP_HEADERS, "Authorization": f"Bearer {token}", "Host": "evil.example"},
    )
    assert response.status_code == 421


def test_missing_credentials_challenge_names_the_scope_and_has_no_error(asgi_request) -> None:
    response = asgi_request("POST", "/mcp", json=INIT_BODY, headers=MCP_HEADERS)
    challenge = response.headers["www-authenticate"]
    assert response.status_code == 401
    assert 'scope="records:read"' in challenge
    assert 'resource_metadata="' in challenge
    assert "error=" not in challenge


def test_invalid_token_challenge_keeps_the_error_and_names_the_scope(
    asgi_request, make_token
) -> None:
    token = make_token(overrides={"aud": "https://other.example/"})
    response = asgi_request(
        "POST", "/mcp", json=INIT_BODY, headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"}
    )
    challenge = response.headers["www-authenticate"]
    assert response.status_code == 401
    assert 'error="invalid_token"' in challenge
    assert 'scope="records:read"' in challenge


def test_insufficient_scope_challenge_names_the_required_scope(asgi_request, make_token) -> None:
    token = make_token(overrides={"scope": "other:read"})
    response = asgi_request(
        "POST", "/mcp", json=INIT_BODY, headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"}
    )
    challenge = response.headers["www-authenticate"]
    assert response.status_code == 403
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="records:read"' in challenge
    assert 'resource_metadata="' in challenge
