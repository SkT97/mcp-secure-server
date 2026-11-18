"""Disposable Docker/Keycloak integration with synthetic service accounts.
Run from the repository: uv run python examples/keycloak_integration.py
Requires Docker. Binds loopback only; creates and removes its own container.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import threading
import time

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization

from mcp_secure_server.client import client_session
from mcp_secure_server.config import ServerConfig
from mcp_secure_server.data import NOT_FOUND
from mcp_secure_server.exchange import ExchangeConfig, exchange_token
from mcp_secure_server.server import build_server, make_app

IMAGE = "quay.io/keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0"
REALM = "synthetic-mcp"


def docker(*arguments, env=None):
    result = subprocess.run(
        ["docker", *arguments], capture_output=True, text=True, timeout=180, env=env, check=False
    )
    if result.returncode:
        raise RuntimeError("dedicated Docker operation failed")
    return result.stdout.strip()


def mapper(name, kind, config):
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": kind,
        "config": {"access.token.claim": "true", "id.token.claim": "false", **config},
    }


def client(name, secret, tenant, resource, scope=True):
    return {
        "clientId": name,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "secret": secret,
        "attributes": {"standard.token.exchange.enabled": "true"},
        "defaultClientScopes": ["records:read"] if scope else [],
        "optionalClientScopes": [],
        "protocolMappers": [
            mapper("resource", "oidc-audience-mapper", {"included.custom.audience": resource}),
            mapper(
                "downstream", "oidc-audience-mapper", {"included.client.audience": "downstream"}
            ),
            mapper(
                "tenant",
                "oidc-hardcoded-claim-mapper",
                {"claim.name": "tenant_id", "claim.value": tenant, "jsonType.label": "String"},
            ),
        ],
    }


async def verify(resource, issuer, key, tokens, wrong, missing, north_secret):
    for tenant, other in (("north", "south"), ("south", "north")):
        async with client_session(resource, tokens[tenant], demo_mode=True) as session:
            listing = await session.call_tool("records_list", {"limit": 5})
            records = listing.structured_content["result"]
            assert len(records) == 5 and all(row["tenant"] == tenant for row in records)
            own = await session.call_tool("records_get", {"record_id": f"rec-{tenant}-1"})
            assert not own.is_error
            cross = await session.call_tool("records_get", {"record_id": f"rec-{other}-1"})
            unknown = await session.call_tool("records_get", {"record_id": "rec-unknown-1"})
            assert cross.content[0].text == unknown.content[0].text == NOT_FOUND
            spoof = await session.call_tool("records_list", {"limit": 1, "tenant_id": other})
            assert spoof.is_error or all(
                row["tenant"] == tenant for row in spoof.structured_content["result"]
            )
    async with httpx.AsyncClient(timeout=10, trust_env=False) as http:
        response = await http.post(resource, json={})
        assert response.status_code == 401
        match = re.search(
            r'resource_metadata="([^"]+)"', response.headers.get("www-authenticate", "")
        )
        assert match
        metadata = await http.get(match.group(1))
        assert metadata.status_code == 200
        assert metadata.json()["resource"].rstrip("/") == resource
        for token, status in ((wrong, 401), (missing, 403)):
            response = await http.post(
                resource, json={}, headers={"Authorization": "Bearer " + token}
            )
            assert response.status_code == status
    exchanged = await exchange_token(
        ExchangeConfig(
            token_endpoint=issuer + "/protocol/openid-connect/token",
            client_id="demo-north",
            client_secret=north_secret,
            audience="downstream",
            demo_mode=True,
        ),
        tokens["north"],
    )
    claims = jwt.decode(exchanged, key, algorithms=["RS256"], issuer=issuer, audience="downstream")
    original = jwt.decode(
        tokens["north"], key, algorithms=["RS256"], issuer=issuer, audience=resource
    )
    audience = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    assert resource not in audience and claims["sub"] == original["sub"]
    assert claims["tenant_id"] == "north" and exchanged != tokens["north"]
    return {
        "checked_on": time.strftime("%Y-%m-%d"),
        "identity_provider": "Keycloak",
        "version": "26.8.2",
        "data": "synthetic service accounts",
        "real_signed_token_tenants": 2,
        "metadata_status": 200,
        "unauthenticated_status": 401,
        "wrong_audience_status": 401,
        "missing_scope_status": 403,
        "cross_tenant_denials": 2,
        "unknown_and_cross_tenant_indistinguishable": True,
        "tenant_argument_escalation_prevented": True,
        "token_exchange": "distinct signed token, downstream audience, subject preserved",
        "transport": "official MCP SDK over loopback Streamable HTTP",
    }


def main():
    logging.disable(logging.CRITICAL)
    name = "mcp-synthetic-" + secrets.token_hex(6)
    admin_secret = secrets.token_urlsafe(32)
    environment = dict(os.environ, KC_BOOTSTRAP_ADMIN_PASSWORD=admin_secret)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    resource = f"http://127.0.0.1:{sock.getsockname()[1]}/mcp"
    server = thread = None
    created = False
    try:
        docker(
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--memory",
            "768m",
            "--cpus",
            "2",
            "-p",
            "127.0.0.1::8080",
            "-e",
            "KC_BOOTSTRAP_ADMIN_USERNAME=demo-admin",
            "-e",
            "KC_BOOTSTRAP_ADMIN_PASSWORD",
            IMAGE,
            "start-dev",
            env=environment,
        )
        created = True
        port = docker("port", name, "8080/tcp").rsplit(":", 1)[1]
        base = f"http://127.0.0.1:{port}"
        with httpx.Client(timeout=10, trust_env=False) as api:
            deadline = time.monotonic() + 90
            while True:
                try:
                    ready = api.get(base + "/realms/master/.well-known/openid-configuration")
                    if ready.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError("dedicated identity provider did not become ready")
                time.sleep(0.5)
            response = api.post(
                base + "/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "demo-admin",
                    "password": admin_secret,
                },
            )
            response.raise_for_status()
            admin = {"Authorization": "Bearer " + response.json()["access_token"]}
            secrets_by_tenant = {
                tenant: secrets.token_urlsafe(32)
                for tenant in ("north", "south", "missing", "wrong")
            }
            clients = [
                client(
                    "demo-" + tenant,
                    secret,
                    "north" if tenant in {"missing", "wrong"} else tenant,
                    "https://wrong.example.test/mcp" if tenant == "wrong" else resource,
                    scope=tenant != "missing",
                )
                for tenant, secret in secrets_by_tenant.items()
            ]
            clients.append(
                {
                    "clientId": "downstream",
                    "enabled": True,
                    "protocol": "openid-connect",
                    "bearerOnly": True,
                }
            )
            response = api.post(
                base + "/admin/realms",
                headers=admin,
                json={
                    "realm": REALM,
                    "enabled": True,
                    "sslRequired": "none",
                    "clientScopes": [
                        {
                            "name": "records:read",
                            "protocol": "openid-connect",
                            "attributes": {"include.in.token.scope": "true"},
                        }
                    ],
                    "clients": clients,
                },
            )
            response.raise_for_status()
            issuer = base + "/realms/" + REALM
            tokens = {}
            for tenant, secret in secrets_by_tenant.items():
                response = api.post(
                    issuer + "/protocol/openid-connect/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": "demo-" + tenant,
                        "client_secret": secret,
                    },
                )
                response.raise_for_status()
                tokens[tenant] = response.json()["access_token"]
            response = api.get(issuer + "/protocol/openid-connect/certs")
            response.raise_for_status()
            kid = jwt.get_unverified_header(tokens["north"])["kid"]
            key = jwt.PyJWK.from_dict(
                next(item for item in response.json()["keys"] if item["kid"] == kid)
            ).key
            pem = key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        config = ServerConfig(
            issuer_url=issuer,
            resource_server_url=resource,
            rsa_public_key_pem=pem,
            allowed_hosts=("127.0.0.1:*",),
            demo_mode=True,
        )
        server = uvicorn.Server(
            uvicorn.Config(make_app(build_server(config), config), log_level="error")
        )
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        for _ in range(200):
            if server.started:
                break
            time.sleep(0.025)
        if not server.started:
            raise RuntimeError("MCP server did not become ready")
        result = asyncio.run(
            verify(
                resource,
                issuer,
                key,
                tokens,
                tokens["wrong"],
                tokens["missing"],
                secrets_by_tenant["north"],
            )
        )
        print(json.dumps(result, sort_keys=True))
    finally:
        if server:
            server.should_exit = True
        if thread:
            thread.join(timeout=10)
        sock.close()
        if created:
            docker("stop", name)


if __name__ == "__main__":
    main()
