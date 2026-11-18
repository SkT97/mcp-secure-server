"""Local demo: ephemeral in-memory keys, loopback HTTP, safe summary only.

Run: python -m mcp_secure_server.demo

No external model or credentials are used. The RSA keypair is generated in
memory at startup and neither keys nor tokens are ever printed.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import threading
import time

import httpx2
import jwt as pyjwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .client import client_session
from .config import ServerConfig
from .server import build_server, make_app


def _ephemeral_keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_pem, public_pem


def build_demo_config(port: int = 9091) -> tuple[ServerConfig, str]:
    """Demo config (loopback HTTP, explicit demo mode) + matching private key."""
    private_pem, public_pem = _ephemeral_keypair()
    config = ServerConfig(
        issuer_url="http://127.0.0.1:9090",
        resource_server_url=f"http://127.0.0.1:{port}",
        rsa_public_key_pem=public_pem,
        allowed_hosts=("127.0.0.1:*",),
        demo_mode=True,
    )
    return config, private_pem


def issue_demo_token(config: ServerConfig, private_pem: str, tenant_id: str) -> str:
    now = int(time.time())
    payload = {
        "iss": config.issuer_url,
        "aud": config.resource_server_url,
        "sub": f"demo-user-{tenant_id}",
        "azp": "demo-client",
        "scope": " ".join(config.required_scopes),
        "tenant_id": tenant_id,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    return pyjwt.encode(payload, private_pem, algorithm="RS256")


def _start_server(app: object, sock: socket.socket) -> tuple[uvicorn.Server, int]:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.025)
    if not server.started:
        raise RuntimeError("demo server did not start")
    return server, server.servers[0].sockets[0].getsockname()[1]


async def _scenario(base_url: str, config: ServerConfig, private_pem: str) -> list[str]:
    lines: list[str] = []
    token = issue_demo_token(config, private_pem, "north")
    async with client_session(base_url + "/mcp", token, demo_mode=True) as session:
        listing = await session.call_tool("records_list", {"limit": 5})
        records = listing.structured_content["result"]
        tenants = sorted({r["tenant"] for r in records})
        lines.append(f"records_list(limit=5): {len(records)} records, tenants {tenants}")
        own = await session.call_tool("records_get", {"record_id": "rec-north-1"})
        lines.append(f"records_get(rec-north-1): {own.content[0].text[:40]}...")
        cross = await session.call_tool("records_get", {"record_id": "rec-south-1"})
        blocked = "not found" in cross.content[0].text.lower()
        if not blocked:
            raise RuntimeError("cross-tenant access was not denied")
        verdict = "blocked (not found)"
        lines.append(f"cross-tenant records_get(rec-south-1): {verdict}")
    return lines


def main() -> int:
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.WARNING)
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    config, private_pem = build_demo_config(sock.getsockname()[1])
    app = make_app(build_server(config), config)
    server, port = _start_server(app, sock)
    base_url = f"http://127.0.0.1:{port}"
    try:
        http = httpx2.Client(base_url=base_url, timeout=10, trust_env=False)
        try:
            challenge = http.post(
                "/mcp",
                json={},
                headers={"Accept": "application/json, text/event-stream"},
            )
            challenge_url = re.search(
                r'resource_metadata="([^" ]+)"', challenge.headers.get("www-authenticate", "")
            )
            if challenge.status_code != 401 or challenge_url is None:
                raise RuntimeError("missing protected resource challenge")
            meta = http.get(challenge_url.group(1))
            resource = meta.json().get("resource")
            if meta.status_code != 200 or str(resource).rstrip("/") != base_url:
                raise RuntimeError("resource metadata does not match the bound server")
        finally:
            http.close()
        print("mcp-secure-server demo (loopback, ephemeral in-memory keys)")
        print(f"- RFC 9728 metadata: HTTP {meta.status_code} (resource {resource})")
        print(
            f"- unauthenticated request: HTTP {challenge.status_code}, "
            f"WWW-Authenticate present: {'www-authenticate' in challenge.headers}"
        )
        for line in asyncio.run(_scenario(base_url, config, private_pem)):
            print(f"- {line}")
        print("demo ok")
        return 0
    finally:
        server.should_exit = True
        for _ in range(200):
            if not server.started or not any(s.is_serving() for s in server.servers):
                break
            time.sleep(0.025)
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
