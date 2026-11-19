"""Assemble the official mcp 2.x MCPServer with JWT auth and tenant tools."""

from __future__ import annotations

from typing import Annotated

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl, Field
from starlette.applications import Starlette

from .auth import JwtTokenVerifier
from .challenge import BearerChallengeScopes
from .config import ServerConfig
from .data import MAX_LIMIT, MIN_LIMIT, RecordStore


def build_server(config: ServerConfig) -> MCPServer:
    """Build the MCPServer with signed-JWT bearer auth and tenant tools."""
    store = RecordStore()
    server = MCPServer(
        name="mcp-secure-server",
        description=(
            "Reference MCP resource server: RS256 JWT bearer auth with "
            "tenant-isolated synthetic records."
        ),
        token_verifier=JwtTokenVerifier(config),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(config.issuer_url),
            resource_server_url=AnyHttpUrl(config.resource_server_url),
            required_scopes=list(config.required_scopes),
            validate_token_resource=True,
        ),
    )

    def _verified_tenant() -> str:
        # Tenant comes exclusively from the verified principal (SDK context),
        # never from tool arguments or headers.
        access_token = get_access_token()
        tenant_id = (access_token.claims or {}).get("tenant_id") if access_token else None
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise RuntimeError("authenticated tenant unavailable")
        return tenant_id

    @server.tool(
        description=(
            f"List up to {MAX_LIMIT} synthetic records of the authenticated "
            f"tenant (limit {MIN_LIMIT}..{MAX_LIMIT})."
        )
    )
    async def records_list(
        limit: Annotated[int, Field(ge=MIN_LIMIT, le=MAX_LIMIT)] = 5,
    ) -> list[dict[str, str]]:
        return store.list_for_tenant(_verified_tenant(), limit)

    @server.tool(description="Fetch one synthetic record of the authenticated tenant by id.")
    async def records_get(
        record_id: Annotated[str, Field(min_length=1, max_length=32)],
    ) -> str | dict[str, str]:
        return store.get_for_tenant(_verified_tenant(), record_id)

    return server


def make_app(server: MCPServer, config: ServerConfig) -> Starlette:
    """Streamable-HTTP ASGI app with DNS-rebinding protection enabled."""
    app = server.streamable_http_app(
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(config.allowed_hosts),
        )
    )
    app.add_middleware(BearerChallengeScopes, scopes=config.required_scopes)
    return app
