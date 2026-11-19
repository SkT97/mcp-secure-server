# Standards and verification map

Sources checked 16 November 2026. This map defines the intended controls; implementation results must be attached after execution.

| Boundary | Reference | Check |
| --- | --- | --- |
| Token is intended for this resource | [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Wrong-audience token is refused |
| Protected resource discovery | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | Metadata and authentication challenge agree |
| Resource identity in authorization | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Explicit resource URI and token binding |
| OAuth threat model | [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Restrict privileges and credential exposure |
| Distinct downstream credential | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) | Exchange adapter checks target, timeout and errors |
| Tool contract and transport | [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28) | Official SDK client reaches the protected tools |
| Challenge scopes | [MCP authorization, scope selection](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1) | 401 and 403 challenges carry `scope`; a request without credentials gets no error code |
| Audience at two layers | [python-sdk advisory GHSA-w4fh-qvv9-3v23](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-w4fh-qvv9-3v23) | The verifier checks `aud` and returns it as `resource`; the SDK setting `validate_token_resource` is on |
| Signing keys and rotation | [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7515 section 4.1.4](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4) | `kid` selects among published RSA keys; unknown `kid` refreshes at most once per interval; failed refreshes fail closed |
| Cross-tenant access | Project policy | Both directions deny access to another tenant's records |
| Untrusted inputs | Project policy | Bounded arguments and structured output |
| Local identity provider | [Keycloak token exchange](https://www.keycloak.org/securing-apps/token-exchange) | Real issuer/JWKS integration is tested separately |

Token exchange is an architectural option for obtaining an appropriate downstream token; MCP does not require every integration to use RFC 8693. Implementing one adapter does not establish conformance with every OAuth flow.

Tenant claim names and record permissions are this example's application policy, not standardized MCP claims. Tool annotations are descriptive hints; authorization must be enforced independently.

## Current verified dependencies

The official Python SDK exposes MCPServer in v2. The package selected for the local implementation is mcp 2.3.0.

Keycloak 26.8.2 was checked against its [official release](https://github.com/keycloak/keycloak/releases/tag/26.8.2), published 5 November 2026. The local image was pulled by digest. The development server remains bound to loopback with synthetic data.

SDK versions before 1.30.0 and 2.2.0 accepted tokens issued for another resource server unless the verifier checked the audience. Upgrading does not enable the SDK check by itself: the setting `validate_token_resource` must be on and the verifier must return the audience. This server does both, so a token for another service is refused twice. The SDK builds its `WWW-Authenticate` header without the required scopes, so `challenge.py` rewrites that header.

A spec version, a pinned dependency and a passing test suite do not amount to a security certification.
