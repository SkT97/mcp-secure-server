# Trust boundaries

The authorization server signs the identity and tenant claims. The resource server validates that credential and applies record permissions. Tool arguments and user-supplied headers do not select the authenticated tenant.

The example protects a small read-only record service. It is designed to test wrong-recipient tokens, invalid signatures, expired credentials, missing scopes and access across two synthetic tenants.

The operator controls the trusted issuer, keys or JWKS location, resource URI and transport configuration. A token must not supply a new trusted key URL. When the keys come from a JWKS, a flood of unknown `kid` values is limited to one refresh per interval, and a JWKS that stays unreachable stops being trusted after `max_stale`. The JWKS host is resolved by the operating system, so a compromised DNS or a hostile host on the operator's network can still serve keys: pin the address to an issuer you control. Tokens and signing keys must not appear in logs or exported results.

A downstream API has its own authorization boundary. Forwarding an inbound token without the intended resource binding is not an acceptable substitute for obtaining a credential valid for that API.

The verifier requires `exp`, `iss`, `aud` and `sub`. The `nbf` and `iat` claims are optional, and a future value is rejected when present.

The exchange adapter checks the response shape and that the issued token differs from the subject token. It does not verify the issued token's signature, audience or subject, so the caller must validate it before use.

The local demo may use loopback HTTP and ephemeral credentials. An internet deployment requires TLS, deployment hardening, key rotation, operational controls and a reviewed authorization-server configuration.

This project does not claim to stop prompt injection, establish an operating-system sandbox, implement every OAuth client flow or certify a production deployment.
