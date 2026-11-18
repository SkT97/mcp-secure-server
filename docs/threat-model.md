# Trust boundaries

The authorization server signs the identity and tenant claims. The resource server validates that credential and applies record permissions. Tool arguments and user-supplied headers do not select the authenticated tenant.

The example protects a small read-only record service. It is designed to test wrong-recipient tokens, invalid signatures, expired credentials, missing scopes and access across two synthetic tenants.

The operator controls the trusted issuer, keys or JWKS location, resource URI and transport configuration. A token must not supply a new trusted key URL. Tokens and signing keys must not appear in logs or exported results.

A downstream API has its own authorization boundary. Forwarding an inbound token without the intended resource binding is not an acceptable substitute for obtaining a credential valid for that API.

The local demo may use loopback HTTP and ephemeral credentials. An internet deployment requires TLS, deployment hardening, key rotation, operational controls and a reviewed authorization-server configuration.

This project does not claim to stop prompt injection, establish an operating-system sandbox, implement every OAuth client flow or certify a production deployment.
