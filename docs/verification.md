# Verification

Checked locally on Windows on 16 November 2026, using Python 3.12.14 and the checked-in `uv.lock`.

```sh
uv sync --locked --group dev
uv run --locked python -m pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mcp-secure-server
```

The GitHub Actions workflow is prepared for Linux and Windows. No GitHub run is claimed before a repository is created and the workflow executes. Local verification is not a hosted CI result.

Local suite: **85 tests passed**. Ruff checks and formatting passed; the documented demo exited successfully. Markdown lint passed.

The Docker example also passed with Keycloak 26.8.2, two synthetic service-account tenants and a real downstream token exchange. The safe result is in [keycloak.json](../results/keycloak.json). The container was removed by the example.

Rerun on 19 November 2026 (Windows): 138 tests passed, Ruff checks and formatting passed, and the demo exited successfully. The Keycloak 26.8.2 example passed twice on the final code, once with a PEM key and once with `--jwks`. The JWKS run also refused tokens signed by an unknown key under an unknown `kid` and under the real `kid`. Its safe result is in [keycloak-jwks.json](../results/keycloak-jwks.json). Both containers were removed by the example. Markdown lint was not run in this rerun.

A proxy-environment regression verifies that loopback Bearer requests do not follow ambient proxy settings. Client and exchange transports ignore proxy environment configuration explicitly.
