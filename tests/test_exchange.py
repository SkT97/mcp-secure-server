"""RFC 8693 token-exchange adapter tests.



Uses httpx.MockTransport and dynamically generated opaque dummy values

(no static credentials). The adapter is standalone: it is not wired into

the MCP record tools.

"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from urllib.parse import parse_qs

import httpx
import pytest

from mcp_secure_server.exchange import (
    ExchangeConfig,
    ExchangeConfigError,
    TokenExchangeError,
    exchange_token,
)


def _value(kind: str) -> str:
    """Dynamically generated opaque dummy value (no static secrets)."""

    return f"{kind}-{uuid.uuid4().hex}"


def _config(**overrides) -> ExchangeConfig:

    params = dict(
        token_endpoint=f"https://auth.example.test/{uuid.uuid4().hex}/token",
        client_id=_value("client"),
        client_secret=_value("secret"),
        audience=_value("audience"),
    )

    params.update(overrides)

    return ExchangeConfig(**params)


def _ok_body(access_token: str) -> dict:

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "expires_in": 60,
    }


def _run(handler, config: ExchangeConfig, subject_token: str) -> tuple[object, list[httpx.Request]]:

    seen: list[httpx.Request] = []

    def recording(request: httpx.Request):

        seen.append(request)

        return handler(request)

    return asyncio.run(
        exchange_token(config, subject_token, transport=httpx.MockTransport(recording))
    ), seen


def test_happy_path_returns_access_token_and_sends_rfc8693_fields() -> None:

    config = _config(scopes=("records:read",))

    subject_token = _value("subject")

    access_token = _value("access")

    result, seen = _run(
        lambda r: httpx.Response(200, json=_ok_body(access_token)), config, subject_token
    )

    assert result == access_token

    assert len(seen) == 1

    request = seen[0]

    assert request.method == "POST"

    assert str(request.url) == config.token_endpoint

    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")

    form = parse_qs(request.content.decode("ascii"), keep_blank_values=True)

    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]

    assert form["subject_token"] == [subject_token]

    assert form["subject_token_type"] == ["urn:ietf:params:oauth:token-type:access_token"]

    assert form["audience"] == [config.audience]

    assert form["scope"] == ["records:read"]

    scheme, credentials = request.headers["authorization"].split(" ", 1)

    assert scheme == "Basic"

    assert (
        base64.b64decode(credentials).decode("ascii")
        == f"{config.client_id}:{config.client_secret}"
    )


def test_no_scope_field_when_unconfigured() -> None:

    config = _config()

    subject_token = _value("subject")

    _, seen = _run(
        lambda r: httpx.Response(200, json=_ok_body(_value("access"))), config, subject_token
    )

    form = parse_qs(seen[0].content.decode("ascii"), keep_blank_values=True)

    assert "scope" not in form


def test_subject_token_cannot_control_endpoint_url() -> None:

    config = _config()

    hostile_subject = "http://evil.example.test/steal?token=abc"

    _, seen = _run(
        lambda r: httpx.Response(200, json=_ok_body(_value("access"))), config, hostile_subject
    )

    assert str(seen[0].url) == config.token_endpoint


def test_http_endpoint_rejected_outside_demo_mode() -> None:

    with pytest.raises(ExchangeConfigError):
        _config(token_endpoint="http://auth.example.test/token")


def test_http_loopback_endpoint_allowed_in_demo_mode() -> None:

    config = _config(token_endpoint="http://127.0.0.1:9000/token", demo_mode=True)

    subject_token = _value("subject")

    result, _ = _run(
        lambda r: httpx.Response(200, json=_ok_body(_value("access"))), config, subject_token
    )

    assert isinstance(result, str)


def test_non_loopback_http_endpoint_rejected_in_demo_mode() -> None:

    with pytest.raises(ExchangeConfigError):
        _config(token_endpoint="http://auth.example.test/token", demo_mode=True)


def test_ipv6_loopback_http_endpoint_allowed_in_demo_mode() -> None:
    config = _config(token_endpoint="http://[::1]:9000/token", demo_mode=True)

    subject_token = _value("subject")

    result, seen = _run(
        lambda r: httpx.Response(200, json=_ok_body(_value("access"))), config, subject_token
    )

    assert isinstance(result, str)
    assert seen[0].url.host == "::1"
    assert seen[0].url.port == 9000


def test_ipv6_loopback_http_endpoint_rejected_outside_demo_mode() -> None:
    with pytest.raises(ExchangeConfigError):
        _config(token_endpoint="http://[::1]:9000/token")


def test_ipv4_mapped_ipv6_loopback_endpoint_rejected_even_in_demo_mode() -> None:
    # Loopback in practice, but LOOPBACK_HOSTS is an exact hostname match, so
    # the IPv4-mapped form stays rejected. Pinned as the current behaviour.
    with pytest.raises(ExchangeConfigError):
        _config(token_endpoint="http://[::ffff:127.0.0.1]:9000/token", demo_mode=True)


def test_endpoint_userinfo_rejected() -> None:

    with pytest.raises(ExchangeConfigError):
        _config(token_endpoint=f"https://user:pw@auth.example.test/{uuid.uuid4().hex}/token")


def test_empty_client_credentials_rejected() -> None:

    with pytest.raises(ExchangeConfigError):
        _config(client_secret="")

    with pytest.raises(ExchangeConfigError):
        _config(audience="   ")


def test_timeout_raises_sanitized_error() -> None:

    config = _config(timeout_seconds=0.05)

    subject_token = _value("subject")

    # MockTransport does not enforce wall-clock timeouts, so the timeout is

    # simulated at the transport level, exactly as httpx would raise it.

    def timing_out(request: httpx.Request) -> httpx.Response:

        raise httpx.ReadTimeout("read timed out", request=request)

    with pytest.raises(TokenExchangeError) as excinfo:
        _run(timing_out, config, subject_token)

    message = str(excinfo.value)

    assert subject_token not in message

    assert config.client_secret not in message

    assert "read timed out" not in message


def test_network_error_raises_sanitized_error() -> None:

    config = _config()

    subject_token = _value("subject")

    def broken(request: httpx.Request) -> httpx.Response:

        raise httpx.ConnectError("connection failed")

    with pytest.raises(TokenExchangeError) as excinfo:
        _run(broken, config, subject_token)

    message = str(excinfo.value)

    assert subject_token not in message

    assert config.client_secret not in message

    assert "connection failed" not in message


def test_http_error_is_sanitized_and_body_not_leaked() -> None:

    config = _config()

    subject_token = _value("subject")

    leaked_body = json.dumps(
        {"error": "invalid", "echo": f"{config.client_secret}:{subject_token}"}
    )

    def failing(request: httpx.Request) -> httpx.Response:

        return httpx.Response(400, text=leaked_body)

    with pytest.raises(TokenExchangeError) as excinfo:
        _run(failing, config, subject_token)

    message = str(excinfo.value)

    assert config.client_secret not in message

    assert subject_token not in message

    assert leaked_body not in message


def test_redirect_is_not_followed() -> None:

    config = _config()

    subject_token = _value("subject")

    seen: list[httpx.Request] = []

    def redirecting(request: httpx.Request) -> httpx.Response:

        seen.append(request)

        return httpx.Response(302, headers={"location": "https://other.example.test/elsewhere"})

    with pytest.raises(TokenExchangeError):
        asyncio.run(
            exchange_token(
                config,
                subject_token,
                transport=httpx.MockTransport(redirecting),
            )
        )

    assert len(seen) == 1  # exactly one request, never a follow-up


def test_malformed_response_rejected() -> None:

    config = _config()

    subject_token = _value("subject")

    with pytest.raises(TokenExchangeError):
        _run(lambda r: httpx.Response(200, content=b"not json at all"), config, subject_token)

    with pytest.raises(TokenExchangeError):
        _run(lambda r: httpx.Response(200, json=["access_token"]), config, subject_token)


def test_missing_response_fields_rejected() -> None:

    config = _config()

    subject_token = _value("subject")

    for missing in ("access_token", "token_type", "issued_token_type"):
        body = _ok_body(_value("access"))

        body.pop(missing)

        with pytest.raises(TokenExchangeError):
            _run(lambda r, body=body: httpx.Response(200, json=body), config, subject_token)


def test_unsupported_token_type_rejected() -> None:

    config = _config()

    subject_token = _value("subject")

    body = _ok_body(_value("access"))

    body["token_type"] = "MAC"

    with pytest.raises(TokenExchangeError):
        _run(lambda r, body=body: httpx.Response(200, json=body), config, subject_token)


def test_unsupported_issued_token_type_rejected() -> None:

    config = _config()

    subject_token = _value("subject")

    body = _ok_body(_value("access"))

    body["issued_token_type"] = "urn:ietf:params:oauth:token-type:refresh_token"

    with pytest.raises(TokenExchangeError):
        _run(lambda r, body=body: httpx.Response(200, json=body), config, subject_token)


def test_empty_access_token_rejected() -> None:

    config = _config()

    subject_token = _value("subject")

    with pytest.raises(TokenExchangeError):
        _run(lambda r: httpx.Response(200, json=_ok_body("  ")), config, subject_token)


def test_unchanged_subject_token_rejected() -> None:

    config = _config()

    subject_token = _value("subject")

    with pytest.raises(TokenExchangeError) as excinfo:
        _run(lambda r: httpx.Response(200, json=_ok_body(subject_token)), config, subject_token)

    assert subject_token not in str(excinfo.value)


def test_missing_subject_token_rejected() -> None:

    config = _config()

    with pytest.raises(TokenExchangeError):
        asyncio.run(
            exchange_token(config, "", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        )


def test_basic_credentials_are_form_encoded_before_base64():

    from urllib.parse import unquote_plus

    config = _config(client_id="demo: +%Ã©", client_secret=_value("secret") + ": +%Ã©")

    _, seen = _run(
        lambda r: httpx.Response(200, json=_ok_body(_value("access"))), config, _value("subject")
    )

    encoded = seen[0].headers["authorization"].split(" ", 1)[1]

    client, secret = base64.b64decode(encoded).decode("ascii").split(":")

    assert unquote_plus(client) == config.client_id

    assert unquote_plus(secret) == config.client_secret


def test_exchange_does_not_inherit_proxy_configuration(monkeypatch):
    original = httpx.AsyncClient
    seen_policy = []

    class Client(original):
        def __init__(self, **kwargs):
            seen_policy.append(kwargs.get("trust_env"))
            super().__init__(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    _run(
        lambda r: httpx.Response(200, json=_ok_body(_value("access"))), _config(), _value("subject")
    )
    assert seen_policy == [False]
