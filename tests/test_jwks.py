"""JWKS key source: kid lookup, bounded refresh, rotation and hostile documents."""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import jwt
import pytest
from conftest import ISSUER, RESOURCE, base_payload
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from mcp_secure_server.auth import JwtTokenVerifier
from mcp_secure_server.config import ServerConfig
from mcp_secure_server.jwks import MAX_JWKS_BYTES, JwksKeySource

URL = "https://issuer.example.test/jwks"


def _rsa(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


KEY_A, KEY_B, KEY_C = _rsa(), _rsa(), _rsa()


def jwk(key, kid: str, **extra) -> dict:
    document = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return {**document, "kid": kid, "use": "sig", "alg": "RS256", **extra}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Idp:
    """A JWKS endpoint whose content and failures the test controls."""

    def __init__(self, *keys: dict) -> None:
        self.keys = list(keys)
        self.requests = 0
        self.status = 200
        self.body: bytes | None = None
        self.redirect = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.redirect:
            return httpx.Response(302, headers={"location": "https://evil.example.test/jwks"})
        if self.status != 200:
            return httpx.Response(self.status)
        body = self.body if self.body is not None else json.dumps({"keys": self.keys}).encode()
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    def source(self, clock: Clock, **options) -> JwksKeySource:
        client = httpx.AsyncClient(transport=httpx.MockTransport(self.handle))
        return JwksKeySource(URL, client=client, clock=clock, **options)


def lookup(source: JwksKeySource, kid: str):
    return asyncio.run(source.key_for(kid))


def test_the_key_is_found_by_kid() -> None:
    idp = Idp(jwk(KEY_A, "a"), jwk(KEY_B, "b"))
    source = idp.source(Clock())

    async def both():
        return await source.key_for("b"), await source.key_for("a")

    found_b, found_a = asyncio.run(both())
    assert found_b.public_numbers() == KEY_B.public_key().public_numbers()
    assert found_a.public_numbers() == KEY_A.public_key().public_numbers()
    assert idp.requests == 1


def test_an_unknown_kid_is_refused_and_refreshes_at_most_once_per_interval() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    clock = Clock()
    source = idp.source(clock, min_refresh=30.0)

    async def many():
        return [await source.key_for("nope") for _ in range(50)]

    assert set(asyncio.run(many())) == {None}
    assert idp.requests == 1
    clock.now += 31
    assert asyncio.run(source.key_for("nope")) is None
    assert idp.requests == 2


def test_a_rotated_key_is_picked_up_after_the_minimum_interval() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    clock = Clock()
    source = idp.source(clock, min_refresh=30.0)

    async def scenario():
        first = await source.key_for("a")
        idp.keys = [jwk(KEY_A, "a"), jwk(KEY_B, "b")]
        too_soon = await source.key_for("b")
        clock.now += 31
        later = await source.key_for("b")
        return first, too_soon, later

    first, too_soon, later = asyncio.run(scenario())
    assert first is not None
    assert too_soon is None
    assert later is not None


def test_a_removed_key_stops_being_trusted_after_the_ttl() -> None:
    idp = Idp(jwk(KEY_A, "a"), jwk(KEY_B, "b"))
    clock = Clock()
    source = idp.source(clock, ttl=300.0, min_refresh=30.0)

    async def scenario():
        first = await source.key_for("a")
        idp.keys = [jwk(KEY_B, "b")]
        clock.now += 301
        return first, await source.key_for("a")

    first, after = asyncio.run(scenario())
    assert first is not None
    assert after is None


def test_cached_keys_survive_a_short_outage() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    clock = Clock()
    source = idp.source(clock, ttl=300.0, min_refresh=30.0, max_stale=3600.0)

    async def scenario():
        first = await source.key_for("a")
        idp.status = 503
        clock.now += 400
        return first, await source.key_for("a")

    first, during = asyncio.run(scenario())
    assert first is not None
    assert during is not None


def test_keys_are_dropped_when_the_outage_outlasts_max_stale() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    clock = Clock()
    source = idp.source(clock, ttl=300.0, min_refresh=30.0, max_stale=3600.0)

    async def scenario():
        first = await source.key_for("a")
        idp.status = 503
        clock.now += 3601
        return first, await source.key_for("a")

    first, during = asyncio.run(scenario())
    assert first is not None
    assert during is None


def test_a_redirect_is_not_followed() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    idp.redirect = True
    source = idp.source(Clock())
    assert lookup(source, "a") is None
    assert idp.requests == 1


def test_an_oversized_document_is_refused() -> None:
    idp = Idp()
    document = {"keys": [jwk(KEY_A, "a")], "pad": "x" * (MAX_JWKS_BYTES + 10)}
    idp.body = json.dumps(document).encode()
    assert lookup(idp.source(Clock()), "a") is None


def test_the_internal_client_does_not_follow_redirects_or_read_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict = {}
    idp = Idp(jwk(KEY_A, "a"))
    real = httpx.AsyncClient

    def factory(**kwargs):
        seen.update(kwargs)
        return real(transport=httpx.MockTransport(idp.handle), **kwargs)

    monkeypatch.setattr("mcp_secure_server.jwks.httpx.AsyncClient", factory)
    source = JwksKeySource(URL, timeout=2.5, clock=Clock())
    assert lookup(source, "a") is not None
    assert seen == {"follow_redirects": False, "trust_env": False, "timeout": 2.5}


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"keys": "x"}', b'{"keys": [1, null]}'])
def test_malformed_documents_give_no_keys(body: bytes) -> None:
    idp = Idp()
    idp.body = body
    assert lookup(idp.source(Clock()), "a") is None


def test_unsuitable_keys_are_left_out() -> None:
    weak = jwk(_rsa(1024), "weak")
    ec_key = jwt.algorithms.ECAlgorithm.to_jwk(
        ec.generate_private_key(ec.SECP256R1()).public_key(), as_dict=True
    )
    idp = Idp(
        weak,
        {**ec_key, "kid": "ec"},
        jwk(KEY_A, "enc", use="enc"),
        jwk(KEY_A, "ps", alg="PS256"),
        jwk(KEY_B, "good"),
    )
    source = idp.source(Clock())

    async def scenario():
        bad = [await source.key_for(kid) for kid in ("weak", "ec", "enc", "ps")]
        return bad, await source.key_for("good")

    bad, good = asyncio.run(scenario())
    assert bad == [None, None, None, None]
    assert good is not None


def test_a_private_key_in_the_document_is_not_accepted() -> None:
    private = jwt.algorithms.RSAAlgorithm.to_jwk(KEY_A, as_dict=True)
    idp = Idp({**private, "kid": "priv", "use": "sig"})
    assert lookup(idp.source(Clock()), "priv") is None


def test_a_duplicate_kid_is_ambiguous_and_refused() -> None:
    idp = Idp(jwk(KEY_A, "dup"), jwk(KEY_B, "dup"), jwk(KEY_C, "ok"))
    source = idp.source(Clock())

    async def scenario():
        return await source.key_for("dup"), await source.key_for("ok")

    dup, ok = asyncio.run(scenario())
    assert dup is None
    assert ok is not None


def test_a_huge_kid_never_reaches_the_network() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    assert lookup(idp.source(Clock()), "k" * 1000) is None
    assert idp.requests == 0


# --- through the verifier -------------------------------------------------


def _config() -> ServerConfig:
    return ServerConfig(issuer_url=ISSUER, resource_server_url=RESOURCE, jwks_url=URL)


def _token(key, kid: str | None, **claims) -> str:
    headers = {"kid": kid} if kid else {}
    payload = {**base_payload(), **claims}
    return jwt.encode(payload, key, algorithm="RS256", headers=headers)


def _verify(verifier: JwtTokenVerifier, token: str):
    return asyncio.run(verifier.verify_token(token))


def test_a_token_signed_by_a_jwks_key_verifies() -> None:
    idp = Idp(jwk(KEY_A, "a"), jwk(KEY_B, "b"))
    verifier = JwtTokenVerifier(_config(), key_source=idp.source(Clock()))
    assert _verify(verifier, _token(KEY_B, "b")) is not None
    assert _verify(verifier, _token(KEY_A, "a")) is not None


def test_a_token_signed_with_another_key_under_a_known_kid_is_refused() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    verifier = JwtTokenVerifier(_config(), key_source=idp.source(Clock()))
    assert _verify(verifier, _token(KEY_B, "a")) is None


def test_a_token_without_kid_is_refused_when_jwks_is_used() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    verifier = JwtTokenVerifier(_config(), key_source=idp.source(Clock()))
    assert _verify(verifier, _token(KEY_A, None)) is None
    assert idp.requests == 0


def test_claims_are_still_checked_with_a_jwks_key() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    verifier = JwtTokenVerifier(_config(), key_source=idp.source(Clock()))
    assert _verify(verifier, _token(KEY_A, "a", aud="https://other.example/")) is None
    assert _verify(verifier, _token(KEY_A, "a", exp=int(time.time()) - 10)) is None


def test_a_hostile_body_that_raises_something_else_still_counts_as_a_failed_refresh() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    clock = Clock()
    source = idp.source(clock, ttl=10.0, min_refresh=30.0, max_stale=3600.0)

    async def scenario():
        first = await source.key_for("a")
        idp.body = b"[" * 30000  # json.loads raises RecursionError, not ValueError
        clock.now += 31
        during = await source.key_for("a")
        clock.now += 5000
        later = await source.key_for("a")
        return first, during, later

    first, during, later = asyncio.run(scenario())
    assert first is not None
    assert during is not None  # inside max_stale the cached key still serves
    assert later is None  # a failing refresh never keeps keys past max_stale


def test_an_unexpected_transport_exception_is_a_failed_refresh_not_a_crash() -> None:
    clock = Clock()

    def handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("transport blew up")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    source = JwksKeySource(URL, client=client, clock=clock)
    assert lookup(source, "a") is None


def test_keys_are_not_served_past_max_stale_even_when_no_refresh_is_due() -> None:
    idp = Idp(jwk(KEY_A, "a"))
    clock = Clock()
    source = idp.source(clock, ttl=300.0, min_refresh=100000.0, max_stale=3600.0)

    async def scenario():
        first = await source.key_for("a")
        clock.now += 3601
        return first, await source.key_for("a")

    first, after = asyncio.run(scenario())
    assert first is not None
    assert after is None
    assert idp.requests == 1
