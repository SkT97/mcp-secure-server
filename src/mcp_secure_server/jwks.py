"""Signing keys from a JWKS document (RFC 7517) with a bounded, fail-closed cache.

The operator configures one HTTPS address. The token chooses nothing but the
``kid`` it asks for, and that only selects among keys already published there.

- The address is fetched without following redirects, with a timeout and a size
  limit; proxy settings from the environment are ignored.
- Only RSA public keys of at least 2048 bits that are usable for signing with
  RS256 are kept. A kid that appears twice is ambiguous and is dropped.
- An unknown kid triggers at most one refresh per ``min_refresh`` seconds, so a
  flood of random kids costs at most one request in that interval.
- Keys are refreshed after ``ttl`` seconds. If the refresh keeps failing, the
  cached keys are used for at most ``max_stale`` seconds and are then dropped.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .config import MIN_RSA_KEY_BITS

logger = logging.getLogger(__name__)

MAX_JWKS_BYTES = 64 * 1024
MAX_KEYS = 20
MAX_KID_LENGTH = 128


class JwksKeySource:
    """Looks up verification keys by ``kid`` in the JWKS published at ``url``."""

    def __init__(
        self,
        url: str,
        *,
        ttl: float = 300.0,
        min_refresh: float = 30.0,
        max_stale: float = 3600.0,
        timeout: float = 5.0,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._ttl = ttl
        self._min_refresh = min_refresh
        self._max_stale = max_stale
        self._timeout = timeout
        self._client = client
        self._clock = clock
        self._keys: dict[str, RSAPublicKey] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._lock = asyncio.Lock()

    async def key_for(self, kid: str) -> RSAPublicKey | None:
        if not kid or len(kid) > MAX_KID_LENGTH:
            return None
        async with self._lock:
            now = self._clock()
            if self._fetched_at is not None and now - self._fetched_at >= self._max_stale:
                self._keys = {}  # keys older than max_stale are never served
            fresh = self._fetched_at is not None and now - self._fetched_at < self._ttl
            if fresh and kid in self._keys:
                return self._keys[kid]
            if self._attempted_at is None or now - self._attempted_at >= self._min_refresh:
                await self._refresh(now)
            return self._keys.get(kid)

    async def _refresh(self, now: float) -> None:
        self._attempted_at = now
        try:
            keys = await self._fetch()
        except Exception:  # any failure, including a hostile body, is a failed refresh
            logger.warning("jwks refresh failed")
            return
        self._keys = keys
        self._fetched_at = now

    async def _fetch(self) -> dict[str, RSAPublicKey]:
        client = self._client or httpx.AsyncClient(
            follow_redirects=False, trust_env=False, timeout=self._timeout
        )
        try:
            async with client.stream("GET", self._url, headers={"Accept": "application/json"}) as r:
                if r.status_code != 200:
                    raise ValueError("unexpected status")
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_JWKS_BYTES:
                        raise ValueError("document too large")
        finally:
            if self._client is None:
                await client.aclose()
        return _parse(json.loads(bytes(body)))


def _parse(document: object) -> dict[str, RSAPublicKey]:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("not a JWKS document")
    keys: dict[str, RSAPublicKey] = {}
    ambiguous: set[str] = set()
    for entry in document["keys"][:MAX_KEYS]:
        if not isinstance(entry, dict) or entry.get("kty") != "RSA":
            continue
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_LENGTH:
            continue
        if entry.get("use") not in (None, "sig") or entry.get("alg") not in (None, "RS256"):
            continue
        try:
            key = jwt.PyJWK.from_dict(entry).key
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            continue
        if not isinstance(key, RSAPublicKey) or key.key_size < MIN_RSA_KEY_BITS:
            continue
        if kid in keys:
            ambiguous.add(kid)
        keys[kid] = key
    return {kid: key for kid, key in keys.items() if kid not in ambiguous}
