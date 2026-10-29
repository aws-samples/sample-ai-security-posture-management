"""Caller checks for the transparent LLM proxy, run before any detection work.

The proxy (``/v1/chat/completions``) must not run detectors, write runtime
events, send AIDR alerts or call Bedrock for a caller LiteLLM would reject.
``admit`` therefore:

1. requires a bearer key;
2. applies per-key and per-client-IP rate limits
   (``SPM_PROXY_RATE_LIMIT_PER_MIN``, default 120 per key, and
   ``SPM_PROXY_IP_RATE_LIMIT_PER_MIN``, default 600 per IP; both per API task).
   The IP limit also bounds how often made-up keys can reach LiteLLM;
3. validates the key with LiteLLM (``GET /v1/models`` with the caller's key) and
   caches a successful result for ``SPM_PROXY_KEY_CACHE_SEC`` (default 60).

Rejected keys are never cached, so a revoked key stops working within the cache
TTL. Callers are tracked only by an HMAC-SHA256 fingerprint of their key,
keyed with a random per-process secret. The fingerprint is an in-memory cache
and rate-limit key, not a stored credential: it is never persisted or compared
against a stored value, and it is meaningless outside this process. If LiteLLM
runs without authentication it accepts any key, and so does this check.
"""
from __future__ import annotations

import hmac
import os
import secrets
import time
from collections import OrderedDict, deque

import httpx
from fastapi import HTTPException

from spm.core.auth import audit_logger

_CACHE_MAX = 10_000
_FINGERPRINT_SECRET = secrets.token_bytes(32)  # per process, never logged or stored
_valid_until: "OrderedDict[str, float]" = OrderedDict()
_hits: "OrderedDict[str, deque]" = OrderedDict()


def _key_limit() -> int:
    return int(os.getenv("SPM_PROXY_RATE_LIMIT_PER_MIN", "120"))


def _ip_limit() -> int:
    return int(os.getenv("SPM_PROXY_IP_RATE_LIMIT_PER_MIN", "600"))


def _cache_ttl() -> float:
    return float(os.getenv("SPM_PROXY_KEY_CACHE_SEC", "60"))


def fingerprint(api_key: str) -> str:
    """Keyed, per-process identifier for an API key (cache and rate-limit key only)."""
    return hmac.new(_FINGERPRINT_SECRET, api_key.encode(), "sha256").hexdigest()


def _check_rate(bucket: str, limit: int, now: float) -> None:
    window = _hits.setdefault(bucket, deque())
    _hits.move_to_end(bucket)
    while window and now - window[0] >= 60:
        window.popleft()
    if len(window) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    window.append(now)
    while len(_hits) > _CACHE_MAX:  # drop the least recently used window
        _hits.popitem(last=False)


async def _litellm_accepts(auth_header: str) -> bool:
    url = os.getenv("LITELLM_URL", "http://localhost:4000")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{url}/v1/models", headers={"Authorization": auth_header})
    except httpx.HTTPError:
        # Fail closed: without LiteLLM we cannot tell whether the key is valid.
        raise HTTPException(status_code=502, detail="Upstream LLM gateway unavailable")
    if resp.status_code in (401, 403):
        return False
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail="Upstream LLM gateway error")
    return True


async def admit(auth_header: str, client_ip: str = "unknown") -> str:
    """Return the caller's key fingerprint, or raise 401/429/502."""
    now = time.monotonic()
    _check_rate(f"ip:{client_ip}", _ip_limit(), now)
    if not auth_header.startswith("Bearer ") or not auth_header.removeprefix("Bearer ").strip():
        raise HTTPException(status_code=401, detail="Missing API key")
    fp = fingerprint(auth_header.removeprefix("Bearer ").strip())
    _check_rate(f"key:{fp}", _key_limit(), now)

    expiry = _valid_until.get(fp)
    if expiry is not None and expiry > now:
        return fp
    if not await _litellm_accepts(auth_header):
        _valid_until.pop(fp, None)
        audit_logger.warning("proxy rejected key fingerprint=%s", fp[:12])
        raise HTTPException(status_code=401, detail="Invalid API key")
    _valid_until[fp] = now + _cache_ttl()
    _valid_until.move_to_end(fp)
    while len(_valid_until) > _CACHE_MAX:
        _valid_until.popitem(last=False)
    return fp


def reset() -> None:
    """Clear caches (tests)."""
    _valid_until.clear()
    _hits.clear()
