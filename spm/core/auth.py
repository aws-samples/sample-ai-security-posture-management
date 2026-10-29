"""Amazon Cognito JWT authentication and group-based authorization for FastAPI.

Enforcement is default-deny and app-wide: ``require_auth`` is registered as a
global FastAPI dependency, so every route, including routes added later, needs
a valid Cognito ID token unless its path is in ``PUBLIC_PATHS``. Handlers do
not have to remember to call anything. ``tests/test_route_auth.py`` enumerates
every route and asserts this.

Authentication fails closed: if ``COGNITO_POOL_ID`` / ``COGNITO_CLIENT_ID`` are
not set, every protected request is rejected with 503. For local development
only, ``SPM_AUTH_DISABLED=true`` treats every caller as a local admin; the API
refuses to start in that mode unless it is bound to loopback and not running in
ECS (see ``assert_auth_disabled_is_local``).

Authorization uses Cognito groups from the ID token (``cognito:groups``):

* GET/HEAD/OPTIONS need ``SPM_VIEWER_GROUP`` or ``SPM_ADMIN_GROUP``;
* every other method needs ``SPM_ADMIN_GROUP``.

GET routes must be read-only. The route test pins the reviewed list of GET
routes, so a new GET route fails CI until someone confirms it changes nothing.
Users who are in neither group get 403.

Group changes take effect when the user's ID token is next refreshed; the
Cognito app client in ``infra/00-spm-identity.yaml`` limits ID tokens to 15
minutes.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import time

import httpx
from fastapi import HTTPException, Request
from jose import jwt, JWTError

logger = logging.getLogger("spm.auth")

# Dedicated audit logger: always emits INFO to stderr (collected by the ECS
# awslogs driver) regardless of the root logging configuration.
audit_logger = logging.getLogger("spm.audit")
if not audit_logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    audit_logger.addHandler(_h)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

COGNITO_POOL_ID = os.getenv("COGNITO_POOL_ID", "")
COGNITO_REGION = os.getenv("AWS_REGION", "us-east-1")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "")
ADMIN_GROUP = os.getenv("SPM_ADMIN_GROUP", "spm-admins")
VIEWER_GROUP = os.getenv("SPM_VIEWER_GROUP", "spm-viewers")

# Routes that skip Cognito auth. Keep this list short and reviewed:
#   /spm/health          fixed liveness response for the ALB health check
#   /v1/chat/completions transparent LLM proxy; the caller's LiteLLM key is
#                        rate-limited and validated against LiteLLM before any
#                        detector, event or alert (spm.defender.proxy_guard)
#   /v1/models           pass-through; LiteLLM authenticates the key, nothing
#                        else runs
# The /v1/* routes are not routed by the ALB (only /spm/* is), so they are
# reachable only from inside the VPC.
PUBLIC_PATHS = frozenset({"/spm/health", "/v1/chat/completions", "/v1/models"})

_READ_METHODS = {"GET", "HEAD", "OPTIONS"}
_JWKS_MIN_REFRESH_SEC = 60  # bound refetches triggered by unknown key IDs
_jwks: list | None = None
_jwks_fetched_at = 0.0


def auth_disabled() -> bool:
    """True only when local development explicitly opts out of authentication."""
    return os.getenv("SPM_AUTH_DISABLED", "").lower() == "true"


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_auth_disabled_is_local(bind_host: str | None = None) -> None:
    """Refuse to run with auth disabled anywhere but a loopback-bound local process.

    Called at startup. Raises RuntimeError (the server exits) when
    ``SPM_AUTH_DISABLED=true`` and the process runs in ECS, or is bound to a
    non-loopback address (``bind_host`` or ``SPM_API_HOST``).
    """
    if not auth_disabled():
        return
    if os.getenv("ECS_CONTAINER_METADATA_URI_V4") or os.getenv("ECS_CONTAINER_METADATA_URI"):
        raise RuntimeError("SPM_AUTH_DISABLED=true is not allowed in ECS; unset it.")
    host = bind_host or os.getenv("SPM_API_HOST", "127.0.0.1")
    if not _is_loopback(host):
        raise RuntimeError(
            f"SPM_AUTH_DISABLED=true requires a loopback bind (got {host!r}); "
            "bind to 127.0.0.1 or turn authentication on.")


def _issuer() -> str:
    return f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_POOL_ID}"


async def _fetch_jwks() -> list:
    global _jwks, _jwks_fetched_at
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(f"{_issuer()}/.well-known/jwks.json")
        resp.raise_for_status()
        keys = resp.json()["keys"]
    _jwks, _jwks_fetched_at = keys, time.monotonic()
    return keys


async def _signing_key(kid: str | None) -> dict | None:
    """Return the JWKS entry for ``kid``, fetching again once if it is unknown.

    Unknown key IDs trigger at most one refetch per ``_JWKS_MIN_REFRESH_SEC`` so a
    caller sending random ``kid`` values cannot make every request hit Cognito.
    """
    keys = _jwks or await _fetch_jwks()
    key = next((k for k in keys if k.get("kid") == kid), None)
    if key is None and time.monotonic() - _jwks_fetched_at >= _JWKS_MIN_REFRESH_SEC:
        keys = await _fetch_jwks()
        key = next((k for k in keys if k.get("kid") == kid), None)
    return key


def _authorize(request: Request, user: dict) -> dict:
    groups = set(user.get("groups", []))
    write = request.method.upper() not in _READ_METHODS
    allowed = {ADMIN_GROUP} if write else {ADMIN_GROUP, VIEWER_GROUP}
    if not groups & allowed:
        audit_logger.warning("authz denied user=%s method=%s path=%s",
                             user.get("user_id"), request.method, request.url.path)
        raise HTTPException(status_code=403, detail="Not authorized for this action")
    if write:
        # Audit trail for every state-changing or action-triggering request.
        audit_logger.info("allowed user=%s email=%s method=%s path=%s",
                          user.get("user_id"), user.get("email"), request.method, request.url.path)
    return user


async def _authenticate(request: Request) -> dict:
    if auth_disabled():
        return {"user_id": "local-dev", "email": "local-dev", "groups": [ADMIN_GROUP]}

    if not COGNITO_POOL_ID or not COGNITO_CLIENT_ID:
        logger.error("Cognito is not configured; rejecting request (fail closed)")
        raise HTTPException(status_code=503, detail="Authentication is not configured")

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization token")
    token = auth.removeprefix("Bearer ")

    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        key = await _signing_key(header.get("kid"))
    except (httpx.HTTPError, KeyError, ValueError):
        logger.exception("Could not fetch Cognito JWKS")
        raise HTTPException(status_code=503, detail="Cannot validate token")
    if not key:
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            issuer=_issuer(),
            options={"verify_at_hash": False},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if claims.get("token_use") != "id":
        raise HTTPException(status_code=401, detail="Invalid token")

    return {
        "user_id": claims["sub"],
        "email": claims.get("email", ""),
        "groups": list(claims.get("cognito:groups", []) or []),
    }


async def get_current_user(request: Request) -> dict:
    """Authenticate and authorize the request; cached per request.

    Returns ``{"user_id", "email", "groups"}``. Raises 401 for a missing or
    invalid token, 403 when the user lacks the required group, and 503 when
    Cognito is not configured (unless ``SPM_AUTH_DISABLED=true``).
    """
    cached = getattr(request.state, "user", None)
    if cached is not None:
        return cached
    user = _authorize(request, await _authenticate(request))
    request.state.user = user
    return user


async def require_auth(request: Request) -> None:
    """Global dependency: every route except ``PUBLIC_PATHS`` needs auth."""
    if request.url.path in PUBLIC_PATHS:
        return
    await get_current_user(request)
