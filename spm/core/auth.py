"""Amazon Cognito JWT authentication and group-based authorization for FastAPI.

Authentication fails closed: if ``COGNITO_POOL_ID`` / ``COGNITO_CLIENT_ID`` are
not set, every protected request is rejected with 503. For local development
only, set ``SPM_AUTH_DISABLED=true`` to treat every caller as a local admin; the
API listens on 127.0.0.1 by default when run with ``uvicorn``.

Authorization uses Cognito groups from the ID token (``cognito:groups``):

* read requests (GET/HEAD/OPTIONS) need ``SPM_VIEWER_GROUP`` or ``SPM_ADMIN_GROUP``;
* every other method (scans, evaluations, policy and defender changes,
  remediation, purge, red-team, integrations) needs ``SPM_ADMIN_GROUP``.

Users who are not in either group (for example self-registered users) get 403.
"""
from __future__ import annotations

import logging
import os

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

_READ_METHODS = {"GET", "HEAD", "OPTIONS"}
_jwks: list | None = None


def auth_disabled() -> bool:
    """True only when local development explicitly opts out of authentication."""
    return os.getenv("SPM_AUTH_DISABLED", "").lower() == "true"


def _issuer() -> str:
    return f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_POOL_ID}"


async def _get_jwks() -> list:
    global _jwks
    if not _jwks and COGNITO_POOL_ID:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{_issuer()}/.well-known/jwks.json")
            resp.raise_for_status()
            _jwks = resp.json()["keys"]
    return _jwks or []


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


async def get_current_user(request: Request) -> dict:
    """Authenticate the caller and authorize the request method.

    Returns ``{"user_id", "email", "groups"}``. Raises 401 for a missing or
    invalid token, 403 when the user lacks the required group, and 503 when
    Cognito is not configured (unless ``SPM_AUTH_DISABLED=true``).
    """
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
        jwks = await _get_jwks()
    except (httpx.HTTPError, KeyError, ValueError):
        logger.exception("Could not fetch Cognito JWKS")
        raise HTTPException(status_code=503, detail="Cannot validate token")
    if not jwks:
        raise HTTPException(status_code=503, detail="Cannot validate token")

    try:
        header = jwt.get_unverified_header(token)
        key = next((k for k in jwks if k.get("kid") == header.get("kid")), None)
        if not key:
            raise HTTPException(status_code=401, detail="Invalid token")
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

    user = {
        "user_id": claims["sub"],
        "email": claims.get("email", ""),
        "groups": list(claims.get("cognito:groups", []) or []),
    }
    return _authorize(request, user)
