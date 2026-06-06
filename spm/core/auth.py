"""Amazon Cognito JWT authentication for FastAPI.

If ``COGNITO_POOL_ID`` is not set, authentication is disabled and every request
is treated as an anonymous user. This is convenient for local development, but
you should always configure a Cognito user pool before exposing the API.
"""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import HTTPException, Request
from jose import jwt, JWTError

logger = logging.getLogger("spm.auth")

COGNITO_POOL_ID = os.getenv("COGNITO_POOL_ID", "")
COGNITO_REGION = os.getenv("AWS_REGION", "us-east-1")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "")

_jwks: list | None = None


async def _get_jwks() -> list:
    global _jwks
    if not _jwks and COGNITO_POOL_ID:
        url = (
            f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/"
            f"{COGNITO_POOL_ID}/.well-known/jwks.json"
        )
        async with httpx.AsyncClient() as client:
            resp = await client.get(url)
            _jwks = resp.json()["keys"]
    return _jwks or []


async def get_current_user(request: Request) -> dict:
    """Extract and validate the user from the Authorization header.

    Returns ``{"user_id": ..., "email": ...}``. When Cognito is not configured,
    returns an anonymous user instead of raising.
    """
    if not COGNITO_POOL_ID:
        return {"user_id": "anonymous", "email": "anonymous"}

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization token")

    token = auth.removeprefix("Bearer ")
    try:
        jwks = await _get_jwks()
        if not jwks:
            raise HTTPException(status_code=401, detail="Cannot validate token")

        header = jwt.get_unverified_header(token)
        key = next((k for k in jwks if k["kid"] == header["kid"]), None)
        if not key:
            raise HTTPException(status_code=401, detail="Invalid token key")

        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_POOL_ID}",
            options={"verify_at_hash": False},
        )
        return {"user_id": claims["sub"], "email": claims.get("email", "")}
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
