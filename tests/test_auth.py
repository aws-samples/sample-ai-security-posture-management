"""Tests for fail-closed Cognito authentication and group-based authorization."""
import asyncio
import secrets
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
jose = pytest.importorskip("jose")
crypto = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from jose import jwk, jwt  # noqa: E402
from starlette.requests import Request  # noqa: E402

from spm.core import auth  # noqa: E402

POOL = "us-east-1_TESTPOOL1"
CLIENT = "testclientid"
REGION = "us-east-1"
KID = "test-kid"
# Cognito token_use claim values (token types, not credentials).
ID_USE = "id"
ACCESS_USE = "access"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_jwk = jwk.construct(pub_pem, "RS256").to_dict()
    pub_jwk.update({"kid": KID, "alg": "RS256", "use": "sig"})
    return priv_pem, pub_jwk


@pytest.fixture
def configured(monkeypatch, keypair):
    monkeypatch.delenv("SPM_AUTH_DISABLED", raising=False)
    monkeypatch.setattr(auth, "COGNITO_POOL_ID", POOL)
    monkeypatch.setattr(auth, "COGNITO_CLIENT_ID", CLIENT)
    monkeypatch.setattr(auth, "COGNITO_REGION", REGION)
    monkeypatch.setattr(auth, "_jwks", [keypair[1]])
    return keypair[0]


def _request(method="GET", path="/spm/api/findings", token=None):
    headers = [(b"authorization", f"Bearer {token}".encode())] if token else []
    return Request({"type": "http", "method": method, "path": path, "headers": headers,
                    "query_string": b""})


def _token(priv, groups=None, **overrides):
    now = int(time.time())
    claims = {"sub": "user-1", "email": "u@example.com", "aud": CLIENT,
              "iss": f"https://cognito-idp.{REGION}.amazonaws.com/{POOL}",
              "token_use": ID_USE, "iat": now, "exp": now + 300}
    if groups is not None:
        claims["cognito:groups"] = groups
    claims.update(overrides)
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": KID})


def _call(req):
    return asyncio.run(auth.get_current_user(req))


def _status(req):
    with pytest.raises(HTTPException) as e:
        _call(req)
    return e.value.status_code


def test_fails_closed_when_cognito_not_configured(monkeypatch):
    monkeypatch.delenv("SPM_AUTH_DISABLED", raising=False)
    monkeypatch.setattr(auth, "COGNITO_POOL_ID", "")
    monkeypatch.setattr(auth, "COGNITO_CLIENT_ID", "")
    assert _status(_request()) == 503


@pytest.mark.parametrize("value", ["", "1", "yes", "TRUE-ish"])
def test_only_exact_opt_in_disables_auth(monkeypatch, value):
    monkeypatch.setenv("SPM_AUTH_DISABLED", value)
    monkeypatch.setattr(auth, "COGNITO_POOL_ID", "")
    monkeypatch.setattr(auth, "COGNITO_CLIENT_ID", "")
    assert _status(_request()) == 503


def test_explicit_local_opt_in(monkeypatch):
    monkeypatch.setenv("SPM_AUTH_DISABLED", "true")
    assert _call(_request("POST", "/spm/api/remediate"))["user_id"] == "local-dev"


def test_missing_token_is_401(configured):
    assert _status(_request()) == 401


def test_viewer_can_read(configured):
    user = _call(_request("GET", token=_token(configured, ["spm-viewers"])))
    assert user["user_id"] == "user-1"


def test_viewer_cannot_write(configured):
    assert _status(_request("POST", "/spm/api/remediate",
                            token=_token(configured, ["spm-viewers"]))) == 403


def test_admin_can_write(configured):
    user = _call(_request("PUT", "/spm/api/defender/mode",
                          token=_token(configured, ["spm-admins"])))
    assert "spm-admins" in user["groups"]


def test_user_without_group_is_denied(configured):
    assert _status(_request("GET", token=_token(configured))) == 403


def test_wrong_audience_rejected(configured):
    assert _status(_request(token=_token(configured, ["spm-admins"], aud="other"))) == 401


def test_access_token_rejected(configured):
    assert _status(_request(token=_token(configured, ["spm-admins"],
                                         token_use=ACCESS_USE))) == 401


def test_expired_token_rejected(configured):
    past = int(time.time()) - 3600
    assert _status(_request(token=_token(configured, ["spm-admins"], iat=past - 300,
                                         exp=past))) == 401


def test_hs256_token_rejected(configured):
    # Attacker-chosen HMAC key (random per run): an HS256 token must never be
    # accepted, whatever key signed it.
    attacker_key = secrets.token_urlsafe(32)
    forged = jwt.encode({"sub": "x", "aud": CLIENT, "token_use": ID_USE,
                         "cognito:groups": ["spm-admins"]},
                        attacker_key, algorithm="HS256", headers={"kid": KID})
    assert _status(_request(token=forged)) == 401
