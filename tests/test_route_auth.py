"""Default-deny route authorization and proxy caller checks, against the real app."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("jose")
pytest.importorskip("opentelemetry.instrumentation.fastapi")

from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from spm.core import auth  # noqa: E402
from spm.api import main  # noqa: E402
from spm.defender import proxy_guard  # noqa: E402

# Reviewed: these GET routes only read data, so spm-viewers may call them.
# Adding a GET route fails this test until someone confirms it changes nothing.
READ_ONLY_GET_ROUTES = {
    "/spm/api/dashboard", "/spm/api/inventory", "/spm/api/inventory/{agent_id}",
    "/spm/api/topology", "/spm/api/scans", "/spm/api/findings", "/spm/api/policies",
    "/spm/api/runtime/events", "/spm/api/runtime/events/{event_id}",
    "/spm/api/runtime/alerts", "/spm/api/runtime/stats", "/spm/api/defender/config",
    "/spm/api/monitor/status", "/spm/api/plugins", "/spm/api/integrations",
}


def _routes():
    return [r for r in main.app.routes if isinstance(r, APIRoute)]


def _concrete(path: str) -> str:
    return path.replace("{", "x").replace("}", "")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("SPM_AUTH_DISABLED", raising=False)
    monkeypatch.setattr(auth, "COGNITO_POOL_ID", "us-east-1_TESTPOOL1")
    monkeypatch.setattr(auth, "COGNITO_CLIENT_ID", "testclientid")
    proxy_guard.reset()
    return TestClient(main.app)  # lifespan (monitor loop) not started


def test_public_paths_are_exactly_the_reviewed_set():
    assert auth.PUBLIC_PATHS == {"/spm/health", "/v1/chat/completions", "/v1/models"}
    paths = {r.path for r in _routes()}
    assert auth.PUBLIC_PATHS <= paths


def test_every_non_public_route_requires_a_token(client):
    checked = 0
    for route in _routes():
        if route.path in auth.PUBLIC_PATHS:
            continue
        for method in route.methods - {"HEAD"}:
            resp = client.request(method, _concrete(route.path), json={})
            assert resp.status_code == 401, f"{method} {route.path} -> {resp.status_code}"
            checked += 1
    assert checked >= 34


def test_get_routes_are_the_reviewed_read_only_set():
    gets = {r.path for r in _routes() if "GET" in r.methods and r.path not in auth.PUBLIC_PATHS}
    assert gets == READ_ONLY_GET_ROUTES


def test_global_dependency_is_registered():
    assert any(d.dependency is auth.require_auth for d in main.app.router.dependencies)


def test_api_docs_off_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_health_is_public(client):
    assert client.get("/spm/health").status_code == 200


# ---------------- transparent proxy caller checks ----------------

@pytest.fixture
def no_side_effects(monkeypatch):
    calls = {"events": 0, "detectors": 0}
    monkeypatch.setattr(main.db, "put_runtime_event", lambda *a, **k: calls.__setitem__("events", calls["events"] + 1))
    import spm.core.registry as registry
    monkeypatch.setattr(registry, "detectors_for", lambda phase: calls.__setitem__("detectors", calls["detectors"] + 1) or [])
    monkeypatch.setattr(main, "_emit_alert_events", lambda *a, **k: calls.__setitem__("events", calls["events"] + 1))
    return calls


def _chat(client, key="sk-made-up-key-123456"):
    return client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {key}"},
                       json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})


def test_proxy_rejects_missing_key(client, no_side_effects):
    resp = client.post("/v1/chat/completions", json={"model": "m", "messages": []})
    assert resp.status_code == 401
    assert no_side_effects == {"events": 0, "detectors": 0}


def test_proxy_rejects_unknown_key_before_any_work(client, no_side_effects, monkeypatch):
    async def reject(_auth):
        return False
    monkeypatch.setattr(proxy_guard, "_litellm_accepts", reject)
    assert _chat(client).status_code == 401
    assert no_side_effects == {"events": 0, "detectors": 0}


def test_proxy_fails_closed_when_litellm_unreachable(client, no_side_effects, monkeypatch):
    monkeypatch.setenv("LITELLM_URL", "http://127.0.0.1:9")  # discard port: nothing listens
    assert _chat(client).status_code == 502
    assert no_side_effects == {"events": 0, "detectors": 0}


def test_proxy_rate_limits_per_key(client, no_side_effects, monkeypatch):
    monkeypatch.setenv("SPM_PROXY_RATE_LIMIT_PER_MIN", "3")
    async def reject(_auth):
        return False
    monkeypatch.setattr(proxy_guard, "_litellm_accepts", reject)
    codes = [_chat(client).status_code for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]


@pytest.mark.parametrize("ip_limit", ["2"])
def test_proxy_rate_limits_per_ip_across_keys(client, no_side_effects, monkeypatch, ip_limit):
    monkeypatch.setenv("SPM_PROXY_IP_RATE_LIMIT_PER_MIN", ip_limit)
    async def reject(_auth):
        return False
    monkeypatch.setattr(proxy_guard, "_litellm_accepts", reject)
    codes = [_chat(client, key=f"sk-random-key-{i:06d}").status_code for i in range(3)]
    assert codes == [401, 401, 429]


def test_valid_key_is_cached(monkeypatch):
    import asyncio
    proxy_guard.reset()
    seen = []
    async def accept(auth_header):
        seen.append(auth_header)
        return True
    monkeypatch.setattr(proxy_guard, "_litellm_accepts", accept)
    for _ in range(3):
        asyncio.run(proxy_guard.admit("Bearer sk-valid-key-abcdef"))
    assert len(seen) == 1
