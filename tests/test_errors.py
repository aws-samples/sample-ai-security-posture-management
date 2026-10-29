"""API error responses carry no exception text; remediation is always recorded."""
import secrets

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("jose")
pytest.importorskip("opentelemetry.instrumentation.fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from spm.api import main  # noqa: E402
from spm.core import auth, errors  # noqa: E402
from spm.defender import proxy_guard  # noqa: E402

# Unique marker standing in for internal detail (hostnames, upstream bodies)
# that must never reach an API response. Random per run, not a credential.
LEAK_MARKER = f"internal-detail-{secrets.token_hex(8)}"


@pytest.fixture
def admin_client(monkeypatch):
    async def admin():
        return None
    main.app.dependency_overrides[auth.require_auth] = admin
    events = []
    monkeypatch.setattr(main.db, "put_runtime_event", events.append)
    yield TestClient(main.app), events
    main.app.dependency_overrides.clear()


def test_public_error_hides_exception_text():
    try:
        raise RuntimeError(LEAK_MARKER)
    except RuntimeError:
        msg = errors.public_error("disable_key")
    assert msg.startswith("disable_key failed (error id ")
    assert LEAK_MARKER not in msg and "Traceback" not in msg and "RuntimeError" not in msg


def test_remediate_failure_returns_no_exception_text_and_records_event(admin_client, monkeypatch):
    client, events = admin_client

    class Boom:
        def __init__(self, *a, **k):
            raise RuntimeError(LEAK_MARKER)

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", Boom)
    resp = client.post("/spm/api/remediate", json={"action": "disable_key", "target": "k1"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is False
    assert LEAK_MARKER not in resp.text
    assert body["error"].startswith("disable_key failed (error id ")
    # The remediation attempt is always written as a runtime event.
    assert len(events) == 1 and events[0]["event_type"] == "remediation"


def test_sink_errors_return_no_exception_text(monkeypatch):
    from spm.integrations import dispatch_findings
    from spm.core import registry

    def failing(_items):
        raise RuntimeError(LEAK_MARKER)

    spec = registry.SinkSpec(id="test.failing", fn=failing, kind="findings") \
        if hasattr(registry, "SinkSpec") else None
    if spec is None:
        pytest.skip("registry has no SinkSpec")
    import spm.integrations as integ
    monkeypatch.setattr(integ, "sinks_for", lambda kind: [spec])
    out = dispatch_findings([{"finding_id": "f1"}])
    assert out[0]["sink"] == "test.failing"
    assert LEAK_MARKER not in str(out)


def test_proxy_fingerprint_is_keyed_per_process():
    a = proxy_guard.fingerprint("sk-test-key-123456")
    assert a == proxy_guard.fingerprint("sk-test-key-123456")
    import hashlib
    assert a != hashlib.sha256(b"sk-test-key-123456").hexdigest()  # not a bare hash
