"""Tests for intent-based detection (build-to-runtime correlation + session drift)
and the Guardian graduated-response decision logic."""
import pytest

pytest.importorskip("boto3")

from spm.core.registry import DetectionContext
from spm.defender import guardian
from spm.defender import intent


# ---------------- Guardian decision ladder (pure) ----------------

def test_guardian_critical_workflow_quarantines():
    d = guardian.decide({"severity": "critical", "event_type": "attack_chain",
                         "agent_id": "temporal-wf-Orders", "details": {}})
    assert d["recommended_action"] == "quarantine_agent"
    assert d["target"] == "Orders" and d["auto_executable"] is True


def test_guardian_critical_exfil_revokes_model():
    d = guardian.decide({"severity": "critical", "event_type": "data_exfiltration",
                         "agent_id": "litellm-key-abcd1234", "details": {}})
    assert d["recommended_action"] == "revoke_model_access"


def test_guardian_high_blocks_and_medium_alerts():
    assert guardian.decide({"severity": "high", "event_type": "jailbreak",
                            "agent_id": "x"})["recommended_action"] == "block"
    assert guardian.decide({"severity": "medium", "event_type": "mcp_tool_usage",
                            "agent_id": "x"})["recommended_action"] == "alert"


@pytest.mark.asyncio
async def test_guardian_off_by_default(monkeypatch):
    monkeypatch.delenv("SPM_GUARDIAN_MODE", raising=False)
    out = await guardian.run_guardian()
    assert out["mode"] == "off" and "skipped" in out


# ---------------- Intent: session behavioral drift ----------------

@pytest.mark.asyncio
async def test_intent_flags_new_model_mid_session(monkeypatch):
    monkeypatch.setattr(intent.db, "get_inventory", lambda *a, **k: None)
    aid = "test-agent-session-1"
    ctx1 = DetectionContext(phase="post", agent_id=aid, model="claude-a", usage={})
    assert await intent.intent_alignment(ctx1) == []  # establishes baseline
    ctx2 = DetectionContext(phase="post", agent_id=aid, model="claude-b", usage={})
    dets = await intent.intent_alignment(ctx2)
    assert any(d.event_type == "behavioral_drift" and d.details.get("reason") == "new_model_in_session"
               for d in dets)


# ---------------- Intent: build-to-runtime correlation ----------------

@pytest.mark.asyncio
async def test_intent_flags_unsanctioned_model(monkeypatch):
    inv = {"agent_id": "k1", "permissions": {"allowed_models": ["claude-sanctioned"]},
           "config": {}, "behavioral_baseline": {}}
    monkeypatch.setattr(intent.db, "get_inventory", lambda *a, **k: inv)
    monkeypatch.delenv("SPM_INTENT_LLM", raising=False)
    ctx = DetectionContext(phase="post", agent_id="k1", model="evil-model", usage={})
    dets = await intent.intent_alignment(ctx)
    viol = [d for d in dets if d.event_type == "intent_violation"]
    assert viol and viol[0].block is True


@pytest.mark.asyncio
async def test_intent_token_volume_drift(monkeypatch):
    inv = {"agent_id": "k2", "permissions": {"allowed_models": ["m"]},
           "config": {}, "behavioral_baseline": {"avg_token_usage": 100}}
    monkeypatch.setattr(intent.db, "get_inventory", lambda *a, **k: inv)
    ctx = DetectionContext(phase="post", agent_id="k2", model="m", usage={"total_tokens": 5000})
    dets = await intent.intent_alignment(ctx)
    assert any(d.event_type == "behavioral_drift" and d.details.get("reason") == "token_volume_anomaly"
               for d in dets)
