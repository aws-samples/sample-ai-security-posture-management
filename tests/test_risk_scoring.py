"""Tests for the quantitative risk-scoring compute function."""
from datetime import datetime, timezone

import pytest

pytest.importorskip("boto3")
pytest.importorskip("opentelemetry")

from spm.engine.risk_scoring import compute_risk_score


def _now():
    return datetime.now(timezone.utc).isoformat()


def test_zero_when_clean():
    out = compute_risk_score([], [])
    assert out["risk_score"] == 0 and out["risk_level"] == "low"


def test_open_findings_increase_score():
    findings = [{"severity": "critical", "status": "open"},
                {"severity": "high", "status": "open"}]
    out = compute_risk_score(findings, [])
    assert out["risk_score"] >= 50
    assert out["risk_level"] in ("high", "critical")


def test_resolved_findings_do_not_count():
    findings = [{"severity": "critical", "status": "resolved"}]
    assert compute_risk_score(findings, [])["risk_score"] == 0


def test_recent_runtime_events_add_risk():
    events = [{"event_type": "jailbreak", "severity": "high", "timestamp": _now()}]
    assert compute_risk_score([], events)["risk_score"] > 0


def test_llm_call_events_are_ignored():
    events = [{"event_type": "llm_call", "severity": "low", "timestamp": _now()}]
    assert compute_risk_score([], events)["risk_score"] == 0


def test_score_capped_at_100():
    findings = [{"severity": "critical", "status": "open"} for _ in range(20)]
    assert compute_risk_score(findings, [])["risk_score"] == 100
