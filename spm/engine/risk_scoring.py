"""Quantitative agent risk scoring (Govern pillar).

Produces a 0-100 risk score per agent by combining:
  * open policy findings (weighted by severity),
  * recent runtime threat events (injection, jailbreak, exfiltration, ...),
  * posture signals (missing guardrails, over-privilege, excessive agency).

The score and its contributing factors are written back onto the inventory item
so the dashboard can rank and triage agents. An aggregate posture score across
all agents is also produced for the dashboard headline.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from opentelemetry import trace

from spm.core import db

tracer = trace.get_tracer("spm.engine.risk")

# Severity weights for open findings.
FINDING_WEIGHTS = {"critical": 40, "high": 25, "medium": 10, "low": 3}

# Weights for recent runtime events by type (additive, capped).
EVENT_WEIGHTS = {
    "prompt_injection": 18,
    "semantic_injection": 18,
    "jailbreak": 20,
    "system_prompt_extraction": 16,
    "data_exfiltration": 25,
    "insecure_output": 14,
    "memory_poisoning": 12,
    "privilege_escalation": 22,
    "excessive_agency": 14,
    "rate_limit": 6,
    "mcp_tool_usage": 4,
    "attack_chain": 30,
    "coordinated_attack": 30,
}

RUNTIME_LOOKBACK_HOURS = 24


def _level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def compute_risk_score(findings: list[dict], events: list[dict]) -> dict:
    """Compute a 0-100 risk score and the factors that produced it."""
    score = 0.0
    factors: list[dict] = []

    # Open findings dominate the posture score.
    open_findings = [f for f in findings if f.get("status") == "open"]
    for f in open_findings:
        w = FINDING_WEIGHTS.get(f.get("severity", "low"), 3)
        score += w
    if open_findings:
        factors.append({"source": "findings", "count": len(open_findings),
                        "contribution": sum(FINDING_WEIGHTS.get(f.get("severity", "low"), 3)
                                            for f in open_findings)})

    # Recent runtime events add on top (diminishing — half weight beyond the first of a type).
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=RUNTIME_LOOKBACK_HOURS)).isoformat()
    seen_types: dict[str, int] = {}
    event_contrib = 0.0
    for e in events:
        if e.get("timestamp", "") < cutoff:
            continue
        et = e.get("event_type", "")
        if et == "llm_call":
            continue
        w = EVENT_WEIGHTS.get(et, 4)
        n = seen_types.get(et, 0)
        contrib = w if n == 0 else w * 0.5
        score += contrib
        event_contrib += contrib
        seen_types[et] = n + 1
    if seen_types:
        factors.append({"source": "runtime_events", "types": list(seen_types.keys()),
                        "contribution": round(event_contrib, 1)})

    score_int = int(max(0, min(100, round(score))))
    return {"risk_score": score_int, "risk_level": _level(score_int), "factors": factors}


async def score_all() -> dict:
    """Recompute risk scores for every inventory agent and persist them."""
    with tracer.start_as_current_span("spm.engine.risk.score_all"):
        inventory = db.list_inventory(limit=500)
        agents = [i for i in inventory if i.get("agent_type") != "topology"]

        all_findings = db.list_findings(limit=500)
        findings_by_agent: dict[str, list[dict]] = {}
        for f in all_findings:
            findings_by_agent.setdefault(f.get("agent_id", ""), []).append(f)

        scored, total = 0, 0
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for agent in agents:
            aid = agent.get("agent_id", "")
            events, _ = db.list_runtime_events(agent_id=aid, limit=100)
            result = compute_risk_score(findings_by_agent.get(aid, []), events)
            agent["risk_score"] = result["risk_score"]
            agent.setdefault("metadata", {})["risk_level"] = result["risk_level"]
            agent["metadata"]["risk_factors"] = result["factors"]
            db.put_inventory(agent)
            scored += 1
            total += result["risk_score"]
            distribution[result["risk_level"]] += 1

        avg = round(total / scored, 1) if scored else 0
        # Posture score = 100 minus the average agent risk (higher is healthier).
        posture = max(0, min(100, round(100 - avg)))
        return {
            "agents_scored": scored,
            "average_risk": avg,
            "posture_score": posture,
            "risk_distribution": distribution,
        }
