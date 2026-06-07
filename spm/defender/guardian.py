"""Guardian — autonomous, graduated response orchestrator (Defend pillar).

Closes the loop from detection to response "at agent speed". Given recent
high-severity runtime events/alerts, Guardian decides a **graduated** response
proportional to severity and (optionally) executes it automatically using the
existing remediation actions.

Modes (``SPM_GUARDIAN_MODE``):
  * ``off``       — disabled (default; safe).
  * ``recommend`` — decide and record recommended actions, but DO NOT execute.
  * ``auto``      — execute resolvable actions automatically (use with care).

Response ladder (proportional response, never more than the threat warrants):
  low/medium  -> alert (record only)
  high        -> block (inline enforce already blocks; record + recommend)
  critical    -> contain (quarantine workflow / revoke model / disable key)

Every decision and action is written back as a ``guardian_action`` runtime event
for auditability, so analysts retain oversight.
"""
from __future__ import annotations

import os
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from spm.core import db
from spm.core.models import RuntimeEvent

LITELLM_URL = os.getenv("LITELLM_URL", "http://localhost:4000")
LITELLM_KEY = os.getenv("LITELLM_KEY", "")
TEMPORAL_ADDRESS = os.getenv("TEMPORAL_ADDRESS", "localhost:7233")

# Event types that justify containment at critical severity.
_CONTAIN_EVENTS = {
    "data_exfiltration", "attack_chain", "coordinated_attack",
    "intent_violation", "privilege_escalation", "guardrail_intervention",
}


def mode() -> str:
    return os.getenv("SPM_GUARDIAN_MODE", "off").lower()


def decide(event: dict) -> dict:
    """Decide a graduated response for one event. Pure function (no side effects)."""
    sev = event.get("severity", "low")
    etype = event.get("event_type", "")
    agent_id = event.get("agent_id", "")

    action, target, rationale = "log", agent_id, "informational"
    if sev == "critical" and etype in _CONTAIN_EVENTS:
        if agent_id.startswith("temporal-wf-"):
            action, target = "quarantine_agent", agent_id.replace("temporal-wf-", "")
            rationale = "critical agentic threat on a workflow -> quarantine"
        elif etype == "data_exfiltration":
            action, rationale = "revoke_model_access", "data exfiltration -> revoke model access"
        else:
            action, rationale = "block", "critical threat -> block (inline enforce)"
    elif sev == "high":
        action, rationale = "block", "high-severity threat -> block (inline enforce)"
    elif sev == "medium":
        action, rationale = "alert", "medium-severity -> alert SecOps"
    # auto_executable only for actions we can resolve a concrete target for
    auto_executable = action == "quarantine_agent" or (
        action == "revoke_model_access" and bool(event.get("details", {}).get("api_key"))
    )
    return {"agent_id": agent_id, "event_type": etype, "severity": sev,
            "recommended_action": action, "target": target,
            "rationale": rationale, "auto_executable": auto_executable}


async def _execute(action: str, target: str, reason: str) -> dict:
    """Execute a containment action. Returns a result dict."""
    result = {"action": action, "target": target, "executed": False}
    try:
        if action == "quarantine_agent":
            from temporalio.client import Client
            tc = await Client.connect(TEMPORAL_ADDRESS)
            await tc.get_workflow_handle(target).terminate(reason=f"SPM Guardian: {reason}")
            result["executed"] = True
        elif action == "revoke_model_access" and LITELLM_KEY:
            import httpx
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(f"{LITELLM_URL}/key/update",
                    headers={"Authorization": f"Bearer {LITELLM_KEY}"},
                    json={"key": target, "models": []})
                result["executed"] = resp.status_code == 200
        elif action == "disable_key" and LITELLM_KEY:
            import httpx
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(f"{LITELLM_URL}/key/block",
                    headers={"Authorization": f"Bearer {LITELLM_KEY}"},
                    json={"key": target})
                result["executed"] = resp.status_code == 200
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


async def run_guardian(lookback_min: int = 15, limit: int = 200) -> dict:
    """Evaluate recent high/critical events and respond per the configured mode."""
    m = mode()
    if m == "off":
        return {"mode": "off", "skipped": "SPM_GUARDIAN_MODE not enabled"}

    events, _ = db.list_runtime_events(limit=limit)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=lookback_min)).isoformat()
    candidates = [e for e in events
                  if e.get("severity") in ("critical", "high")
                  and e.get("timestamp", "") >= cutoff
                  and e.get("event_type") not in ("guardian_action", "llm_call")]

    decisions, executed = [], 0
    for e in candidates:
        d = decide(e)
        if m == "auto" and d["auto_executable"]:
            res = await _execute(d["recommended_action"], d["target"], d["rationale"])
            d["execution"] = res
            if res.get("executed"):
                executed += 1
        decisions.append(d)
        # Audit trail
        db.put_runtime_event(asdict(RuntimeEvent(
            agent_id=d["agent_id"], event_type="guardian_action",
            severity="high" if d["severity"] == "critical" else "medium",
            details={"mode": m, "recommended_action": d["recommended_action"],
                     "rationale": d["rationale"], "source_event": e.get("event_type"),
                     "executed": d.get("execution", {}).get("executed", False)},
        )))

    return {"mode": m, "evaluated": len(candidates),
            "decisions": decisions, "actions_executed": executed}
