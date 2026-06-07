"""Intent-based detection + build-time -> runtime correlation (Defend pillar).

This goes beyond per-request signatures: it infers whether an agent's *runtime
behavior* aligns with how it was *built/configured* (its inventory record) and
with its own established session pattern. Two complementary signals:

1. **Build-to-runtime correlation** — compares the model/tools/token usage seen
   at runtime against the agent's inventory record (sanctioned models, expected
   dependencies, behavioral baseline). Divergence = `intent_violation`.
2. **Session behavioral drift** — tracks each agent's established per-session
   pattern (models, tools, token volume) and flags new capabilities appearing
   mid-session or volume spikes = `behavioral_drift`.

Optionally (``SPM_INTENT_LLM=true``) a Bedrock classifier judges whether an
agent's action summary aligns with its declared purpose.

This is the agentic analogue of intent-aware runtime defense: understanding what
an agent is *trying to do* across a sequence, not just individual events.
"""
from __future__ import annotations

import json
import os
import time

from spm.core import db
from spm.core.registry import Detection, DetectionContext, detector
from spm.defender import advanced_detectors as ad

_BASELINE_FACTOR = float(os.getenv("SPM_INTENT_BASELINE_FACTOR", "3.0"))
_SESSION_TTL = 1800  # 30 min
_sessions: dict[str, dict] = {}


def _session(agent_id: str) -> dict:
    now = time.time()
    s = _sessions.get(agent_id)
    if not s or now - s["start"] > _SESSION_TTL:
        s = {"start": now, "models": set(), "tools": set(), "calls": 0}
        _sessions[agent_id] = s
    if len(_sessions) > 5000:  # bound memory
        for k in list(_sessions)[:2500]:
            _sessions.pop(k, None)
    return s


def _extract_tools(messages: list, response_text: str) -> set[str]:
    text = " ".join(m.get("content", "") for m in messages if isinstance(m, dict)) + " " + response_text
    tools: set[str] = set()
    for pattern in ad.MCP_TOOL_PATTERNS:
        for m in pattern.finditer(text):
            tools.add(m.group(1).strip())
    return tools


def _allowed_models(inv: dict) -> set[str]:
    perms = inv.get("permissions", {})
    cfg = inv.get("config", {})
    models = set(perms.get("allowed_models", []) or cfg.get("models", []) or [])
    if cfg.get("provider_model"):
        models.add(cfg["provider_model"])
    if inv.get("name"):
        models.add(inv["name"])
    return {m for m in models if m}


async def _classify_intent(purpose: str, action_summary: str):
    """Optional Bedrock intent-alignment classifier. Returns (aligned, reason)."""
    import boto3
    try:
        client = boto3.client("bedrock-runtime", region_name=ad.REGION)
        prompt = (
            "You are an AI agent security analyst. An agent's SANCTIONED PURPOSE and its "
            "OBSERVED RUNTIME ACTIONS are given. Reply with one word: ALIGNED if the actions "
            "are consistent with the purpose, or MISALIGNED if they suggest the agent is doing "
            f"something outside its sanctioned task.\n\nPURPOSE: {purpose[:300]}\n"
            f"OBSERVED ACTIONS: {action_summary[:400]}\n\nAnswer:"
        )
        body = json.dumps({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 5,
                           "messages": [{"role": "user", "content": prompt}]})
        resp = client.invoke_model(modelId=ad.CLASSIFIER_MODEL_ID, body=body,
                                   contentType="application/json")
        ans = json.loads(resp["body"].read()).get("content", [{}])[0].get("text", "").strip().upper()
        return ("MISALIGNED" not in ans, ans)
    except Exception as e:
        return True, f"unavailable:{e}"


@detector("builtin.intent_alignment", phases=("post",), is_async=True,
          description="Build-to-runtime correlation + session intent/behavioral drift")
async def intent_alignment(ctx: DetectionContext) -> list[Detection]:
    detections: list[Detection] = []
    agent_id = ctx.agent_id or "unknown"
    model = ctx.model or ""
    tools = _extract_tools(ctx.messages, ctx.response_text)
    total_tokens = (ctx.usage or {}).get("total_tokens", 0)

    inv = None
    try:
        inv = db.get_inventory(agent_id)
    except Exception:
        inv = None

    # (1) Build-to-runtime correlation against the inventory record.
    if inv:
        allowed = _allowed_models(inv)
        if allowed and model and not any(model in a or a in model for a in allowed):
            detections.append(Detection("intent_violation", "high",
                {"reason": "unsanctioned_model", "model": model,
                 "sanctioned": sorted(allowed)[:5]}, block=True))
        baseline = inv.get("behavioral_baseline", {})
        avg_tokens = baseline.get("avg_token_usage", 0)
        if avg_tokens and total_tokens > avg_tokens * _BASELINE_FACTOR:
            detections.append(Detection("behavioral_drift", "medium",
                {"reason": "token_volume_anomaly", "tokens": total_tokens,
                 "baseline_avg": avg_tokens}))

    # (2) Session behavioral drift (new model/tools appearing mid-session).
    s = _session(agent_id)
    s["calls"] += 1
    if model and model not in s["models"] and s["models"]:
        detections.append(Detection("behavioral_drift", "medium",
            {"reason": "new_model_in_session", "model": model}))
    if model:
        s["models"].add(model)
    new_tools = tools - s["tools"]
    if new_tools and s["tools"]:
        detections.append(Detection("behavioral_drift", "medium",
            {"reason": "new_tools_in_session", "tools": sorted(new_tools)[:10]}))
    s["tools"].update(tools)

    # (3) Optional Bedrock intent-alignment classification.
    if os.getenv("SPM_INTENT_LLM", "").lower() in ("1", "true", "yes") and inv and tools:
        purpose = f"{inv.get('name', '')} {inv.get('metadata', {}).get('description', '')}".strip()
        action_summary = f"model={model}; tools={sorted(tools)}"
        aligned, reason = await _classify_intent(purpose, action_summary)
        if not aligned:
            detections.append(Detection("intent_violation", "high",
                {"reason": "llm_misaligned", "detail": reason, "tools": sorted(tools)[:10]},
                block=True))

    return detections
