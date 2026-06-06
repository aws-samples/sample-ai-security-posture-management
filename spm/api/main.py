"""AI SPM FastAPI service — Observe, Govern, Defend endpoints."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from pydantic import BaseModel

from spm.core.auth import get_current_user
from spm.core.tracing import init_tracing
from spm.core import db

tracer = trace.get_tracer("spm.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_tracing("spm-api")
    # Start real-time monitoring loop
    import asyncio
    from spm.defender.monitor import monitor_loop, stop
    task = asyncio.create_task(monitor_loop())
    yield
    stop()
    task.cancel()


app = FastAPI(title="AI SPM API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
FastAPIInstrumentor.instrument_app(app)


# --- Request/Response models ---

class ScanResponse(BaseModel):
    scan_time: str = ""
    total_discovered: int = 0
    delta: dict = {}

class ModeUpdate(BaseModel):
    mode: str  # monitor | enforce

class RulesUpdate(BaseModel):
    rules: dict = {}

class PolicyUpdate(BaseModel):
    enabled: bool

class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    rules: list[dict] = []
    compliance_framework: str = ""
    enabled: bool = True

class PromptTestRequest(BaseModel):
    prompt: str
    model: str = "claude-sonnet"


# ============================================================
# Health
# ============================================================

@app.get("/spm/health")
async def health():
    return {"status": "ok", "service": "ai-spm"}


# ============================================================
# Observe — Dashboard & Inventory
# ============================================================

@app.get("/spm/api/dashboard")
async def dashboard(req: Request):
    await get_current_user(req)
    with tracer.start_as_current_span("spm.api.dashboard"):
        items = db.list_inventory(limit=500)
        agents = [i for i in items if i.get("agent_type") != "topology"]
        topo = next((i for i in items if i.get("agent_id") == "topology-snapshot"), None)
        findings = db.list_findings(limit=500)
        events, _ = db.list_runtime_events(limit=100)

        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            if sev in severity_dist:
                severity_dist[sev] += 1

        return {
            "total_agents": len(agents),
            "by_source": _count_by(agents, "source"),
            "by_type": _count_by(agents, "agent_type"),
            "risk_distribution": severity_dist,
            "open_findings": sum(1 for f in findings if f.get("status") == "open"),
            "total_findings": len(findings),
            "topology_nodes": topo.get("metadata", {}).get("node_count", 0) if topo else 0,
            "topology_edges": topo.get("metadata", {}).get("edge_count", 0) if topo else 0,
            "runtime_events_24h": len(events),
        }


@app.get("/spm/api/inventory")
async def list_inventory(req: Request, source: str | None = None):
    await get_current_user(req)
    with tracer.start_as_current_span("spm.api.inventory"):
        items = db.list_inventory(source=source)
        return {"items": [i for i in items if i.get("agent_type") != "topology"]}


@app.get("/spm/api/inventory/{agent_id}")
async def get_inventory(agent_id: str, req: Request):
    await get_current_user(req)
    item = db.get_inventory(agent_id)
    if not item:
        raise HTTPException(404, "Agent not found")
    findings = db.list_findings(agent_id=agent_id)
    events, _ = db.list_runtime_events(agent_id=agent_id, limit=20)
    return {"agent": item, "findings": findings, "recent_events": events}


@app.get("/spm/api/topology")
async def get_topology(req: Request):
    await get_current_user(req)
    topo = db.get_inventory("topology-snapshot")
    if not topo:
        return {"nodes": [], "edges": []}
    return topo.get("config", {"nodes": [], "edges": []})


@app.get("/spm/api/scans")
async def list_scans(req: Request):
    await get_current_user(req)
    # Scan history is stored as metadata on the topology snapshot
    topo = db.get_inventory("topology-snapshot")
    return {"last_scan": topo.get("last_seen") if topo else None}


# ============================================================
# Observe — Trigger Scan
# ============================================================

@app.post("/spm/api/scan")
async def trigger_scan(req: Request):
    await get_current_user(req)
    with tracer.start_as_current_span("spm.api.scan"):
        from spm.scanner.orchestrator import run_scan
        result = await run_scan()
        return result


# ============================================================
# Govern — Findings & Policies
# ============================================================

@app.get("/spm/api/findings")
async def list_findings(req: Request, severity: str | None = None,
                        status: str | None = None, agent_id: str | None = None):
    await get_current_user(req)
    return {"findings": db.list_findings(agent_id=agent_id, severity=severity, status=status)}


@app.post("/spm/api/findings/{finding_id}/acknowledge")
async def acknowledge_finding(finding_id: str, req: Request):
    await get_current_user(req)
    f = db.get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    db.update_finding_status(finding_id, "acknowledged")
    return {"finding_id": finding_id, "status": "acknowledged"}


@app.post("/spm/api/findings/{finding_id}/resolve")
async def resolve_finding(finding_id: str, req: Request):
    await get_current_user(req)
    f = db.get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    db.update_finding_status(finding_id, "resolved")
    return {"finding_id": finding_id, "status": "resolved"}


@app.post("/spm/api/evaluate")
async def run_evaluation(req: Request):
    """Trigger policy evaluation against current inventory."""
    await get_current_user(req)
    with tracer.start_as_current_span("spm.api.evaluate"):
        from spm.engine.policy_engine import evaluate_all
        result = await evaluate_all()
        return result


@app.get("/spm/api/policies")
async def list_policies(req: Request):
    await get_current_user(req)
    return {"policies": db.list_policies()}


@app.put("/spm/api/policies/{policy_id}")
async def update_policy(policy_id: str, body: PolicyUpdate, req: Request):
    await get_current_user(req)
    p = db.get_policy(policy_id)
    if not p:
        raise HTTPException(404, "Policy not found")
    db.update_policy_enabled(policy_id, body.enabled)
    return {"policy_id": policy_id, "enabled": body.enabled}


@app.post("/spm/api/policies")
async def create_policy(body: PolicyCreate, req: Request):
    await get_current_user(req)
    import uuid
    policy = {
        "policy_id": str(uuid.uuid4()),
        "name": body.name,
        "description": body.description,
        "rules": body.rules,
        "compliance_framework": body.compliance_framework,
        "enabled": body.enabled,
    }
    db.put_policy(policy)
    return policy


@app.delete("/spm/api/policies/{policy_id}")
async def delete_policy(policy_id: str, req: Request):
    await get_current_user(req)
    p = db.get_policy(policy_id)
    if not p:
        raise HTTPException(404, "Policy not found")
    from spm.core.db import _table, POLICIES_TABLE
    _table(POLICIES_TABLE).delete_item(Key={"policy_id": policy_id})
    return {"deleted": policy_id}


# ============================================================
# Defend — Runtime Events & Alerts
# ============================================================

@app.get("/spm/api/runtime/events")
async def list_runtime_events(req: Request, agent_id: str | None = None, limit: int = 25,
                               cursor: str | None = None):
    await get_current_user(req)
    import json as _json
    last_key = _json.loads(cursor) if cursor else None
    items, next_key = db.list_runtime_events(agent_id=agent_id, limit=limit, last_key=last_key)
    return {
        "events": items,
        "next_cursor": _json.dumps(next_key) if next_key else None,
        "has_more": next_key is not None,
    }


@app.get("/spm/api/runtime/events/{event_id}")
async def get_runtime_event(event_id: str, req: Request):
    await get_current_user(req)
    event = db.get_runtime_event(event_id)
    if not event:
        raise HTTPException(404, "Event not found")
    return event


@app.get("/spm/api/runtime/alerts")
async def list_alerts(req: Request, limit: int = 50):
    await get_current_user(req)
    # Get all events and filter to critical/high — DynamoDB doesn't have a severity index
    all_events, _ = db.list_runtime_events(limit=500)
    alerts = [e for e in all_events if e.get("severity") in ("critical", "high")]
    alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"alerts": alerts[:limit]}


@app.get("/spm/api/runtime/stats")
async def runtime_stats(req: Request):
    await get_current_user(req)
    events, _ = db.list_runtime_events(limit=500)
    by_type = _count_by(events, "event_type")
    by_severity = _count_by(events, "severity")
    by_agent = _count_by(events, "agent_id")
    return {"by_type": by_type, "by_severity": by_severity, "by_agent": by_agent, "total": len(events)}


# ============================================================
# Defend — Mode & Rules
# ============================================================

@app.get("/spm/api/defender/config")
async def get_defender_config(req: Request):
    await get_current_user(req)
    policy = db.get_policy("defender-config")
    if not policy:
        return {"mode": "monitor", "rules": {}, "bypass_keys": []}
    return policy.get("config", {"mode": "monitor", "rules": {}, "bypass_keys": []})


@app.put("/spm/api/defender/mode")
async def set_defender_mode(body: ModeUpdate, req: Request):
    await get_current_user(req)
    if body.mode not in ("monitor", "enforce"):
        raise HTTPException(400, "Mode must be 'monitor' or 'enforce'")
    policy = db.get_policy("defender-config") or {
        "policy_id": "defender-config", "name": "Defender Configuration",
        "config": {"mode": "monitor", "rules": {}, "bypass_keys": []},
    }
    policy.setdefault("config", {})["mode"] = body.mode
    db.put_policy(policy)
    return {"mode": body.mode}


@app.put("/spm/api/defender/rules")
async def set_defender_rules(body: RulesUpdate, req: Request):
    await get_current_user(req)
    policy = db.get_policy("defender-config") or {
        "policy_id": "defender-config", "name": "Defender Configuration",
        "config": {"mode": "monitor", "rules": {}, "bypass_keys": []},
    }
    policy.setdefault("config", {})["rules"] = body.rules
    db.put_policy(policy)
    return {"rules": body.rules}


# ============================================================
# Defend — Monitor Status
# ============================================================

@app.get("/spm/api/monitor/status")
async def monitor_status(req: Request):
    await get_current_user(req)
    from spm.defender.monitor import _running, _seen_ids, POLL_INTERVAL
    return {"running": _running, "poll_interval_sec": POLL_INTERVAL, "seen_request_ids": len(_seen_ids)}


@app.post("/spm/api/runtime/purge")
async def purge_runtime_events(req: Request):
    """Delete all runtime events (cleanup stale/noisy data)."""
    await get_current_user(req)
    from spm.core.db import _table, RUNTIME_TABLE
    tbl = _table(RUNTIME_TABLE)
    count = 0
    resp = tbl.scan(ProjectionExpression="event_id")
    while True:
        for item in resp.get("Items", []):
            tbl.delete_item(Key={"event_id": item["event_id"]})
            count += 1
        if not resp.get("LastEvaluatedKey"):
            break
        resp = tbl.scan(ProjectionExpression="event_id", ExclusiveStartKey=resp["LastEvaluatedKey"])
    return {"purged": count}


# ============================================================
# Defend — Prompt Injection Test & Proxy
# ============================================================

@app.post("/spm/api/defend/test")
async def test_prompt(body: PromptTestRequest, req: Request):
    """Test a prompt against the defender without sending to LLM."""
    await get_current_user(req)
    from spm.defender.litellm_callback import SPMCallback
    cb = SPMCallback()
    injection = cb._check_prompt_injection(body.prompt)
    rate_limited = cb._check_rate_limit("test-key", rpm_limit=9999)

    mode = cb._get_mode()
    blocked = mode == "enforce" and injection is not None

    if injection:
        from dataclasses import asdict
        from spm.core.models import RuntimeEvent
        event = RuntimeEvent(
            agent_id="test-prompt", event_type="prompt_injection",
            severity="critical", details={"pattern": injection, "prompt_preview": body.prompt[:200], "mode": mode, "blocked": blocked},
        )
        db.put_runtime_event(asdict(event))

    return {
        "prompt_preview": body.prompt[:100] + "..." if len(body.prompt) > 100 else body.prompt,
        "injection_detected": injection is not None,
        "injection_pattern": injection,
        "mode": mode,
        "blocked": blocked,
        "rate_limited": rate_limited,
    }


@app.post("/spm/api/defend/proxy")
async def proxy_llm(body: PromptTestRequest, req: Request):
    """Send a prompt through the SPM defender, then forward to LLM if allowed.

    In monitor mode: always forwards, logs detections.
    In enforce mode: blocks if injection detected, returns 403.
    """
    await get_current_user(req)
    import httpx
    from spm.defender.litellm_callback import SPMCallback
    from dataclasses import asdict
    from spm.core.models import RuntimeEvent

    cb = SPMCallback()
    mode = cb._get_mode()
    injection = cb._check_prompt_injection(body.prompt)

    # Log the detection
    if injection:
        event = RuntimeEvent(
            agent_id="proxy-request", event_type="prompt_injection",
            severity="critical", details={"pattern": injection, "prompt_preview": body.prompt[:200], "mode": mode},
        )
        db.put_runtime_event(asdict(event))

    # Block in enforce mode
    if mode == "enforce" and injection:
        return {"blocked": True, "reason": f"Prompt injection detected: {injection}", "mode": "enforce", "llm_response": None}

    # Forward to LiteLLM
    litellm_url = os.getenv("LITELLM_URL", "http://localhost:4000")
    litellm_key = os.getenv("LITELLM_KEY", "")
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{litellm_url}/v1/chat/completions",
            headers={"Authorization": f"Bearer {litellm_key}"},
            json={"model": body.model, "messages": [{"role": "user", "content": body.prompt}], "max_tokens": 512},
        )
        resp.raise_for_status()
        llm_resp = resp.json()

    # Log successful call
    event = RuntimeEvent(
        agent_id="proxy-request", event_type="llm_call", severity="low",
        details={"model": body.model, "injection_detected": injection is not None, "mode": mode},
    )
    db.put_runtime_event(asdict(event))

    reply = llm_resp["choices"][0]["message"]["content"]
    return {
        "blocked": False,
        "injection_detected": injection is not None,
        "injection_pattern": injection,
        "mode": mode,
        "llm_response": reply,
    }


# ============================================================
# Defend — Auto-Remediation
# ============================================================

class RemediationAction(BaseModel):
    action: str  # disable_key, quarantine_agent, revoke_model_access
    target: str  # key ID, agent ID, or model name
    reason: str = ""

@app.post("/spm/api/remediate")
async def auto_remediate(body: RemediationAction, req: Request):
    """Execute auto-remediation actions."""
    await get_current_user(req)
    import httpx
    litellm_url = os.getenv("LITELLM_URL", "http://localhost:4000")
    litellm_key = os.getenv("LITELLM_KEY", "")
    result = {"action": body.action, "target": body.target, "success": False}

    if body.action == "disable_key":
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(f"{litellm_url}/key/delete",
                    headers={"Authorization": f"Bearer {litellm_key}"},
                    json={"keys": [body.target]})
                result["success"] = resp.status_code == 200
                result["detail"] = "Key disabled"
        except Exception as e:
            result["error"] = str(e)

    elif body.action == "quarantine_agent":
        # Stop the Temporal workflow
        try:
            from temporalio.client import Client
            tc = await Client.connect(os.getenv("TEMPORAL_ADDRESS", "localhost:7233"))
            handle = tc.get_workflow_handle(body.target)
            await handle.terminate(reason=f"SPM quarantine: {body.reason}")
            result["success"] = True
            result["detail"] = "Workflow terminated"
        except Exception as e:
            result["error"] = str(e)

    elif body.action == "revoke_model_access":
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(f"{litellm_url}/key/update",
                    headers={"Authorization": f"Bearer {litellm_key}"},
                    json={"key": body.target, "models": []})
                result["success"] = resp.status_code == 200
                result["detail"] = "Model access revoked"
        except Exception as e:
            result["error"] = str(e)

    # Log remediation
    event = RuntimeEvent(
        agent_id=body.target, event_type="remediation", severity="high",
        details={"action": body.action, "reason": body.reason, "success": result.get("success")},
    )
    db.put_runtime_event(asdict(event))
    return result


@app.post("/spm/api/correlate")
async def run_correlation(req: Request):
    """Run attack chain correlation analysis."""
    await get_current_user(req)
    from spm.defender.correlation import correlate_attack_chains
    alerts = correlate_attack_chains()
    return {"chains_detected": len(alerts), "alerts": alerts}


# ============================================================
# Defend — Transparent LLM Proxy (OpenAI-compatible)
# Agents call this instead of LiteLLM directly.
# Intercepts, scans, blocks/logs, then forwards to LiteLLM.
# ============================================================

@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request):
    """Transparent LLM proxy with full threat detection suite."""
    import httpx
    from spm.defender.litellm_callback import SPMCallback
    from spm.defender.advanced_detectors import (
        classify_injection_semantic, scan_response_for_pii,
        detect_memory_poisoning, detect_mcp_tool_usage,
    )
    from spm.core.models import RuntimeEvent

    body = await request.json()
    auth = request.headers.get("Authorization", "")
    api_key = auth.replace("Bearer ", "") if auth else "unknown"
    agent_id = f"litellm-key-{api_key[-8:]}" if len(api_key) > 8 else "unknown"

    messages = body.get("messages", [])
    prompt_text = " ".join(m.get("content", "") for m in messages if isinstance(m, dict))
    model = body.get("model", "unknown")

    cb = SPMCallback()
    mode = cb._get_mode()
    threats = []

    # 1. Regex injection check (fast)
    injection = cb._check_prompt_injection(prompt_text)
    if injection:
        threats.append(("prompt_injection", "critical", {"pattern": injection}))

    # 2. Semantic injection check (Bedrock-powered, if regex missed)
    if not injection and len(prompt_text) > 20:
        try:
            is_inj, reason = await classify_injection_semantic(prompt_text)
            if is_inj:
                injection = reason
                threats.append(("semantic_injection", "critical", {"reason": reason}))
        except Exception:
            pass

    # 3. Memory poisoning check
    memory_issues = detect_memory_poisoning(messages)
    for issue in memory_issues:
        threats.append(("memory_poisoning", "high", issue))

    # 4. Rate limiting
    rate_limited = cb._check_rate_limit(api_key)
    if rate_limited:
        threats.append(("rate_limit", "high", {"api_key": api_key[-4:]}))

    # Log all threats
    for event_type, severity, details in threats:
        event = RuntimeEvent(
            agent_id=agent_id, event_type=event_type, severity=severity,
            details={**details, "model": model, "mode": mode, "blocked": mode == "enforce",
                     "prompt_preview": prompt_text[:200]},
        )
        db.put_runtime_event(asdict(event))

    # Block in enforce mode if any critical/high threat
    if mode == "enforce" and threats:
        top_threat = threats[0]
        return {"error": {"message": f"Request blocked by AI SPM: {top_threat[0]}",
                          "type": "spm_blocked", "code": top_threat[0]},
                "id": "spm-blocked", "object": "error", "model": model,
                "choices": [{"message": {"role": "assistant",
                             "content": f"⚠️ This request was blocked by AI SPM: {top_threat[0]} detected."},
                             "index": 0, "finish_reason": "content_filter"}]}

    # Forward to real LiteLLM
    litellm_url = os.getenv("LITELLM_URL", "http://localhost:4000")
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            f"{litellm_url}/v1/chat/completions",
            headers={"Authorization": auth, "Content-Type": "application/json"},
            json=body,
        )

    # Post-response checks
    try:
        resp_json = resp.json()
        response_text = resp_json.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = resp_json.get("usage", {})

        # 5. Data exfiltration check on response
        pii_detections = scan_response_for_pii(response_text)
        if pii_detections:
            event = RuntimeEvent(
                agent_id=agent_id, event_type="data_exfiltration", severity="critical",
                details={"pii_types": pii_detections, "model": model, "mode": mode},
            )
            db.put_runtime_event(asdict(event))

        # 6. MCP tool usage check
        mcp_detections = detect_mcp_tool_usage(messages, response_text)
        for det in mcp_detections:
            event = RuntimeEvent(
                agent_id=agent_id, event_type="mcp_tool_usage", severity="medium",
                details={**det, "model": model},
            )
            db.put_runtime_event(asdict(event))

        # Log the call
        event = RuntimeEvent(
            agent_id=agent_id, event_type="llm_call", severity="low",
            details={"model": model, "prompt_tokens": usage.get("prompt_tokens", 0),
                     "completion_tokens": usage.get("completion_tokens", 0),
                     "total_tokens": usage.get("total_tokens", 0),
                     "injection_scanned": True,
                     "pii_detected": len(pii_detections) > 0,
                     **({"threats": [t[0] for t in threats]} if threats else {})},
        )
        db.put_runtime_event(asdict(event))
        return resp_json
    except Exception:
        from fastapi.responses import Response
        return Response(content=resp.content, status_code=resp.status_code,
                        headers=dict(resp.headers))


# Also proxy other LiteLLM endpoints for full transparency
@app.get("/v1/models")
async def proxy_models(request: Request):
    import httpx
    litellm_url = os.getenv("LITELLM_URL", "http://localhost:4000")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{litellm_url}/v1/models",
                                headers={"Authorization": request.headers.get("Authorization", "")})
        return resp.json()


# ============================================================
# Helpers
# ============================================================

def _count_by(items: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for i in items:
        v = i.get(key, "unknown")
        counts[v] = counts.get(v, 0) + 1
    return counts
