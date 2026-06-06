"""Policy engine — evaluates agent inventory against security rules (Govern pillar)."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from opentelemetry import trace

from spm.core import db
from spm.core.config import EXPECTED_DEPS
from spm.core.models import Finding

tracer = trace.get_tracer("spm.engine.policy")

# ============================================================
# Rule definitions
# ============================================================

RULES = [
    # --- Config-based rules ---
    {
        "rule_id": "overprivileged_key",
        "name": "Overprivileged API Key",
        "description": "Key has no budget limit or model restrictions",
        "severity": "high",
        "compliance": ["OWASP_LLM_TOP10", "NIST_AI_RMF"],
        "applies_to": "key",
        "check": "_check_overprivileged_key",
    },
    {
        "rule_id": "missing_guardrails",
        "name": "Missing Model Guardrails",
        "description": "Model config lacks max_tokens limits",
        "severity": "medium",
        "compliance": ["OWASP_LLM_TOP10"],
        "applies_to": "model",
        "check": "_check_missing_guardrails",
    },
    {
        "rule_id": "unrestricted_model_access",
        "name": "Unrestricted Model Access",
        "description": "Key can access all models with no allowlist",
        "severity": "high",
        "compliance": ["NIST_AI_RMF", "MITRE_ATLAS"],
        "applies_to": "key",
        "check": "_check_unrestricted_model_access",
    },
    {
        "rule_id": "excessive_spend",
        "name": "Excessive Spend",
        "description": "Key spend exceeds 80% of budget",
        "severity": "medium",
        "compliance": ["NIST_AI_RMF"],
        "applies_to": "key",
        "check": "_check_excessive_spend",
    },
    {
        "rule_id": "stale_agent",
        "name": "Stale Agent",
        "description": "Workflow type not executed in >7 days",
        "severity": "low",
        "compliance": ["NIST_AI_RMF"],
        "applies_to": "workflow",
        "check": "_check_stale_agent",
    },
    # --- Trace-based rules ---
    {
        "rule_id": "high_retry_rate",
        "name": "High Failure/Retry Rate",
        "description": "Workflow has >10% failure rate",
        "severity": "high",
        "compliance": ["OWASP_LLM_TOP10", "NIST_AI_RMF"],
        "applies_to": "workflow",
        "check": "_check_high_retry_rate",
    },
    {
        "rule_id": "latency_anomaly",
        "name": "Latency Anomaly",
        "description": "Agent execution time significantly exceeds baseline",
        "severity": "medium",
        "compliance": ["MITRE_ATLAS"],
        "applies_to": "workflow",
        "check": "_check_latency_anomaly",
    },
    {
        "rule_id": "excessive_llm_calls",
        "name": "Excessive LLM Calls",
        "description": "Agent making more LLM calls per execution than baseline",
        "severity": "medium",
        "compliance": ["OWASP_LLM_TOP10", "MITRE_ATLAS"],
        "applies_to": "workflow",
        "check": "_check_excessive_llm_calls",
    },
    {
        "rule_id": "missing_trace_propagation",
        "name": "Missing Trace Propagation",
        "description": "Workflow executions lack trace context",
        "severity": "low",
        "compliance": ["NIST_AI_RMF"],
        "applies_to": "workflow",
        "check": "_check_missing_trace_propagation",
    },
    {
        "rule_id": "unexpected_dependency",
        "name": "Unexpected Dependency",
        "description": "Agent calling a service not in expected dependency graph",
        "severity": "high",
        "compliance": ["MITRE_ATLAS", "OWASP_LLM_TOP10"],
        "applies_to": "topology",
        "check": "_check_unexpected_dependency",
    },
]

# Expected dependencies per agent are loaded from spm.core.config (EXPECTED_DEPS).
# Each entry maps a workflow name to the set of downstream services it is allowed
# to call. Any service-graph edge to a target outside this set raises an
# "unexpected_dependency" finding. Defaults to empty (no baseline = no findings)
# until you supply a config file via SPM_CONFIG_FILE.


# ============================================================
# Rule check functions
# ============================================================

def _check_overprivileged_key(agent: dict) -> Finding | None:
    config = agent.get("config", {})
    meta = agent.get("metadata", {})
    no_budget = meta.get("max_budget") is None
    no_model_restrict = not config.get("models")
    if no_budget and no_model_restrict:
        return Finding(
            agent_id=agent["agent_id"], severity="high", rule_id="overprivileged_key",
            title=f"Overprivileged key: {agent.get('name', 'unknown')}",
            description=f"Key '{agent.get('name')}' has no budget limit and no model restrictions.",
            remediation="Set a max_budget and restrict allowed models for this key.",
            compliance_frameworks=["OWASP_LLM_TOP10", "NIST_AI_RMF"],
        )
    return None


def _check_missing_guardrails(agent: dict) -> Finding | None:
    config = agent.get("config", {})
    if not config.get("max_tokens"):
        return Finding(
            agent_id=agent["agent_id"], severity="medium", rule_id="missing_guardrails",
            title=f"Missing guardrails: {agent.get('name', 'unknown')}",
            description=f"Model '{agent.get('name')}' has no max_tokens configured.",
            remediation="Set max_tokens in the model configuration to prevent runaway generation.",
            compliance_frameworks=["OWASP_LLM_TOP10"],
        )
    return None


def _check_unrestricted_model_access(agent: dict) -> Finding | None:
    models = agent.get("config", {}).get("models", [])
    if not models or models == []:
        return Finding(
            agent_id=agent["agent_id"], severity="high", rule_id="unrestricted_model_access",
            title=f"Unrestricted model access: {agent.get('name', 'unknown')}",
            description=f"Key '{agent.get('name')}' has no model allowlist — can access all models.",
            remediation="Restrict the key to specific models via the models allowlist.",
            compliance_frameworks=["NIST_AI_RMF", "MITRE_ATLAS"],
        )
    return None


def _check_excessive_spend(agent: dict) -> Finding | None:
    meta = agent.get("metadata", {})
    spend = meta.get("spend", 0)
    budget = meta.get("max_budget")
    if budget and budget > 0 and spend > budget * 0.8:
        return Finding(
            agent_id=agent["agent_id"], severity="medium", rule_id="excessive_spend",
            title=f"Excessive spend: {agent.get('name', 'unknown')}",
            description=f"Key spend ${spend:.2f} exceeds 80% of budget ${budget:.2f}.",
            remediation="Review usage patterns or increase budget limit.",
            compliance_frameworks=["NIST_AI_RMF"],
        )
    return None


def _check_stale_agent(agent: dict) -> Finding | None:
    meta = agent.get("metadata", {})
    total = meta.get("total_executions", 0)
    if total == 0:
        return Finding(
            agent_id=agent["agent_id"], severity="low", rule_id="stale_agent",
            title=f"Stale agent: {agent.get('name', 'unknown')}",
            description=f"Workflow '{agent.get('name')}' has zero executions.",
            remediation="Verify if this workflow is still needed or decommission it.",
            compliance_frameworks=["NIST_AI_RMF"],
        )
    return None


def _check_high_retry_rate(agent: dict) -> Finding | None:
    meta = agent.get("metadata", {})
    rate = meta.get("failure_rate_pct", 0)
    if rate > 10:
        return Finding(
            agent_id=agent["agent_id"], severity="high", rule_id="high_retry_rate",
            title=f"High failure rate: {agent.get('name', 'unknown')}",
            description=f"Workflow '{agent.get('name')}' has {rate:.1f}% failure rate (threshold: 10%).",
            remediation="Investigate workflow failures and add error handling or retry logic.",
            compliance_frameworks=["OWASP_LLM_TOP10", "NIST_AI_RMF"],
        )
    return None


def _check_latency_anomaly(agent: dict) -> Finding | None:
    baseline = agent.get("behavioral_baseline", {})
    avg = baseline.get("avg_latency_ms", 0)
    p95 = baseline.get("p95_latency_ms", 0)
    if avg > 0 and p95 > avg * 3:
        return Finding(
            agent_id=agent["agent_id"], severity="medium", rule_id="latency_anomaly",
            title=f"Latency anomaly: {agent.get('name', 'unknown')}",
            description=f"P95 latency ({p95:.0f}ms) is >3x average ({avg:.0f}ms).",
            remediation="Investigate slow executions — may indicate prompt injection causing recursive calls.",
            compliance_frameworks=["MITRE_ATLAS"],
        )
    return None


def _check_excessive_llm_calls(agent: dict) -> Finding | None:
    baseline = agent.get("behavioral_baseline", {})
    avg_calls = baseline.get("avg_llm_calls_per_execution", 0)
    # Flag if average exceeds 5 calls per execution (configurable threshold)
    if avg_calls > 5:
        return Finding(
            agent_id=agent["agent_id"], severity="medium", rule_id="excessive_llm_calls",
            title=f"Excessive LLM calls: {agent.get('name', 'unknown')}",
            description=f"Agent averages {avg_calls:.1f} LLM calls per execution.",
            remediation="Review agent logic for unnecessary LLM calls or prompt chaining.",
            compliance_frameworks=["OWASP_LLM_TOP10", "MITRE_ATLAS"],
        )
    return None


def _check_missing_trace_propagation(agent: dict) -> Finding | None:
    baseline = agent.get("behavioral_baseline", {})
    sample_count = baseline.get("sample_count", -1)
    total_exec = agent.get("metadata", {}).get("total_executions", 0)
    # If we have executions but very few traces, propagation is broken
    if total_exec > 10 and sample_count == 0:
        return Finding(
            agent_id=agent["agent_id"], severity="low", rule_id="missing_trace_propagation",
            title=f"Missing traces: {agent.get('name', 'unknown')}",
            description=f"Workflow has {total_exec} executions but no X-Ray traces found.",
            remediation="Ensure OpenTelemetry TracingInterceptor is configured on the worker.",
            compliance_frameworks=["NIST_AI_RMF"],
        )
    return None


def _check_unexpected_dependency(topology: dict, inventory: list[dict]) -> list[Finding]:
    """Check topology edges against expected dependency map."""
    findings = []
    edges = topology.get("edges", [])
    for edge in edges:
        source = edge.get("source", "")
        target = edge.get("target", "")
        for wf_name, expected in EXPECTED_DEPS.items():
            if wf_name.lower().replace("workflow", "") in source.lower():
                if target not in expected and target != source:
                    findings.append(Finding(
                        agent_id=f"temporal-wf-{wf_name}",
                        severity="high", rule_id="unexpected_dependency",
                        title=f"Unexpected dependency: {wf_name} → {target}",
                        description=f"Agent '{wf_name}' is calling '{target}' which is not in its expected dependency set.",
                        remediation=f"Verify if '{target}' is a legitimate dependency. If so, add it to the expected set.",
                        compliance_frameworks=["MITRE_ATLAS", "OWASP_LLM_TOP10"],
                    ))
    return findings


# ============================================================
# Evaluation orchestrator
# ============================================================

CHECK_FNS = {
    "overprivileged_key": _check_overprivileged_key,
    "missing_guardrails": _check_missing_guardrails,
    "unrestricted_model_access": _check_unrestricted_model_access,
    "excessive_spend": _check_excessive_spend,
    "stale_agent": _check_stale_agent,
    "high_retry_rate": _check_high_retry_rate,
    "latency_anomaly": _check_latency_anomaly,
    "excessive_llm_calls": _check_excessive_llm_calls,
    "missing_trace_propagation": _check_missing_trace_propagation,
}


async def evaluate_all() -> dict:
    """Run all enabled policy rules against current inventory."""
    with tracer.start_as_current_span("spm.engine.evaluate"):
        inventory = db.list_inventory(limit=500)
        agents = [i for i in inventory if i.get("agent_type") != "topology"]
        topo_item = next((i for i in inventory if i.get("agent_id") == "topology-snapshot"), None)
        topology = topo_item.get("config", {}) if topo_item else {}

        new_findings: list[Finding] = []

        # Per-agent rules
        for agent in agents:
            agent_type = agent.get("agent_type", "")
            for rule in RULES:
                if rule["applies_to"] == "topology":
                    continue
                # Match rule to agent type
                if rule["applies_to"] not in (agent_type, "workflow") and agent_type not in ("agent", "orchestrator"):
                    if rule["applies_to"] != agent_type:
                        continue
                fn = CHECK_FNS.get(rule["rule_id"])
                if fn:
                    finding = fn(agent)
                    if finding:
                        new_findings.append(finding)

        # Topology rules
        if topology:
            topo_findings = _check_unexpected_dependency(topology, agents)
            new_findings.extend(topo_findings)

        # Persist findings (deduplicate by agent_id + rule_id)
        existing = db.list_findings(limit=500)
        existing_keys = {(f["agent_id"], f["rule_id"]) for f in existing if f.get("status") == "open"}

        created = 0
        for f in new_findings:
            key = (f.agent_id, f.rule_id)
            if key not in existing_keys:
                db.put_finding(asdict(f))
                created += 1

        return {
            "evaluated_agents": len(agents),
            "rules_checked": len(RULES),
            "new_findings": created,
            "total_findings_generated": len(new_findings),
        }
