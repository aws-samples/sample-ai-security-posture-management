"""Policy engine — evaluates agent inventory against security rules (Govern pillar)."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from opentelemetry import trace

from spm.core import db
from spm.core.config import EXPECTED_DEPS
from spm.core.models import Finding

tracer = trace.get_tracer("spm.engine.policy")

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

def _applies(applies_to: str, agent_type: str) -> bool:
    if applies_to == "*" or applies_to == agent_type:
        return True
    if applies_to == "workflow" and agent_type in ("workflow", "agent", "orchestrator"):
        return True
    return False


async def evaluate_all() -> dict:
    """Run all registered, enabled policy rules against current inventory.

    Rules are sourced from the plugin registry (spm.core.registry.RULES), which
    is populated by spm.engine.rules and any third-party SPM_PLUGINS modules.
    """
    from spm.plugins import load_plugins
    from spm.core.registry import RULES as RULE_REGISTRY
    load_plugins()

    with tracer.start_as_current_span("spm.engine.evaluate"):
        inventory = db.list_inventory(limit=500)
        agents = [i for i in inventory if i.get("agent_type") != "topology"]
        topo_item = next((i for i in inventory if i.get("agent_id") == "topology-snapshot"), None)
        topology = topo_item.get("config", {}) if topo_item else {}

        rules = [r for r in RULE_REGISTRY.values() if r.enabled]
        item_rules = [r for r in rules if r.scope == "item"]
        topo_rules = [r for r in rules if r.scope == "topology"]

        new_findings: list[Finding] = []

        # Per-agent (item-scope) rules
        for agent in agents:
            atype = agent.get("agent_type", "")
            for r in item_rules:
                if not _applies(r.applies_to, atype):
                    continue
                try:
                    finding = r.fn(agent)
                except Exception as e:
                    print(f"[SPM] rule {r.rule_id} error: {e}")
                    finding = None
                if finding:
                    new_findings.append(finding)

        # Topology-scope rules
        if topology:
            for r in topo_rules:
                try:
                    new_findings.extend(r.fn(topology, agents) or [])
                except Exception as e:
                    print(f"[SPM] topology rule {r.rule_id} error: {e}")

        # Persist findings (deduplicate by agent_id + rule_id among open findings)
        existing = db.list_findings(limit=500)
        existing_keys = {(f["agent_id"], f["rule_id"]) for f in existing if f.get("status") == "open"}

        created = 0
        for f in new_findings:
            if (f.agent_id, f.rule_id) not in existing_keys:
                db.put_finding(asdict(f))
                created += 1

        return {
            "evaluated_agents": len(agents),
            "rules_checked": len(rules),
            "new_findings": created,
            "total_findings_generated": len(new_findings),
        }
