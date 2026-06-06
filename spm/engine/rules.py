"""Built-in Govern rules, registered as plugins.

The existing configuration/trace checks live in ``policy_engine`` and are
registered here with their metadata. New agentic rules are defined and
registered in this module. Add your own rule by decorating a function with
``@rule(...)`` in any module loaded via ``SPM_PLUGINS``.

Compliance tags map to:
  * OWASP LLM Top 10 (2025):  LLM01 Prompt Injection, LLM02 Sensitive Info
    Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency,
    LLM08 Vector/Embedding Weaknesses, LLM10 Unbounded Consumption.
  * OWASP Agentic AI threats (T1..T15), e.g. T2 Tool Misuse, T6 Excessive Agency.
  * MITRE ATLAS adversarial-ML tactics.
"""
from __future__ import annotations

from spm.core import db
from spm.core.models import Finding
from spm.core.registry import rule
from spm.engine import policy_engine as pe

# ------------------------------------------------------------------
# Register the existing checks (defined in policy_engine) with metadata
# ------------------------------------------------------------------

rule("overprivileged_key", "Overprivileged API Key",
     "Key has no budget limit or model restrictions", "high", "key",
     ["OWASP_LLM_TOP10:LLM06", "OWASP_AGENTIC:T6", "NIST_AI_RMF"])(pe._check_overprivileged_key)

rule("missing_guardrails", "Missing Model Guardrails",
     "Model config lacks max_tokens limits", "medium", "model",
     ["OWASP_LLM_TOP10:LLM10", "NIST_AI_RMF"])(pe._check_missing_guardrails)

rule("unrestricted_model_access", "Unrestricted Model Access",
     "Key can access all models with no allowlist", "high", "key",
     ["OWASP_LLM_TOP10:LLM06", "MITRE_ATLAS", "NIST_AI_RMF"])(pe._check_unrestricted_model_access)

rule("excessive_spend", "Excessive Spend",
     "Key spend exceeds 80% of budget", "medium", "key",
     ["OWASP_LLM_TOP10:LLM10", "NIST_AI_RMF"])(pe._check_excessive_spend)

rule("stale_agent", "Stale Agent",
     "Workflow type not executed recently", "low", "workflow",
     ["NIST_AI_RMF"])(pe._check_stale_agent)

rule("high_retry_rate", "High Failure/Retry Rate",
     "Workflow has >10% failure rate", "high", "workflow",
     ["OWASP_LLM_TOP10:LLM10", "NIST_AI_RMF"])(pe._check_high_retry_rate)

rule("latency_anomaly", "Latency Anomaly",
     "Agent execution time significantly exceeds baseline", "medium", "workflow",
     ["MITRE_ATLAS"])(pe._check_latency_anomaly)

rule("excessive_llm_calls", "Excessive LLM Calls",
     "Agent making more LLM calls per execution than baseline", "medium", "workflow",
     ["OWASP_LLM_TOP10:LLM06", "OWASP_AGENTIC:T6", "MITRE_ATLAS"])(pe._check_excessive_llm_calls)

rule("missing_trace_propagation", "Missing Trace Propagation",
     "Workflow executions lack trace context", "low", "workflow",
     ["NIST_AI_RMF"])(pe._check_missing_trace_propagation)

rule("unexpected_dependency", "Unexpected Dependency",
     "Agent calling a service not in expected dependency graph", "high", "topology",
     ["OWASP_AGENTIC:T2", "MITRE_ATLAS", "OWASP_LLM_TOP10:LLM06"],
     scope="topology")(pe._check_unexpected_dependency)


# ------------------------------------------------------------------
# New agentic rules (posture derived from recent runtime evidence + config)
# ------------------------------------------------------------------

def _recent_event_types(agent_id: str, types: set[str], limit: int = 100) -> int:
    try:
        events, _ = db.list_runtime_events(agent_id=agent_id, limit=limit)
    except Exception:
        return 0
    return sum(1 for e in events if e.get("event_type") in types)


@rule("jailbreak_activity", "Jailbreak Activity",
      "Agent has recent jailbreak attempts", "high", "*",
      ["OWASP_LLM_TOP10:LLM01", "OWASP_AGENTIC:T1", "MITRE_ATLAS"])
def check_jailbreak_activity(agent: dict) -> Finding | None:
    n = _recent_event_types(agent["agent_id"], {"jailbreak"})
    if n:
        return Finding(agent_id=agent["agent_id"], severity="high", rule_id="jailbreak_activity",
                       title=f"Jailbreak attempts: {agent.get('name', 'unknown')}",
                       description=f"{n} jailbreak attempt(s) detected against this agent.",
                       remediation="Enable enforce mode and associate a Bedrock guardrail.",
                       compliance_frameworks=["OWASP_LLM_TOP10:LLM01", "OWASP_AGENTIC:T1", "MITRE_ATLAS"])
    return None


@rule("sensitive_data_exposure", "Sensitive Data Exposure",
      "Agent has recent PII/secret exfiltration in responses", "critical", "*",
      ["OWASP_LLM_TOP10:LLM02", "MITRE_ATLAS", "NIST_AI_RMF"])
def check_sensitive_data_exposure(agent: dict) -> Finding | None:
    n = _recent_event_types(agent["agent_id"], {"data_exfiltration"})
    if n:
        return Finding(agent_id=agent["agent_id"], severity="critical", rule_id="sensitive_data_exposure",
                       title=f"Sensitive data exposure: {agent.get('name', 'unknown')}",
                       description=f"{n} response(s) contained PII or secrets.",
                       remediation="Add output PII redaction (Bedrock guardrail) and review data access scope.",
                       compliance_frameworks=["OWASP_LLM_TOP10:LLM02", "MITRE_ATLAS", "NIST_AI_RMF"])
    return None


@rule("insecure_output_handling", "Insecure Output Handling",
      "Agent emits dangerous output (scripts, exfil links, shell)", "high", "*",
      ["OWASP_LLM_TOP10:LLM05", "MITRE_ATLAS"])
def check_insecure_output_handling(agent: dict) -> Finding | None:
    n = _recent_event_types(agent["agent_id"], {"insecure_output"})
    if n:
        return Finding(agent_id=agent["agent_id"], severity="high", rule_id="insecure_output_handling",
                       title=f"Insecure output handling: {agent.get('name', 'unknown')}",
                       description=f"{n} response(s) contained unsafe constructs (scripts/links/commands).",
                       remediation="Sanitize/encode model output before rendering or executing downstream.",
                       compliance_frameworks=["OWASP_LLM_TOP10:LLM05", "MITRE_ATLAS"])
    return None


@rule("excessive_agency", "Excessive Agency",
      "Agent invokes too many or too wide a set of tools", "high", "*",
      ["OWASP_LLM_TOP10:LLM06", "OWASP_AGENTIC:T6", "MITRE_ATLAS"])
def check_excessive_agency(agent: dict) -> Finding | None:
    n = _recent_event_types(agent["agent_id"], {"excessive_agency"})
    if n:
        return Finding(agent_id=agent["agent_id"], severity="high", rule_id="excessive_agency",
                       title=f"Excessive agency: {agent.get('name', 'unknown')}",
                       description=f"{n} turn(s) showed excessive tool invocation / spread.",
                       remediation="Constrain the agent's tool set and require approval for sensitive tools.",
                       compliance_frameworks=["OWASP_LLM_TOP10:LLM06", "OWASP_AGENTIC:T6", "MITRE_ATLAS"])
    return None


@rule("unapproved_model", "Unapproved Model",
      "Agent uses a model outside the approved allowlist", "medium", "model",
      ["NIST_AI_RMF", "OWASP_AGENTIC:T15"])
def check_unapproved_model(agent: dict) -> Finding | None:
    import os
    allow = [m.strip() for m in os.getenv("SPM_APPROVED_MODELS", "").split(",") if m.strip()]
    if not allow:
        return None  # no allowlist configured -> rule inactive
    name = agent.get("name", "") or agent.get("config", {}).get("provider_model", "")
    if name and not any(a.lower() in name.lower() for a in allow):
        return Finding(agent_id=agent["agent_id"], severity="medium", rule_id="unapproved_model",
                       title=f"Unapproved model: {name}",
                       description=f"Model '{name}' is not in the approved allowlist.",
                       remediation="Restrict to approved models or add this model to SPM_APPROVED_MODELS after review.",
                       compliance_frameworks=["NIST_AI_RMF", "OWASP_AGENTIC:T15"])
    return None


@rule("missing_guardrail_association", "Missing Guardrail Association",
      "Model/key has no Bedrock guardrail associated", "medium", "model",
      ["OWASP_LLM_TOP10:LLM01", "NIST_AI_RMF"])
def check_missing_guardrail_association(agent: dict) -> Finding | None:
    import os
    if os.getenv("SPM_REQUIRE_GUARDRAIL", "").lower() not in ("1", "true", "yes"):
        return None  # rule inactive unless org requires guardrails
    cfg = agent.get("config", {})
    if not cfg.get("guardrail_id") and not cfg.get("guardrailIdentifier"):
        return Finding(agent_id=agent["agent_id"], severity="medium", rule_id="missing_guardrail_association",
                       title=f"No guardrail: {agent.get('name', 'unknown')}",
                       description="This model/key has no Amazon Bedrock guardrail associated.",
                       remediation="Associate a Bedrock guardrail (content filters, denied topics, PII redaction).",
                       compliance_frameworks=["OWASP_LLM_TOP10:LLM01", "NIST_AI_RMF"])
    return None
