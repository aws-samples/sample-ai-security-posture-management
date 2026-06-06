"""Deep Amazon Bedrock security posture scanner (Observe pillar).

Discovers Bedrock security-relevant configuration so the Govern rules can assess
it:

  * Guardrails — content-filter strengths, PII (sensitive information) policy,
    denied topics, word filters.
  * Knowledge Bases (RAG) — encryption (customer-managed KMS) and status.
  * Account-level model-invocation logging — whether prompts/responses are
    logged to CloudWatch/S3 for auditing and incident response.

Registered as a scanner plugin; results are merged into the inventory like any
other discovery source.
"""
from __future__ import annotations

import os
from dataclasses import asdict

import boto3
from opentelemetry import trace

from spm.core.models import AgentInventoryItem
from spm.core.registry import scanner

REGION = os.getenv("AWS_REGION", "us-east-1")
tracer = trace.get_tracer("spm.scanner.bedrock")

_STRENGTH_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _bedrock():
    return boto3.client("bedrock", region_name=REGION)


def _bedrock_agent():
    return boto3.client("bedrock-agent", region_name=REGION)


def scan_guardrails() -> list[dict]:
    """Discover Bedrock Guardrails and summarize their protective config."""
    with tracer.start_as_current_span("spm.scan.bedrock.guardrails"):
        items: list[dict] = []
        try:
            client = _bedrock()
            summaries = client.list_guardrails().get("guardrails", [])
        except Exception as e:
            print(f"[SPM] Bedrock guardrail list: {e}")
            return []
        for g in summaries:
            gid = g.get("id") or g.get("arn", "")
            content_strengths: list[str] = []
            has_pii = has_denied_topics = has_word_filter = False
            try:
                detail = _bedrock().get_guardrail(guardrailIdentifier=gid)
                for f in detail.get("contentPolicy", {}).get("filters", []):
                    content_strengths.append(f.get("inputStrength", "NONE"))
                    content_strengths.append(f.get("outputStrength", "NONE"))
                si = detail.get("sensitiveInformationPolicy", {})
                has_pii = bool(si.get("piiEntities") or si.get("regexes"))
                has_denied_topics = bool(detail.get("topicPolicy", {}).get("topics"))
                has_word_filter = bool(detail.get("wordPolicy", {}).get("words")
                                       or detail.get("wordPolicy", {}).get("managedWordLists"))
            except Exception as e:
                print(f"[SPM] Bedrock get_guardrail {gid}: {e}")
            min_strength = min((_STRENGTH_ORDER.get(s, 0) for s in content_strengths), default=0)
            item = AgentInventoryItem(
                agent_id=f"bedrock-guardrail-{gid}",
                source="bedrock", agent_type="guardrail",
                name=g.get("name", gid),
                config={
                    "guardrail_id": gid,
                    "status": g.get("status", ""),
                    "has_content_filters": bool(content_strengths),
                    "min_content_filter_strength": [k for k, v in _STRENGTH_ORDER.items()
                                                    if v == min_strength][0] if content_strengths else "NONE",
                    "has_pii_policy": has_pii,
                    "has_denied_topics": has_denied_topics,
                    "has_word_filter": has_word_filter,
                },
                metadata={"arn": g.get("arn", ""), "updated_at": str(g.get("updatedAt", ""))},
            )
            items.append(asdict(item))
        return items


def scan_knowledge_bases() -> list[dict]:
    """Discover Bedrock Knowledge Bases (RAG) and their encryption posture."""
    with tracer.start_as_current_span("spm.scan.bedrock.knowledge_bases"):
        items: list[dict] = []
        try:
            client = _bedrock_agent()
            kbs = client.list_knowledge_bases(maxResults=100).get("knowledgeBaseSummaries", [])
        except Exception as e:
            print(f"[SPM] Bedrock KB list: {e}")
            return []
        for kb in kbs:
            kb_id = kb.get("knowledgeBaseId", "")
            kms = False
            role_arn = ""
            try:
                detail = _bedrock_agent().get_knowledge_base(knowledgeBaseId=kb_id).get("knowledgeBase", {})
                role_arn = detail.get("roleArn", "")
                # Customer-managed KMS appears in storage/embedding config when set.
                kms = "kmsKeyArn" in str(detail)
            except Exception as e:
                print(f"[SPM] Bedrock get_knowledge_base {kb_id}: {e}")
            item = AgentInventoryItem(
                agent_id=f"bedrock-kb-{kb_id}",
                source="bedrock", agent_type="knowledge_base",
                name=kb.get("name", kb_id),
                config={"knowledge_base_id": kb_id, "status": kb.get("status", ""),
                        "customer_managed_kms": kms},
                permissions={"role_arn": role_arn},
                metadata={"updated_at": str(kb.get("updatedAt", ""))},
            )
            items.append(asdict(item))
        return items


def scan_invocation_logging() -> list[dict]:
    """Capture account-level Bedrock model-invocation logging configuration."""
    with tracer.start_as_current_span("spm.scan.bedrock.logging"):
        enabled = False
        destinations: list[str] = []
        try:
            cfg = _bedrock().get_model_invocation_logging_configuration().get("loggingConfig")
            if cfg:
                enabled = True
                if cfg.get("cloudWatchConfig"):
                    destinations.append("cloudwatch")
                if cfg.get("s3Config"):
                    destinations.append("s3")
        except Exception:
            # Not configured (or no permission) -> treat as disabled.
            enabled = False
        item = AgentInventoryItem(
            agent_id="bedrock-invocation-logging",
            source="bedrock", agent_type="bedrock_config",
            name="Bedrock Model Invocation Logging",
            config={"logging_enabled": enabled, "destinations": destinations},
            metadata={"region": REGION},
        )
        return [asdict(item)]


@scanner("builtin.bedrock_security", source="bedrock", is_async=False,
         description="Bedrock guardrails, knowledge bases, and model-invocation logging posture")
def scan() -> list[dict]:
    with tracer.start_as_current_span("spm.scan.bedrock_security"):
        return scan_guardrails() + scan_knowledge_bases() + scan_invocation_logging()
