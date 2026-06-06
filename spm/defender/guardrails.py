"""Amazon Bedrock Guardrails enforcement, registered as a detector plugin.

When ``SPM_BEDROCK_GUARDRAIL_ID`` is set, this detector calls the Bedrock
``ApplyGuardrail`` API on inbound prompts (pre phase) and outbound responses
(post phase). Bedrock Guardrails provide content filters, denied topics, word
filters, and PII detection/redaction — secure-by-design controls that exceed
regex matching. A guardrail intervention produces a blocking Detection.

    SPM_BEDROCK_GUARDRAIL_ID=abcd1234
    SPM_BEDROCK_GUARDRAIL_VERSION=DRAFT
"""
from __future__ import annotations

import os

import boto3

from spm.core.registry import Detection, DetectionContext, detector

REGION = os.getenv("AWS_REGION", "us-east-1")
_client = None


def _bedrock():
    global _client
    if _client is None:
        _client = boto3.client("bedrock-runtime", region_name=REGION)
    return _client


@detector("builtin.bedrock_guardrail", phases=("pre", "post"),
          description="Amazon Bedrock Guardrails (content filters, denied topics, PII)")
def bedrock_guardrail(ctx: DetectionContext) -> list[Detection]:
    gid = os.getenv("SPM_BEDROCK_GUARDRAIL_ID", "")
    if not gid:
        return []
    version = os.getenv("SPM_BEDROCK_GUARDRAIL_VERSION", "DRAFT")
    text = ctx.prompt_text if ctx.phase == "pre" else ctx.response_text
    if not text:
        return []
    source = "INPUT" if ctx.phase == "pre" else "OUTPUT"
    try:
        resp = _bedrock().apply_guardrail(
            guardrailIdentifier=gid,
            guardrailVersion=version,
            source=source,
            content=[{"text": {"text": text[:25000]}}],
        )
    except Exception as e:
        # Best-effort: never break the request path on guardrail errors.
        return [Detection("guardrail_error", "low", {"error": str(e)[:200], "phase": ctx.phase})]

    if resp.get("action") == "GUARDRAIL_INTERVENED":
        assessments = resp.get("assessments", [])
        categories = []
        for a in assessments:
            for key in ("topicPolicy", "contentPolicy", "sensitiveInformationPolicy", "wordPolicy"):
                if key in a:
                    categories.append(key)
        return [Detection("guardrail_intervention", "high",
                          {"phase": ctx.phase, "policies": categories or ["unspecified"],
                           "model": ctx.model}, block=True)]
    return []
