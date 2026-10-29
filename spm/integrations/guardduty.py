"""Amazon GuardDuty AI Protection ingestion (AIDR).

GuardDuty AI Protection detects Bedrock-specific threats — including credential
exfiltration involving Bedrock, anomalous model invocation, guardrail removal,
and disabled invocation logging. This module pulls those findings, converts them
to SPM findings (so they appear in the dashboard and flow to Govern), and fans
high-severity ones to the event sinks (SNS/EventBridge/Security Hub).

Enable with:
    SPM_GUARDDUTY_ENABLED=true

Runs on demand via POST /spm/api/integrations/guardduty/ingest, or wire it into
the monitor loop. GuardDuty numeric severity is mapped to SPM severities.
"""
from __future__ import annotations

import os
from dataclasses import asdict
from datetime import datetime, timezone

import boto3

from spm.core import db
from spm.core.models import Finding
from spm.core.errors import public_error

REGION = os.getenv("AWS_REGION", "us-east-1")
# GuardDuty finding "type" substrings that indicate AI/Bedrock threats.
_AI_FINDING_HINTS = ("Bedrock", "GenerativeAI", "AISecurity")


def _enabled() -> bool:
    return os.getenv("SPM_GUARDDUTY_ENABLED", "").lower() in ("1", "true", "yes")


def _severity(score: float) -> str:
    # GuardDuty: 1.0-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High (treat >=8.5 critical).
    if score >= 8.5:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _is_ai_finding(f: dict) -> bool:
    ftype = f.get("Type", "")
    if any(h.lower() in ftype.lower() for h in _AI_FINDING_HINTS):
        return True
    # Resource may reference a Bedrock resource type.
    rtype = f.get("Resource", {}).get("ResourceType", "")
    return "Bedrock" in rtype


def _to_finding(f: dict) -> Finding:
    score = float(f.get("Severity", 0) or 0)
    sev = _severity(score)
    ftype = f.get("Type", "guardduty-finding")
    resource = f.get("Resource", {})
    principal = (resource.get("AccessKeyDetails", {}).get("PrincipalId")
                 or resource.get("ResourceType", "")
                 or "guardduty")
    return Finding(
        finding_id=f"guardduty-{f.get('Id', '')}",
        agent_id=f"guardduty-{principal}"[:120],
        severity=sev,
        rule_id=f"guardduty:{ftype}",
        title=(f.get("Title") or ftype)[:200],
        description=(f.get("Description", "") or "GuardDuty AI Protection finding")[:1000],
        remediation="Triage in GuardDuty; verify Bedrock guardrails, invocation logging, and IAM scope.",
        compliance_frameworks=["OWASP_AGENTIC:ASI03", "MITRE_ATLAS", "NIST_AI_RMF"],
        created_at=str(f.get("CreatedAt", datetime.now(timezone.utc).isoformat())),
    )


def ingest(max_findings: int = 100) -> dict:
    """Pull recent GuardDuty AI/Bedrock findings and persist them as SPM findings."""
    if not _enabled():
        return {"integration": "guardduty", "skipped": "SPM_GUARDDUTY_ENABLED not set"}
    try:
        gd = boto3.client("guardduty", region_name=REGION)
        detectors = gd.list_detectors().get("DetectorIds", [])
    except Exception:
        return {"integration": "guardduty", "error": public_error("guardduty init")}
    if not detectors:
        return {"integration": "guardduty", "detectors": 0, "ingested": 0}

    ingested: list[dict] = []
    for det in detectors:
        try:
            ids = gd.list_findings(
                DetectorId=det,
                FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}},
                MaxResults=min(max_findings, 50),
            ).get("FindingIds", [])
            if not ids:
                continue
            findings = gd.get_findings(DetectorId=det, FindingIds=ids).get("Findings", [])
        except Exception as e:
            print(f"[SPM] GuardDuty fetch error ({det}): {e}")
            continue
        for f in findings:
            if not _is_ai_finding(f):
                continue
            sf = _to_finding(f)
            try:
                db.put_finding(asdict(sf))
                ingested.append(asdict(sf))
            except Exception as e:
                print(f"[SPM] GuardDuty persist error: {e}")

    # Fan high-severity findings to event sinks (SNS/EventBridge).
    try:
        alerts = [{"agent_id": f["agent_id"], "event_type": "guardduty_finding",
                   "severity": f["severity"], "details": {"rule_id": f["rule_id"], "title": f["title"]}}
                  for f in ingested if f["severity"] in ("critical", "high")]
        if alerts:
            from spm.integrations import dispatch_events
            dispatch_events(alerts)
    except Exception:
        pass

    return {"integration": "guardduty", "detectors": len(detectors), "ingested": len(ingested)}
