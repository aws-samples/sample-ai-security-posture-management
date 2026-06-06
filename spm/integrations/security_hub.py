"""AWS Security Hub finding exporter (AIDR integration), registered as a sink.

Converts SPM findings to ASFF (AWS Security Finding Format) and imports them via
``BatchImportFindings`` so AI agent risks show up alongside the rest of your
security posture in Security Hub. Enable with::

    SPM_SECURITY_HUB_ENABLED=true
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import boto3

from spm.core.registry import finding_sink

REGION = os.getenv("AWS_REGION", "us-east-1")

_SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
_SEVERITY_SCORE = {"critical": 90, "high": 70, "medium": 40, "low": 10}


def _enabled() -> bool:
    return os.getenv("SPM_SECURITY_HUB_ENABLED", "").lower() in ("1", "true", "yes")


def _to_asff(finding: dict, account: str, region: str) -> dict:
    sev = finding.get("severity", "low")
    fid = finding.get("finding_id", "unknown")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    product_arn = f"arn:aws:securityhub:{region}:{account}:product/{account}/default"
    return {
        "SchemaVersion": "2018-10-08",
        "Id": fid,
        "ProductArn": product_arn,
        "GeneratorId": f"ai-spm/{finding.get('rule_id', 'rule')}",
        "AwsAccountId": account,
        "Types": ["Software and Configuration Checks/AI Security Posture"],
        "CreatedAt": finding.get("created_at", now),
        "UpdatedAt": now,
        "Severity": {"Label": _SEVERITY_LABEL.get(sev, "LOW"),
                     "Normalized": _SEVERITY_SCORE.get(sev, 10)},
        "Title": (finding.get("title") or finding.get("rule_id", "AI SPM finding"))[:256],
        "Description": (finding.get("description", ""))[:1024] or "AI SPM finding",
        "Remediation": {"Recommendation": {"Text": (finding.get("remediation", "") or "Review the finding.")[:512]}},
        "ProductFields": {
            "ai-spm/rule_id": str(finding.get("rule_id", "")),
            "ai-spm/agent_id": str(finding.get("agent_id", "")),
            "ai-spm/compliance": ",".join(finding.get("compliance_frameworks", []))[:1000],
        },
        "Resources": [{
            "Type": "Other",
            "Id": finding.get("agent_id", "unknown-agent"),
            "Partition": "aws",
            "Region": region,
        }],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW" if finding.get("status") == "open" else "RESOLVED"},
    }


@finding_sink("security_hub", kind="findings",
              description="Export findings to AWS Security Hub as ASFF")
def export_findings(findings: list[dict]) -> dict:
    if not _enabled():
        return {"sink": "security_hub", "skipped": "SPM_SECURITY_HUB_ENABLED not set"}
    try:
        account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
        sh = boto3.client("securityhub", region_name=REGION)
    except Exception as e:
        return {"sink": "security_hub", "error": f"init failed: {e}"}

    asff = [_to_asff(f, account, REGION) for f in findings if f.get("finding_id")]
    imported, failed = 0, 0
    for i in range(0, len(asff), 100):  # BatchImportFindings max 100
        batch = asff[i:i + 100]
        try:
            resp = sh.batch_import_findings(Findings=batch)
            imported += resp.get("SuccessCount", 0)
            failed += resp.get("FailedCount", 0)
        except Exception as e:
            failed += len(batch)
            print(f"[SPM] Security Hub import error: {e}")
    return {"sink": "security_hub", "imported": imported, "failed": failed}
