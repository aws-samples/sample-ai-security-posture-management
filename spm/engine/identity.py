"""Agent identity / non-human-identity (NHI) privilege analysis.

OWASP Top 10 for Agentic Applications calls out ASI03 (Identity & Privilege
Abuse) as one of the most important agentic risks: agents inheriting broad
credentials or running with over-permissive execution roles. This module
inspects an IAM role attached to an agent (e.g. a Bedrock Agent or AI Lambda)
and flags excessive privilege — AdministratorAccess, wildcard actions, or
wildcard resources.

Results are cached per role ARN for the process lifetime to avoid repeated IAM
calls during evaluation.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache

import boto3

REGION = os.getenv("AWS_REGION", "us-east-1")

_ROLE_ARN_RE = re.compile(r"arn:aws[\w-]*:iam::\d+:role/(.+)")


def _iam():
    return boto3.client("iam", region_name=REGION)


def _role_name(role_arn: str) -> str | None:
    m = _ROLE_ARN_RE.match(role_arn or "")
    return m.group(1).split("/")[-1] if m else None


def _statements(doc) -> list:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except Exception:
            return []
    stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
    return stmts if isinstance(stmts, list) else [stmts]


def _scan_statements(stmts: list) -> dict:
    wildcard_action = wildcard_resource = False
    for s in stmts:
        if not isinstance(s, dict) or s.get("Effect") != "Allow":
            continue
        actions = s.get("Action", [])
        actions = [actions] if isinstance(actions, str) else (actions or [])
        resources = s.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else (resources or [])
        if any(a == "*" or a.endswith(":*") for a in actions):
            wildcard_action = True
        if any(r == "*" for r in resources):
            wildcard_resource = True
    return {"wildcard_action": wildcard_action, "wildcard_resource": wildcard_resource}


@lru_cache(maxsize=512)
def analyze_role_privilege(role_arn: str) -> tuple:
    """Return (findings_tuple) summarizing privilege risk for a role.

    Returns a tuple of (admin: bool, wildcard_action: bool, wildcard_resource: bool,
    error: str). Tuple (hashable) so it can be lru_cached.
    """
    name = _role_name(role_arn)
    if not name:
        return (False, False, False, "no_role")
    admin = wildcard_action = wildcard_resource = False
    try:
        iam = _iam()
        attached = iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])
        for p in attached:
            if p.get("PolicyName") == "AdministratorAccess" or p.get("PolicyArn", "").endswith("/AdministratorAccess"):
                admin = True
            try:
                pol = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]
                ver = iam.get_policy_version(PolicyArn=p["PolicyArn"],
                                             VersionId=pol["DefaultVersionId"])["PolicyVersion"]
                res = _scan_statements(_statements(ver.get("Document", {})))
                wildcard_action = wildcard_action or res["wildcard_action"]
                wildcard_resource = wildcard_resource or res["wildcard_resource"]
            except Exception:
                continue
        for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            try:
                doc = iam.get_role_policy(RoleName=name, PolicyName=pname).get("PolicyDocument", {})
                res = _scan_statements(_statements(doc))
                wildcard_action = wildcard_action or res["wildcard_action"]
                wildcard_resource = wildcard_resource or res["wildcard_resource"]
            except Exception:
                continue
    except Exception as e:
        return (False, False, False, str(e)[:120])
    return (admin, wildcard_action, wildcard_resource, "")
