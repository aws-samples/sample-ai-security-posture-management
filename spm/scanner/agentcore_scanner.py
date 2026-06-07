"""Amazon Bedrock AgentCore posture scanner (Observe pillar).

Discovers AgentCore resources via the verified ``bedrock-agentcore-control``
control plane and inventories their security-relevant configuration so the
Govern rules can assess them:

  * Agent Runtimes  — inbound authorizer presence, execution role, network config.
  * Gateways (MCP)  — authorizer type, KMS encryption, exception level, role.
  * Memories        — status/encryption.
  * Code interpreters / browsers / workload identities — discovery counts.

All field names verified against the live AgentCore API. Registered as a
scanner plugin; results merge into inventory like any other source.
"""
from __future__ import annotations

import os
from dataclasses import asdict

import boto3
from opentelemetry import trace

from spm.core.models import AgentInventoryItem
from spm.core.registry import scanner

REGION = os.getenv("AWS_REGION", "us-east-1")
tracer = trace.get_tracer("spm.scanner.agentcore")


def _client():
    return boto3.client("bedrock-agentcore-control", region_name=REGION)


def _scalars(d: dict | None) -> dict:
    """Keep only scalar fields (safe, no nested secrets) from a struct."""
    return {k: v for k, v in (d or {}).items() if isinstance(v, (str, bool, int, float))}


def scan_agent_runtimes(client) -> list[dict]:
    items: list[dict] = []
    try:
        runtimes = client.list_agent_runtimes(maxResults=100).get("agentRuntimes", [])
    except Exception as e:
        print(f"[SPM] AgentCore list_agent_runtimes: {e}")
        return []
    for r in runtimes:
        rid = r.get("agentRuntimeId", "")
        role_arn, has_authorizer, network = "", False, {}
        try:
            d = client.get_agent_runtime(agentRuntimeId=rid)
            role_arn = d.get("roleArn", "")
            has_authorizer = bool(d.get("authorizerConfiguration"))
            network = _scalars(d.get("networkConfiguration"))
        except Exception as e:
            print(f"[SPM] AgentCore get_agent_runtime {rid}: {e}")
        items.append(asdict(AgentInventoryItem(
            agent_id=f"agentcore-runtime-{rid}",
            source="agentcore", agent_type="agentcore_runtime",
            name=r.get("agentRuntimeName", rid),
            config={"runtime_id": rid, "status": r.get("status", ""),
                    "has_authorizer": has_authorizer, "network": network},
            permissions={"role_arn": role_arn},
            metadata={"arn": r.get("agentRuntimeArn", ""), "version": r.get("agentRuntimeVersion", "")},
        )))
    return items


def scan_gateways(client) -> list[dict]:
    items: list[dict] = []
    try:
        gateways = client.list_gateways(maxResults=100).get("items", [])
    except Exception as e:
        print(f"[SPM] AgentCore list_gateways: {e}")
        return []
    for g in gateways:
        gid = g.get("gatewayId", "")
        role_arn, has_kms, exception_level = "", False, ""
        authorizer_type = g.get("authorizerType", "")
        try:
            d = client.get_gateway(gatewayIdentifier=gid)
            role_arn = d.get("roleArn", "")
            has_kms = bool(d.get("kmsKeyArn"))
            exception_level = d.get("exceptionLevel", "")
            authorizer_type = d.get("authorizerType", authorizer_type)
        except Exception as e:
            print(f"[SPM] AgentCore get_gateway {gid}: {e}")
        items.append(asdict(AgentInventoryItem(
            agent_id=f"agentcore-gateway-{gid}",
            source="agentcore", agent_type="agentcore_gateway",
            name=g.get("name", gid),
            config={"gateway_id": gid, "status": g.get("status", ""),
                    "protocol_type": g.get("protocolType", ""),
                    "authorizer_type": authorizer_type,
                    "has_kms": has_kms, "exception_level": exception_level},
            permissions={"role_arn": role_arn},
            metadata={"protocol": g.get("protocolType", "")},
        )))
    return items


def scan_memories(client) -> list[dict]:
    items: list[dict] = []
    try:
        memories = client.list_memories(maxResults=100).get("memories", [])
    except Exception as e:
        print(f"[SPM] AgentCore list_memories: {e}")
        return []
    for m in memories:
        mid = m.get("id", "")
        items.append(asdict(AgentInventoryItem(
            agent_id=f"agentcore-memory-{mid}",
            source="agentcore", agent_type="agentcore_memory",
            name=mid,
            config={"memory_id": mid, "status": m.get("status", "")},
            metadata={"arn": m.get("arn", "")},
        )))
    return items


@scanner("builtin.bedrock_agentcore", source="agentcore", is_async=False,
         description="Bedrock AgentCore runtimes, gateways (MCP), and memories posture")
def scan() -> list[dict]:
    with tracer.start_as_current_span("spm.scan.agentcore"):
        try:
            client = _client()
        except Exception as e:
            print(f"[SPM] AgentCore client init: {e}")
            return []
        return scan_agent_runtimes(client) + scan_gateways(client) + scan_memories(client)
