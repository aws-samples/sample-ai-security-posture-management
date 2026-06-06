"""AWS AI platform discovery — Bedrock Agents, SageMaker endpoints, Lambda AI functions."""
from __future__ import annotations

import os
from dataclasses import asdict
from datetime import datetime, timezone

import boto3
from opentelemetry import trace

from spm.core.models import AgentInventoryItem

REGION = os.getenv("AWS_REGION", "us-east-1")
tracer = trace.get_tracer("spm.scanner.aws_platform")

AI_LAYER_KEYWORDS = {"bedrock", "sagemaker", "openai", "anthropic", "langchain", "llama", "huggingface", "torch", "tensorflow"}
AI_ENV_KEYWORDS = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "BEDROCK", "SAGEMAKER_ENDPOINT", "MODEL_ID", "LLM_", "LITELLM"}


def scan_bedrock_agents() -> list[dict]:
    """Discover Bedrock Agents."""
    with tracer.start_as_current_span("spm.scan.bedrock_agents"):
        try:
            client = boto3.client("bedrock-agent", region_name=REGION)
            resp = client.list_agents(maxResults=100)
            items = []
            for a in resp.get("agentSummaries", []):
                item = AgentInventoryItem(
                    agent_id=f"bedrock-agent-{a['agentId']}",
                    source="bedrock", agent_type="bedrock_agent",
                    name=a.get("agentName", ""),
                    config={"agent_id": a["agentId"], "status": a.get("agentStatus", ""),
                            "foundation_model": a.get("foundationModel", "")},
                    metadata={"updated_at": str(a.get("updatedAt", "")),
                              "description": a.get("description", "")},
                )
                items.append(asdict(item))
            return items
        except Exception as e:
            print(f"[SPM] Bedrock agent scan: {e}")
            return []


def scan_sagemaker_endpoints() -> list[dict]:
    """Discover SageMaker endpoints."""
    with tracer.start_as_current_span("spm.scan.sagemaker"):
        try:
            client = boto3.client("sagemaker", region_name=REGION)
            resp = client.list_endpoints(MaxResults=100, StatusEquals="InService")
            items = []
            for ep in resp.get("Endpoints", []):
                item = AgentInventoryItem(
                    agent_id=f"sagemaker-ep-{ep['EndpointName']}",
                    source="sagemaker", agent_type="sagemaker_endpoint",
                    name=ep["EndpointName"],
                    config={"status": ep.get("EndpointStatus", ""),
                            "creation_time": str(ep.get("CreationTime", ""))},
                )
                items.append(asdict(item))
            return items
        except Exception as e:
            print(f"[SPM] SageMaker scan: {e}")
            return []


def scan_lambda_ai_functions() -> list[dict]:
    """Discover Lambda functions that use AI (by layers, env vars, or runtime)."""
    with tracer.start_as_current_span("spm.scan.lambda_ai"):
        try:
            client = boto3.client("lambda", region_name=REGION)
            paginator = client.get_paginator("list_functions")
            items = []
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    if _is_ai_lambda(fn):
                        item = AgentInventoryItem(
                            agent_id=f"lambda-ai-{fn['FunctionName']}",
                            source="lambda", agent_type="lambda_ai",
                            name=fn["FunctionName"],
                            config={"runtime": fn.get("Runtime", ""),
                                    "role": fn.get("Role", ""),
                                    "memory": fn.get("MemorySize", 0),
                                    "timeout": fn.get("Timeout", 0)},
                            permissions={"role_arn": fn.get("Role", "")},
                            metadata={"last_modified": fn.get("LastModified", ""),
                                      "code_size": fn.get("CodeSize", 0)},
                        )
                        items.append(asdict(item))
            return items
        except Exception as e:
            print(f"[SPM] Lambda AI scan: {e}")
            return []


def _is_ai_lambda(fn: dict) -> bool:
    """Check if a Lambda function is AI-related."""
    # Check layers
    for layer in fn.get("Layers", []):
        arn = layer.get("Arn", "").lower()
        if any(kw in arn for kw in AI_LAYER_KEYWORDS):
            return True
    # Check env vars
    env = fn.get("Environment", {}).get("Variables", {})
    for key in env:
        if any(kw in key.upper() for kw in AI_ENV_KEYWORDS):
            return True
    return False


def scan_cloudtrail_shadow_ai(known_principals: set[str] | None = None) -> list[dict]:
    """Detect shadow AI — Bedrock calls from unknown IAM principals."""
    with tracer.start_as_current_span("spm.scan.shadow_ai"):
        try:
            client = boto3.client("cloudtrail", region_name=REGION)
            from datetime import timedelta
            end = datetime.now(timezone.utc)
            start = end - timedelta(hours=6)
            resp = client.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "InvokeModel"}],
                StartTime=start, EndTime=end, MaxResults=50,
            )
            shadow = []
            for event in resp.get("Events", []):
                principal = event.get("Username", "")
                if known_principals and principal not in known_principals:
                    shadow.append(AgentInventoryItem(
                        agent_id=f"shadow-ai-{principal[:40]}",
                        source="cloudtrail", agent_type="shadow_ai",
                        name=f"Shadow AI: {principal}",
                        config={"principal": principal, "event_name": "InvokeModel"},
                        metadata={"event_time": str(event.get("EventTime", "")),
                                  "source_ip": event.get("CloudTrailEvent", "")[:200]},
                    ))
            # Deduplicate by principal
            seen = set()
            unique = []
            for s in shadow:
                pid = s["config"]["principal"]
                if pid not in seen:
                    seen.add(pid)
                    unique.append(asdict(s))
            return unique
        except Exception as e:
            print(f"[SPM] Shadow AI scan: {e}")
            return []


def scan() -> list[dict]:
    """Run all AWS platform discovery."""
    with tracer.start_as_current_span("spm.scan.aws_platform"):
        agents = scan_bedrock_agents()
        endpoints = scan_sagemaker_endpoints()
        lambdas = scan_lambda_ai_functions()
        shadow = scan_cloudtrail_shadow_ai()
        return agents + endpoints + lambdas + shadow
