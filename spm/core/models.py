"""Core data models for AI Security Posture Management."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Source(str, Enum):
    LITELLM = "litellm"
    TEMPORAL = "temporal"
    XRAY = "xray"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ComplianceFramework(str, Enum):
    OWASP_LLM_TOP10 = "OWASP_LLM_TOP10"
    NIST_AI_RMF = "NIST_AI_RMF"
    MITRE_ATLAS = "MITRE_ATLAS"


class DefenderMode(str, Enum):
    MONITOR = "monitor"
    ENFORCE = "enforce"


# --- Nested value objects ---

@dataclass
class BehavioralBaseline:
    avg_latency_ms: float = 0.0
    avg_token_usage: float = 0.0
    avg_llm_calls_per_execution: float = 0.0
    p95_latency_ms: float = 0.0
    sample_count: int = 0


@dataclass
class TopologyEdge:
    target: str = ""
    relationship_type: str = ""  # calls, feeds_data, triggers
    avg_latency_ms: float = 0.0


@dataclass
class PolicyRule:
    rule_id: str = ""
    description: str = ""
    severity: str = "medium"
    enabled: bool = True


# --- Top-level entities ---

@dataclass
class AgentInventoryItem:
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = ""  # litellm | temporal | xray
    agent_type: str = ""  # model, key, workflow, activity
    name: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    permissions: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0  # 0-100
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    owner: str = ""
    dependencies: list[str] = field(default_factory=list)
    behavioral_baseline: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Finding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    severity: str = "medium"  # critical | high | medium | low
    rule_id: str = ""
    title: str = ""
    description: str = ""
    status: str = "open"  # open | acknowledged | resolved
    remediation: str = ""
    compliance_frameworks: list[str] = field(default_factory=list)
    trace_id: str = ""  # optional X-Ray trace link
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Policy:
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    rules: list[dict[str, Any]] = field(default_factory=list)
    enabled: bool = True
    compliance_framework: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class RuntimeEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    event_type: str = ""  # llm_call, prompt_injection, anomaly, rate_limit
    trace_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict[str, Any] = field(default_factory=dict)
    severity: str = "low"
    ttl: int = 0  # epoch seconds for DynamoDB TTL


@dataclass
class AgentTopology:
    agent_id: str = ""
    edges: list[dict[str, Any]] = field(default_factory=list)
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
