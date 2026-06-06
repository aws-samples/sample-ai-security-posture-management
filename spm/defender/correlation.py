"""Enhanced multi-agent attack correlation with time-window analysis and attack chain detection."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from spm.core import db
from spm.core.models import RuntimeEvent

# Attack chain patterns: if these event types appear for the same agent within a time window, escalate
ATTACK_CHAINS = [
    {"name": "injection_then_exfil", "sequence": ["prompt_injection", "data_exfiltration"],
     "severity": "critical", "desc": "Injection followed by data exfiltration — active attack"},
    {"name": "injection_then_exfil", "sequence": ["semantic_injection", "data_exfiltration"],
     "severity": "critical", "desc": "Semantic injection followed by data exfiltration"},
    {"name": "memory_then_injection", "sequence": ["memory_poisoning", "prompt_injection"],
     "severity": "critical", "desc": "Memory poisoning followed by injection — staged attack"},
    {"name": "recon_then_escalation", "sequence": ["prompt_injection", "mcp_tool_usage"],
     "severity": "high", "desc": "Injection followed by tool access — lateral movement"},
    {"name": "multi_injection", "sequence": ["prompt_injection", "prompt_injection", "prompt_injection"],
     "severity": "high", "desc": "Repeated injection attempts — persistent attacker"},
    {"name": "rate_then_inject", "sequence": ["rate_limit", "prompt_injection"],
     "severity": "high", "desc": "Rate limit hit then injection — brute force attack"},
]

WINDOW_MINUTES = 10


def correlate_attack_chains() -> list[dict]:
    """Analyze recent events for multi-step attack patterns."""
    events, _ = db.list_runtime_events(limit=500)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)).isoformat()

    # Group recent events by agent
    by_agent: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("timestamp", "") >= cutoff:
            by_agent[e.get("agent_id", "unknown")].append(e)

    # Also group across agents for cross-agent correlation
    all_recent_types = [e.get("event_type") for e in events if e.get("timestamp", "") >= cutoff]

    alerts = []
    # Per-agent chain detection
    for agent_id, agent_events in by_agent.items():
        event_types = [e.get("event_type") for e in agent_events]
        for chain in ATTACK_CHAINS:
            if _sequence_match(event_types, chain["sequence"]):
                trace_ids = [e.get("trace_id") for e in agent_events if e.get("trace_id")]
                alert = RuntimeEvent(
                    agent_id=agent_id,
                    event_type="attack_chain",
                    severity=chain["severity"],
                    details={
                        "chain": chain["name"],
                        "description": chain["desc"],
                        "signals": chain["sequence"],
                        "event_count": len(agent_events),
                        "trace_ids": trace_ids[:5],
                        "window_minutes": WINDOW_MINUTES,
                    },
                )
                alerts.append(asdict(alert))

    # Cross-agent: if >3 different agents have injections in the window, it's coordinated
    agents_with_injections = [a for a, evts in by_agent.items()
                              if any(e.get("event_type") in ("prompt_injection", "semantic_injection") for e in evts)]
    if len(agents_with_injections) >= 3:
        alert = RuntimeEvent(
            agent_id="cross-agent",
            event_type="coordinated_attack",
            severity="critical",
            details={
                "description": f"Injection attempts across {len(agents_with_injections)} agents in {WINDOW_MINUTES}min",
                "affected_agents": agents_with_injections[:10],
                "window_minutes": WINDOW_MINUTES,
            },
        )
        alerts.append(asdict(alert))

    # Persist alerts
    for a in alerts:
        db.put_runtime_event(a)

    return alerts


def _sequence_match(events: list[str], pattern: list[str]) -> bool:
    """Check if pattern appears as a subsequence in events."""
    pi = 0
    for e in events:
        if pi < len(pattern) and e == pattern[pi]:
            pi += 1
    return pi >= len(pattern)
