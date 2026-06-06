"""Alert correlation engine — merges callback + trace signals into actionable alerts."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict

from opentelemetry import trace

from spm.core import db
from spm.core.models import RuntimeEvent
from spm.defender import trace_analyzer

tracer = trace.get_tracer("spm.defender.alerts")

# Severity escalation: if multiple signals hit the same agent, escalate
ESCALATION = {
    ("prompt_injection", "latency_anomaly"): "critical",
    ("prompt_injection", "new_dependency"): "critical",
    ("rate_limit", "excessive_llm_calls"): "high",
    ("new_dependency", "latency_anomaly"): "high",
}


async def correlate_alerts() -> dict:
    """Run trace analysis, then correlate with recent callback events.

    Groups events by agent_id, looks for multi-signal patterns,
    and generates correlated alerts with escalated severity.
    """
    with tracer.start_as_current_span("spm.defender.correlate"):
        # Step 1: Run trace analyzer to get fresh anomalies
        trace_result = trace_analyzer.analyze_recent_traces()

        # Step 2: Load recent runtime events (from both callback + trace analyzer)
        events, _ = db.list_runtime_events(limit=200)

        # Step 3: Group by agent
        by_agent: dict[str, list[dict]] = defaultdict(list)
        for e in events:
            by_agent[e.get("agent_id", "unknown")].append(e)

        # Step 4: Correlate — look for multi-signal patterns
        correlated = []
        for agent_id, agent_events in by_agent.items():
            event_types = {e.get("event_type") for e in agent_events}
            for (t1, t2), severity in ESCALATION.items():
                if t1 in event_types and t2 in event_types:
                    # Find the trace_ids involved
                    trace_ids = list({e.get("trace_id") for e in agent_events
                                      if e.get("trace_id") and e.get("event_type") in (t1, t2)})
                    alert = RuntimeEvent(
                        agent_id=agent_id,
                        event_type="correlated_alert",
                        severity=severity,
                        trace_id=trace_ids[0] if trace_ids else "",
                        details={
                            "signals": [t1, t2],
                            "event_count": len(agent_events),
                            "trace_ids": trace_ids[:5],
                            "description": f"Multiple threat signals detected: {t1} + {t2}",
                        },
                    )
                    db.put_runtime_event(asdict(alert))
                    correlated.append(asdict(alert))

        return {
            "trace_analysis": trace_result,
            "correlated_alerts": len(correlated),
            "agents_analyzed": len(by_agent),
        }
