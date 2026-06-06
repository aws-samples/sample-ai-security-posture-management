"""Temporal discovery scanner — discovers workflows, activities, and execution stats."""
from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone

from opentelemetry import trace
from temporalio.client import Client

from spm.core.config import KNOWN_WORKFLOWS
from spm.core.models import AgentInventoryItem

TEMPORAL_ADDRESS = os.getenv("TEMPORAL_ADDRESS", "localhost:7233")

tracer = trace.get_tracer("spm.scanner.temporal")

# KNOWN_WORKFLOWS is an optional, user-supplied map of expected Temporal
# workflow types (see spm/core/config.py). It is used to label workflow roles
# and to surface workflows that exist in config but have never executed
# (stale-agent detection). It defaults to empty, so discovery works for any
# Temporal deployment without configuration.


async def _get_client() -> Client:
    return await Client.connect(TEMPORAL_ADDRESS)


async def scan_workflows(client: Client | None = None) -> list[dict]:
    """Discover all workflow types and their execution stats."""
    with tracer.start_as_current_span("spm.scan.temporal.workflows"):
        if not client:
            client = await _get_client()

        stats: dict[str, dict] = defaultdict(lambda: {
            "running": 0, "completed": 0, "failed": 0,
            "terminated": 0, "total": 0, "task_queue": "",
        })

        async for wf in client.list_workflows(query=""):
            wf_type = wf.workflow_type or "unknown"
            status_name = wf.status.name if wf.status else "UNKNOWN"
            s = stats[wf_type]
            s["total"] += 1
            s["task_queue"] = wf.task_queue or s.get("task_queue", "")
            if status_name == "RUNNING":
                s["running"] += 1
            elif status_name == "COMPLETED":
                s["completed"] += 1
            elif status_name == "FAILED":
                s["failed"] += 1
            elif status_name in ("TERMINATED", "CANCELED"):
                s["terminated"] += 1

        items = []
        for wf_type, s in stats.items():
            known = KNOWN_WORKFLOWS.get(wf_type, {})
            total = s["total"] or 1
            failure_rate = (s["failed"] / total) * 100

            item = AgentInventoryItem(
                agent_id=f"temporal-wf-{wf_type}",
                source="temporal",
                agent_type=known.get("type", "workflow"),
                name=wf_type,
                config={
                    "task_queue": s["task_queue"] or known.get("queue", ""),
                    "workflow_type": wf_type,
                },
                metadata={
                    "running": s["running"],
                    "completed": s["completed"],
                    "failed": s["failed"],
                    "terminated": s["terminated"],
                    "total_executions": s["total"],
                    "failure_rate_pct": round(failure_rate, 2),
                },
            )
            items.append(asdict(item))

        # Also add entries for known workflows with zero executions (stale detection)
        seen = {i["name"] for i in items}
        for wf_type, info in KNOWN_WORKFLOWS.items():
            if wf_type not in seen:
                item = AgentInventoryItem(
                    agent_id=f"temporal-wf-{wf_type}",
                    source="temporal",
                    agent_type=info.get("type", "workflow"),
                    name=wf_type,
                    config={"task_queue": info["queue"], "workflow_type": wf_type},
                    metadata={"total_executions": 0, "failure_rate_pct": 0},
                )
                items.append(asdict(item))

        return items


async def scan(client: Client | None = None) -> list[dict]:
    """Run full Temporal discovery."""
    with tracer.start_as_current_span("spm.scan.temporal"):
        return await scan_workflows(client)
