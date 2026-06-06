"""Unified discovery orchestrator — runs all scanners, computes deltas, updates inventory."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from opentelemetry import trace

from spm.core import db
from spm.scanner import litellm_scanner, temporal_scanner, xray_scanner
from spm.scanner import aws_platform_scanner

tracer = trace.get_tracer("spm.scanner.orchestrator")


async def run_scan() -> dict:
    """Execute all scanners, merge results, compute deltas, persist to DynamoDB.

    Returns scan summary with counts and deltas.
    """
    with tracer.start_as_current_span("spm.scan.orchestrate"):
        scan_start = datetime.now(timezone.utc).isoformat()

        # Run LiteLLM + Temporal in parallel (async), X-Ray is sync
        litellm_items, temporal_items = await asyncio.gather(
            litellm_scanner.scan(),
            temporal_scanner.scan(),
        )
        xray_data = xray_scanner.scan()
        aws_items = aws_platform_scanner.scan()

        # Enrich temporal items with X-Ray baselines
        baselines = xray_data.get("baselines", {})
        for item in temporal_items:
            wf_name = item.get("name", "")
            # Match by service name patterns
            for svc_name, baseline in baselines.items():
                if wf_name.lower().replace("workflow", "") in svc_name.lower():
                    item["behavioral_baseline"] = baseline
                    break

        # Enrich temporal items with X-Ray topology (dependencies)
        topology = xray_data.get("topology", {})
        edges = topology.get("edges", [])
        for item in temporal_items:
            name = item.get("name", "")
            deps = [e["target"] for e in edges if name.lower().replace("workflow", "") in e.get("source", "").lower()]
            if deps:
                item["dependencies"] = deps

        # Merge all discovered items
        all_items = litellm_items + temporal_items + aws_items
        new_items_map = {i["agent_id"]: i for i in all_items}

        # Load existing inventory for delta computation
        existing = db.list_inventory(limit=500)
        existing_map = {i["agent_id"]: i for i in existing}

        added, updated, removed = [], [], []

        # Detect new and updated
        for agent_id, item in new_items_map.items():
            item["last_seen"] = scan_start
            if agent_id not in existing_map:
                added.append(agent_id)
            else:
                old = existing_map[agent_id]
                if _has_changes(old, item):
                    updated.append(agent_id)
            db.put_inventory(item)

        # Detect removed (in existing but not in new scan)
        for agent_id in existing_map:
            if agent_id not in new_items_map:
                removed.append(agent_id)
                db.delete_inventory(agent_id)

        # Store topology as a special inventory record
        db.put_inventory({
            "agent_id": "topology-snapshot",
            "source": "xray",
            "agent_type": "topology",
            "name": "Service Topology",
            "config": topology,
            "last_seen": scan_start,
            "metadata": {"node_count": len(topology.get("nodes", [])),
                         "edge_count": len(topology.get("edges", []))},
        })

        summary = {
            "scan_time": scan_start,
            "total_discovered": len(all_items),
            "litellm_count": len(litellm_items),
            "temporal_count": len(temporal_items),
            "aws_platform_count": len(aws_items),
            "topology_nodes": len(topology.get("nodes", [])),
            "topology_edges": len(topology.get("edges", [])),
            "delta": {
                "added": added,
                "updated": updated,
                "removed": removed,
            },
        }
        return summary


def _has_changes(old: dict, new: dict) -> bool:
    """Check if an inventory item has meaningful changes."""
    for key in ("config", "permissions", "metadata", "dependencies", "behavioral_baseline"):
        if old.get(key) != new.get(key):
            return True
    return False
