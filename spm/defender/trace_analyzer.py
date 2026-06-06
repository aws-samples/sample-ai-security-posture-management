"""X-Ray trace analyzer — behavioral monitoring for the Defend pillar.

Uses a learned baseline approach: edges seen in the first scan are considered
normal. Only genuinely new edges (never seen before) trigger alerts.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import boto3
from opentelemetry import trace

from spm.core import db
from spm.core.models import RuntimeEvent

REGION = os.getenv("AWS_REGION", "us-east-1")
LOOKBACK_MIN = int(os.getenv("SPM_TRACE_LOOKBACK_MIN", "15"))
# Optional comma-separated list of service-name substrings. When set, only edges
# touching one of these services raise "new_dependency" alerts (reduces noise
# from unrelated infrastructure). When empty, all newly-seen edges alert.
_MONITORED = [s.strip().lower() for s in os.getenv("SPM_MONITORED_SERVICES", "").split(",") if s.strip()]
tracer = trace.get_tracer("spm.defender.trace_analyzer")

# In-memory set of all edges we've ever seen — anything in here is "normal"
_known_edges: set[tuple[str, str]] = set()
_baseline_loaded = False


def _client():
    return boto3.client("xray", region_name=REGION)


def _load_known_edges():
    """Load known edges from the topology snapshot in inventory."""
    global _known_edges, _baseline_loaded
    if _baseline_loaded:
        return
    try:
        topo = db.get_inventory("topology-snapshot")
        if topo:
            for edge in topo.get("config", {}).get("edges", []):
                _known_edges.add((edge.get("source", ""), edge.get("target", "")))
    except Exception:
        pass
    _baseline_loaded = True


def analyze_recent_traces() -> dict:
    """Poll X-Ray for recent traces and detect anomalies.

    Only alerts on:
    1. Edges never seen before in any previous scan (genuinely new connections)
    2. Latency anomalies (>3x baseline average)
    """
    with tracer.start_as_current_span("spm.defender.trace_analyze"):
        _load_known_edges()

        xray = _client()
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=LOOKBACK_MIN)

        summaries = []
        try:
            paginator = xray.get_paginator("get_trace_summaries")
            for page in paginator.paginate(StartTime=start, EndTime=end, Sampling=False):
                summaries.extend(page.get("TraceSummaries", []))
        except Exception:
            return {"analyzed": 0, "anomalies": 0}

        if not summaries:
            return {"analyzed": 0, "anomalies": 0}

        baselines = _load_baselines()
        trace_ids = [s["Id"] for s in summaries if "Id" in s]
        anomalies = []

        for i in range(0, min(len(trace_ids), 50), 5):
            batch = trace_ids[i:i + 5]
            try:
                resp = xray.batch_get_traces(TraceIds=batch)
            except Exception:
                continue

            for t in resp.get("Traces", []):
                tid = t.get("Id", "")
                edges, spans = _extract_trace_info(t)

                # Learn all edges we see — add to known set
                for src, tgt in edges:
                    edge_key = (src, tgt)
                    if edge_key not in _known_edges:
                        _known_edges.add(edge_key)
                        # Only alert if baseline was already loaded (not first run)
                        if _baseline_loaded and _is_monitored_edge(src, tgt):
                            event = RuntimeEvent(
                                agent_id=f"trace-{src}",
                                event_type="new_dependency",
                                severity="high",
                                trace_id=tid,
                                details={"source": src, "target": tgt,
                                         "message": f"New connection detected: {src} → {tgt}"},
                            )
                            db.put_runtime_event(asdict(event))
                            anomalies.append(asdict(event))

                # Latency anomalies
                for span_name, latency_ms in spans:
                    baseline = baselines.get(span_name, {})
                    avg = baseline.get("avg_latency_ms", 0)
                    if avg > 0 and latency_ms > avg * 5:  # 5x threshold (was 3x, too noisy)
                        event = RuntimeEvent(
                            agent_id=f"trace-{span_name}",
                            event_type="latency_anomaly",
                            severity="medium",
                            trace_id=tid,
                            details={"span": span_name,
                                     "latency_ms": round(latency_ms, 2),
                                     "baseline_avg_ms": round(avg, 2)},
                        )
                        db.put_runtime_event(asdict(event))
                        anomalies.append(asdict(event))

        return {"analyzed": len(trace_ids[:50]), "anomalies": len(anomalies),
                "known_edges": len(_known_edges)}


def _is_monitored_edge(source: str, target: str) -> bool:
    """Whether an edge should raise an alert.

    If SPM_MONITORED_SERVICES is configured, only edges touching one of those
    services alert. Otherwise every newly-seen edge alerts.
    """
    if not _MONITORED:
        return True
    s = source.lower()
    t = target.lower()
    return any(m in s or m in t for m in _MONITORED)


def _load_baselines() -> dict:
    items = db.list_inventory(source="temporal", limit=100)
    baselines = {}
    for item in items:
        bl = item.get("behavioral_baseline", {})
        if bl:
            baselines[item.get("name", "")] = bl
    return baselines


def _extract_trace_info(trace_data: dict) -> tuple[list, list]:
    edges, spans = [], []
    for seg in trace_data.get("Segments", []):
        try:
            doc = json.loads(seg.get("Document", "{}"))
        except (json.JSONDecodeError, TypeError):
            continue
        name = doc.get("name", "unknown")
        duration = doc.get("end_time", 0) - doc.get("start_time", 0)
        if duration > 0:
            spans.append((name, duration * 1000))
        _walk_subsegments(doc, name, edges, spans)
    return edges, spans


def _walk_subsegments(doc: dict, parent: str, edges: list, spans: list) -> None:
    for sub in doc.get("subsegments", []):
        child = sub.get("name", "unknown")
        edges.append((parent, child))
        duration = sub.get("end_time", 0) - sub.get("start_time", 0)
        if duration > 0:
            spans.append((child, duration * 1000))
        _walk_subsegments(sub, child, edges, spans)
