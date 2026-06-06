"""X-Ray discovery scanner — traces, behavioral baselines, and service topology."""
from __future__ import annotations

import os
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import boto3
from opentelemetry import trace

tracer = trace.get_tracer("spm.scanner.xray")

REGION = os.getenv("AWS_REGION", "us-east-1")
LOOKBACK_HOURS = int(os.getenv("SPM_XRAY_LOOKBACK_HOURS", "6"))


def _client():
    return boto3.client("xray", region_name=REGION)


def _time_range() -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=LOOKBACK_HOURS)
    return start, end


# ============================================================
# Service Graph → Topology
# ============================================================

def scan_topology() -> dict:
    """Build agent dependency topology from X-Ray service graph.

    Returns: {
        "nodes": [{"name": ..., "type": ...}],
        "edges": [{"source": ..., "target": ..., "avg_latency_ms": ..., "fault_rate": ...}],
    }
    """
    with tracer.start_as_current_span("spm.scan.xray.topology"):
        xray = _client()
        start, end = _time_range()
        resp = xray.get_service_graph(StartTime=start, EndTime=end)

        nodes, edges = [], []
        for svc in resp.get("Services", []):
            name = svc.get("Name", "unknown")
            svc_type = svc.get("Type", "unknown")
            nodes.append({"name": name, "type": svc_type})

            summary = svc.get("SummaryStatistics", {})
            total_count = summary.get("TotalCount", 0)
            fault_count = summary.get("FaultStatistics", {}).get("TotalCount", 0)
            resp_time = summary.get("TotalResponseTime", 0)
            avg_latency = (resp_time / total_count * 1000) if total_count else 0
            fault_rate = (fault_count / total_count * 100) if total_count else 0

            for edge in svc.get("Edges", []):
                ref_id = edge.get("ReferenceId")
                # Resolve target name from Services list by matching ReferenceId
                target_name = str(ref_id)
                for s2 in resp.get("Services", []):
                    if s2.get("ReferenceId") == ref_id:
                        target_name = s2.get("Name", str(ref_id))
                        break

                e_summary = edge.get("SummaryStatistics", {})
                e_total = e_summary.get("TotalCount", 0)
                e_resp = e_summary.get("TotalResponseTime", 0)
                e_latency = (e_resp / e_total * 1000) if e_total else 0

                edges.append({
                    "source": name,
                    "target": target_name,
                    "avg_latency_ms": round(e_latency, 2),
                    "request_count": e_total,
                    "fault_rate_pct": round(fault_rate, 2),
                })

        return {"nodes": nodes, "edges": edges}


# ============================================================
# Trace Summaries → Per-Agent Behavioral Baselines
# ============================================================

def scan_baselines() -> dict[str, dict]:
    """Compute behavioral baselines per service from recent traces.

    Returns: {
        "service-name": {
            "avg_latency_ms": ..., "p95_latency_ms": ...,
            "avg_token_usage": ..., "avg_llm_calls_per_execution": ...,
            "sample_count": ...,
        }
    }
    """
    with tracer.start_as_current_span("spm.scan.xray.baselines"):
        xray = _client()
        start, end = _time_range()

        # Collect trace summaries
        summaries = []
        paginator = xray.get_paginator("get_trace_summaries")
        for page in paginator.paginate(StartTime=start, EndTime=end, Sampling=False):
            summaries.extend(page.get("TraceSummaries", []))

        if not summaries:
            return {}

        # Group latencies by root service
        service_latencies: dict[str, list[float]] = defaultdict(list)
        trace_ids = [s["Id"] for s in summaries if "Id" in s]

        for s in summaries:
            root = (s.get("Http", {}).get("HttpURL", "") or
                    s.get("EntryPoint", {}).get("Name", "unknown"))
            duration_s = s.get("Duration", 0)
            service_latencies[root].append(duration_s * 1000)

        # Fetch full traces in batches of 5 for span-level analysis
        span_stats: dict[str, dict] = defaultdict(lambda: {
            "llm_calls": [], "token_totals": [],
        })

        for i in range(0, min(len(trace_ids), 50), 5):
            batch = trace_ids[i:i + 5]
            try:
                resp = xray.batch_get_traces(TraceIds=batch)
                for t in resp.get("Traces", []):
                    llm_count = 0
                    token_total = 0
                    root_service = "unknown"
                    for seg in t.get("Segments", []):
                        import json
                        try:
                            doc = json.loads(seg.get("Document", "{}"))
                        except (json.JSONDecodeError, TypeError):
                            continue
                        if doc.get("origin") == "AWS::ECS::Container":
                            root_service = doc.get("name", root_service)
                        # Walk subsegments for LLM spans
                        for sub in doc.get("subsegments", []):
                            _count_llm_spans(sub, llm_count_ref := [0], token_ref := [0])
                            llm_count += llm_count_ref[0]
                            token_total += token_ref[0]
                    span_stats[root_service]["llm_calls"].append(llm_count)
                    span_stats[root_service]["token_totals"].append(token_total)
            except Exception:
                continue

        # Merge into baselines
        baselines = {}
        all_services = set(service_latencies.keys()) | set(span_stats.keys())
        for svc in all_services:
            lats = service_latencies.get(svc, [])
            ss = span_stats.get(svc, {"llm_calls": [], "token_totals": []})
            baselines[svc] = {
                "avg_latency_ms": round(statistics.mean(lats), 2) if lats else 0,
                "p95_latency_ms": round(_percentile(lats, 95), 2) if lats else 0,
                "avg_llm_calls_per_execution": (
                    round(statistics.mean(ss["llm_calls"]), 2) if ss["llm_calls"] else 0
                ),
                "avg_token_usage": (
                    round(statistics.mean(ss["token_totals"]), 2) if ss["token_totals"] else 0
                ),
                "sample_count": len(lats),
            }
        return baselines


def _count_llm_spans(subseg: dict, llm_count: list[int], token_count: list[int]) -> None:
    """Recursively count LLM spans and token usage in subsegments."""
    name = subseg.get("name", "")
    if name.startswith("llm.") or name == "LiteLLM":
        llm_count[0] += 1
        annotations = subseg.get("annotations", {})
        metadata = subseg.get("metadata", {})
        token_count[0] += annotations.get("llm.response_length", 0)
        token_count[0] += annotations.get("llm.prompt_length", 0)
    for child in subseg.get("subsegments", []):
        _count_llm_spans(child, llm_count, token_count)


def _percentile(data: list[float], pct: int) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * pct / 100)
    return sorted_data[min(idx, len(sorted_data) - 1)]


# ============================================================
# Public API
# ============================================================

def scan() -> dict:
    """Run full X-Ray scan. Returns topology + baselines."""
    with tracer.start_as_current_span("spm.scan.xray"):
        topology = scan_topology()
        baselines = scan_baselines()
        return {"topology": topology, "baselines": baselines}
