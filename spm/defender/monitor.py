"""Real-time monitoring loop — polls LiteLLM spend logs + X-Ray traces continuously."""
from __future__ import annotations

import asyncio
import os
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import httpx
from opentelemetry import trace

from spm.core import db
from spm.core.models import RuntimeEvent
from spm.defender.litellm_callback import SPMCallback

LITELLM_URL = os.getenv("LITELLM_URL", "http://localhost:4000")
LITELLM_KEY = os.getenv("LITELLM_KEY", "")
POLL_INTERVAL = int(os.getenv("SPM_POLL_INTERVAL_SEC", "10"))

tracer = trace.get_tracer("spm.defender.monitor")
_cb = SPMCallback()
_seen_ids: set[str] = set()
_running = False


async def poll_litellm_logs():
    """Fetch recent spend logs from LiteLLM and run detection on new entries."""
    global _seen_ids
    since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{LITELLM_URL}/spend/logs",
                headers={"Authorization": f"Bearer {LITELLM_KEY}"},
                params={"start_date": since},
            )
            if resp.status_code != 200:
                return 0
            logs = resp.json()
            if not isinstance(logs, list):
                return 0
    except Exception:
        return 0

    new_count = 0
    for entry in logs:
        log_id = entry.get("request_id", entry.get("id", ""))
        if not log_id or log_id in _seen_ids:
            continue
        _seen_ids.add(log_id)
        # Keep set bounded
        if len(_seen_ids) > 5000:
            _seen_ids = set(list(_seen_ids)[-2500:])

        new_count += 1
        model = entry.get("model", "")
        api_key = entry.get("api_key", "unknown")
        agent_id = f"litellm-key-{api_key[-8:]}" if len(api_key) > 8 else "unknown"
        prompt_tokens = entry.get("prompt_tokens", 0)
        completion_tokens = entry.get("completion_tokens", 0)
        total_tokens = entry.get("total_tokens", 0)
        spend = entry.get("spend", 0)
        call_type = entry.get("call_type", "")
        api_base = entry.get("api_base", "")
        request_tags = entry.get("request_tags", [])

        # Skip healthcheck / non-LLM calls
        if total_tokens == 0 and spend == 0:
            continue
        if call_type in ("health", "healthcheck"):
            continue

        # Check for prompt content if available
        messages = entry.get("messages", [])
        prompt_text = " ".join(
            m.get("content", "") for m in messages if isinstance(m, dict)
        ) if isinstance(messages, list) else ""

        # Run prompt injection detection
        injection = _cb._check_prompt_injection(prompt_text) if prompt_text else None

        # Only log detections from background poller — routine calls are logged by the inline proxy
        if not injection:
            continue

        event = RuntimeEvent(
            agent_id=agent_id,
            event_type="prompt_injection",
            severity="critical",
            details={
                "model": model,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
                "spend": spend,
                "request_id": log_id,
                **({"injection_pattern": injection} if injection else {}),
            },
        )
        db.put_runtime_event(asdict(event))

    return new_count


async def poll_xray_traces():
    """Run trace analyzer for recent anomalies."""
    try:
        from spm.defender.trace_analyzer import analyze_recent_traces
        result = analyze_recent_traces()
        return result.get("anomalies", 0)
    except Exception:
        return 0


_eval_counter = 0
EVAL_EVERY_N = 6   # Evaluation every 6 polls (60s)
SCAN_EVERY_N = 30  # Full scan every 30 polls (5 min)


async def poll_scan():
    """Run full discovery scan periodically."""
    global _eval_counter
    if _eval_counter % SCAN_EVERY_N != 0:
        return None
    try:
        from spm.scanner.orchestrator import run_scan
        result = await run_scan()
        print(f"[SPM Monitor] Scan: {result.get('total_discovered', 0)} agents, "
              f"{len(result.get('delta', {}).get('added', []))} new, "
              f"{len(result.get('delta', {}).get('removed', []))} removed")
        return result
    except Exception as e:
        print(f"[SPM Monitor] Scan error: {e}")
        return None


async def poll_evaluation():
    """Run policy evaluation + privilege escalation + attack correlation periodically."""
    global _eval_counter
    _eval_counter += 1
    if _eval_counter % EVAL_EVERY_N != 0:
        return 0
    try:
        from spm.engine.policy_engine import evaluate_all
        result = await evaluate_all()
        new_findings = result.get("new_findings", 0)

        # Privilege escalation check
        from spm.defender.advanced_detectors import detect_privilege_changes
        priv_changes = await detect_privilege_changes(LITELLM_URL, LITELLM_KEY)
        for change in priv_changes:
            event = RuntimeEvent(
                agent_id=f"litellm-key-{change.get('key', 'unknown')}",
                event_type="privilege_escalation", severity="high",
                details=change,
            )
            db.put_runtime_event(asdict(event))

        # Attack chain correlation
        from spm.defender.correlation import correlate_attack_chains
        chains = correlate_attack_chains()

        if priv_changes or chains:
            print(f"[SPM Monitor] {len(priv_changes)} privilege changes, {len(chains)} attack chains")

        return new_findings
    except Exception as e:
        print(f"[SPM Monitor] Evaluation error: {e}")
        return 0


async def monitor_loop():
    """Main monitoring loop — runs continuously in background."""
    global _running
    if _running:
        return
    _running = True
    print(f"[SPM Monitor] Starting real-time monitoring (poll every {POLL_INTERVAL}s, evaluate every {POLL_INTERVAL * EVAL_EVERY_N}s, scan every {POLL_INTERVAL * SCAN_EVERY_N}s)")

    while _running:
        try:
            with tracer.start_as_current_span("spm.monitor.poll"):
                llm_new = await poll_litellm_logs()
                xray_new = await poll_xray_traces()
                eval_new = await poll_evaluation()
                scan_result = await poll_scan()
                if llm_new > 0 or xray_new > 0 or eval_new > 0:
                    print(f"[SPM Monitor] {llm_new} LLM calls, {xray_new} trace anomalies, {eval_new} new findings")
        except Exception as e:
            print(f"[SPM Monitor] Error: {e}")
        await asyncio.sleep(POLL_INTERVAL)


def stop():
    global _running
    _running = False
