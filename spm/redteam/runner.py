"""Run the red-team corpus against the live detector registry and score defenses.

Produces an objective, reproducible "defense effectiveness" report:
  * detection_rate   — % of malicious cases caught (recall)
  * false_positive_rate — % of benign controls wrongly flagged
  * effectiveness_score — detection_rate adjusted down by false positives
  * per-category breakdown and per-case results

This runs entirely against the registered detectors (built-in + OSS + any
SPM_PLUGINS) with no external API calls, so the score reflects this exact
deployment's posture.
"""
from __future__ import annotations

from collections import defaultdict

from spm.core.registry import DetectionContext, detectors_for
from spm.plugins import load_plugins
from spm.redteam.corpus import CORPUS


async def _evaluate_case(case: dict) -> list:
    phase = case.get("phase", "pre")
    messages = case.get("messages", [])
    if not messages and phase == "pre":
        messages = [{"role": "user", "content": case.get("text", "")}]
    ctx = DetectionContext(
        phase=phase,
        agent_id="redteam",
        model="redteam",
        mode="monitor",
        messages=messages,
        prompt_text=case.get("text", "") if phase == "pre" else "",
        response_text=case.get("text", "") if phase == "post" else "",
    )
    detections = []
    for spec in detectors_for(phase):
        try:
            dets = await spec.fn(ctx) if spec.is_async else spec.fn(ctx)
        except Exception:
            dets = []
        detections.extend(dets or [])
    return detections


async def run_benchmark(corpus: list[dict] | None = None) -> dict:
    """Execute the benchmark and return a scorecard."""
    load_plugins()
    cases = corpus if corpus is not None else CORPUS

    results = []
    by_cat = defaultdict(lambda: {"total": 0, "caught": 0})
    malicious_total = caught = benign_total = false_pos = 0

    for case in cases:
        detections = await _evaluate_case(case)
        flagged = len(detections) > 0
        cat = case.get("category", "unknown")
        results.append({
            "id": case.get("id"),
            "category": cat,
            "malicious": case.get("malicious", True),
            "flagged": flagged,
            "events": [d.event_type for d in detections],
        })
        if case.get("malicious", True):
            malicious_total += 1
            by_cat[cat]["total"] += 1
            if flagged:
                caught += 1
                by_cat[cat]["caught"] += 1
        else:
            benign_total += 1
            if flagged:
                false_pos += 1

    detection_rate = round(100 * caught / malicious_total, 1) if malicious_total else 0.0
    fp_rate = round(100 * false_pos / benign_total, 1) if benign_total else 0.0
    # Effectiveness: recall penalized by the false-positive rate.
    effectiveness = round(max(0.0, detection_rate * (1 - fp_rate / 100)), 1)

    category_scores = {
        cat: {"caught": v["caught"], "total": v["total"],
              "rate": round(100 * v["caught"] / v["total"], 1) if v["total"] else 0.0}
        for cat, v in by_cat.items()
    }

    return {
        "summary": {
            "malicious_cases": malicious_total,
            "caught": caught,
            "detection_rate_pct": detection_rate,
            "benign_cases": benign_total,
            "false_positives": false_pos,
            "false_positive_rate_pct": fp_rate,
            "effectiveness_score": effectiveness,
            "active_detectors": len(detectors_for("pre")) + len(detectors_for("post")),
        },
        "by_category": category_scores,
        "cases": results,
    }
