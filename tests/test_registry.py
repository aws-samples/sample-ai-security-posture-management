"""Tests for the plugin registry and decorators (no third-party deps)."""
from spm.core.registry import (
    DETECTORS, RULES, SCANNERS, SINKS,
    Detection, DetectionContext,
    detector, rule, scanner, finding_sink,
    detectors_for, sinks_for,
)


def test_detector_registration_and_phase_filter():
    @detector("test.pre_only", phases=("pre",))
    def d(ctx):
        return [Detection("x", "low")]

    assert "test.pre_only" in DETECTORS.keys()
    assert any(s.id == "test.pre_only" for s in detectors_for("pre"))
    assert all(s.id != "test.pre_only" for s in detectors_for("post"))


def test_detector_runs_and_returns_detections():
    @detector("test.flagger", phases=("post",))
    def d(ctx):
        return [Detection("flag", "high", {"k": "v"}, block=True)]

    spec = DETECTORS.get("test.flagger")
    out = spec.fn(DetectionContext(phase="post", response_text="hello"))
    assert len(out) == 1 and out[0].event_type == "flag" and out[0].block is True


def test_rule_registration_metadata():
    @rule("test.rule1", "Rule 1", "desc", "high", "key", ["NIST_AI_RMF"])
    def r(agent):
        return None

    spec = RULES.get("test.rule1")
    assert spec.severity == "high" and spec.applies_to == "key"
    assert "NIST_AI_RMF" in spec.compliance and spec.scope == "item"


def test_scanner_and_sink_registration():
    @scanner("test.scan", source="unit")
    def s():
        return []

    @finding_sink("test.sink", kind="events")
    def snk(events):
        return {"ok": True}

    assert SCANNERS.get("test.scan").source == "unit"
    assert any(x.id == "test.sink" for x in sinks_for("events"))


def test_last_registration_wins():
    @detector("test.dup")
    def a(ctx):
        return []

    @detector("test.dup")
    def b(ctx):
        return [Detection("b", "low")]

    spec = DETECTORS.get("test.dup")
    assert spec.fn(DetectionContext()) and spec.fn(DetectionContext())[0].event_type == "b"
