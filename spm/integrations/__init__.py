"""AIDR integrations (finding/event sinks).

Importing this package registers the built-in sinks. Use ``dispatch_findings``
and ``dispatch_events`` to fan out to every enabled sink of the matching kind.
"""
from __future__ import annotations

from spm.core.registry import sinks_for

# Importing the modules registers their @finding_sink decorators.
from spm.integrations import security_hub  # noqa: F401
from spm.integrations import notifications  # noqa: F401


def dispatch_findings(findings: list[dict]) -> list[dict]:
    """Send findings to every enabled 'findings' sink (e.g. Security Hub)."""
    results = []
    for sink in sinks_for("findings"):
        try:
            results.append(sink.fn(findings))
        except Exception as e:  # pragma: no cover
            results.append({"sink": sink.id, "error": str(e)})
    return results


def dispatch_events(events: list[dict]) -> list[dict]:
    """Send events to every enabled 'events' sink (e.g. SNS, EventBridge)."""
    results = []
    for sink in sinks_for("events"):
        try:
            results.append(sink.fn(events))
        except Exception as e:  # pragma: no cover
            results.append({"sink": sink.id, "error": str(e)})
    return results
