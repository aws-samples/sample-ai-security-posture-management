"""Plugin registries that make AI SPM extensible by design.

AI SPM has four extension points, each a small decorator-based registry:

  * detectors  -> runtime threat detectors            (Defend pillar)
  * rules      -> posture policy rules                 (Govern pillar)
  * scanners   -> discovery sources                    (Observe pillar)
  * sinks      -> finding / event exporters            (AIDR integrations)

You add a capability by decorating a function in your own module and making sure
the module gets imported. Built-in plugins are imported by ``spm.plugins``;
third-party plugins are imported from the comma-separated ``SPM_PLUGINS``
environment variable — so you can extend AI SPM without modifying core code.

Example (a custom detector in your own package)::

    from spm.core.registry import detector, Detection

    @detector("my_org.secret_scanner", phases=("post",))
    def scan_secrets(ctx):
        if "BEGIN RSA PRIVATE KEY" in ctx.response_text:
            return [Detection("private_key_leak", "critical",
                              {"model": ctx.model}, block=True)]
        return []

Then run with ``SPM_PLUGINS=my_org.detectors`` and it is live — no core edits.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger("spm.registry")


# ============================================================
# Generic registry
# ============================================================

class Registry:
    """A simple name -> entry registry. Last registration wins (override-friendly)."""

    def __init__(self, name: str):
        self.name = name
        self._entries: dict[str, Any] = {}

    def add(self, key: str, value: Any) -> Any:
        if key in self._entries:
            logger.info("Registry %s: overriding existing entry '%s'", self.name, key)
        self._entries[key] = value
        return value

    def get(self, key: str) -> Any | None:
        return self._entries.get(key)

    def remove(self, key: str) -> None:
        self._entries.pop(key, None)

    def keys(self) -> list[str]:
        return list(self._entries)

    def values(self) -> list[Any]:
        return list(self._entries.values())

    def items(self):
        return list(self._entries.items())

    def __len__(self) -> int:
        return len(self._entries)


# ============================================================
# Detectors (Defend)
# ============================================================

@dataclass
class DetectionContext:
    """Everything a detector needs to inspect one request/response."""
    phase: str = "pre"                       # "pre" (before LLM) or "post" (after)
    agent_id: str = ""
    api_key: str = ""
    model: str = ""
    mode: str = "monitor"                    # "monitor" | "enforce"
    messages: list = field(default_factory=list)
    prompt_text: str = ""
    response_text: str = ""
    usage: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)


@dataclass
class Detection:
    """A single finding produced by a detector at runtime."""
    event_type: str
    severity: str = "medium"                 # critical | high | medium | low
    details: dict = field(default_factory=dict)
    block: bool = False                      # block this request when mode == enforce


@dataclass
class DetectorSpec:
    id: str
    fn: Callable[[DetectionContext], list[Detection]]
    phases: set[str] = field(default_factory=lambda: {"pre"})
    enabled: bool = True
    description: str = ""
    is_async: bool = False


DETECTORS = Registry("detectors")


def detector(id: str, phases: tuple[str, ...] = ("pre",), description: str = "",
             is_async: bool = False) -> Callable:
    """Register a runtime detector. The function takes a DetectionContext and
    returns a list of Detection objects."""
    def deco(fn: Callable[[DetectionContext], list[Detection]]):
        DETECTORS.add(id, DetectorSpec(id=id, fn=fn, phases=set(phases),
                                       description=description, is_async=is_async))
        return fn
    return deco


def detectors_for(phase: str) -> list[DetectorSpec]:
    return [d for d in DETECTORS.values() if d.enabled and phase in d.phases]


# ============================================================
# Rules (Govern)
# ============================================================

@dataclass
class RuleSpec:
    rule_id: str
    name: str
    description: str
    severity: str
    applies_to: str                          # key | model | workflow | agent | topology | *
    compliance: list[str] = field(default_factory=list)
    scope: str = "item"                      # "item" (per agent) or "topology"
    fn: Callable = None                      # item: (agent)->Finding|None ; topology: (topology, inventory)->list[Finding]
    enabled: bool = True


RULES = Registry("rules")


def rule(rule_id: str, name: str, description: str, severity: str, applies_to: str,
         compliance: list[str] | None = None, scope: str = "item") -> Callable:
    """Register a Govern policy rule."""
    def deco(fn: Callable):
        RULES.add(rule_id, RuleSpec(rule_id=rule_id, name=name, description=description,
                                    severity=severity, applies_to=applies_to,
                                    compliance=compliance or [], scope=scope, fn=fn))
        return fn
    return deco


# ============================================================
# Scanners (Observe)
# ============================================================

@dataclass
class ScannerSpec:
    id: str
    source: str
    fn: Callable                             # () -> list[dict] (sync or async)
    enabled: bool = True
    is_async: bool = False
    description: str = ""


SCANNERS = Registry("scanners")


def scanner(id: str, source: str, is_async: bool = False, description: str = "") -> Callable:
    """Register a discovery scanner that returns a list of inventory item dicts."""
    def deco(fn: Callable):
        SCANNERS.add(id, ScannerSpec(id=id, source=source, fn=fn,
                                     is_async=is_async, description=description))
        return fn
    return deco


# ============================================================
# Sinks (AIDR integrations)
# ============================================================

@dataclass
class SinkSpec:
    id: str
    fn: Callable                             # (items: list[dict]) -> dict
    kind: str = "findings"                   # "findings" | "events"
    enabled: bool = True
    description: str = ""


SINKS = Registry("sinks")


def finding_sink(id: str, kind: str = "findings", description: str = "") -> Callable:
    """Register an exporter that pushes findings/events to an external system
    (e.g. AWS Security Hub, SNS, EventBridge)."""
    def deco(fn: Callable):
        SINKS.add(id, SinkSpec(id=id, fn=fn, kind=kind, description=description))
        return fn
    return deco


def sinks_for(kind: str) -> list[SinkSpec]:
    return [s for s in SINKS.values() if s.enabled and s.kind == kind]
