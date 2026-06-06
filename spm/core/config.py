"""User-configurable knowledge used by the scanners and policy engine.

The discovery scanners and the ``unexpected_dependency`` policy rule can use
optional, environment-specific knowledge:

* ``KNOWN_WORKFLOWS`` — Temporal workflow types you expect to see, used to flag
  stale (never-executed) workflows and to label workflow roles.
* ``EXPECTED_DEPS`` — the set of downstream services each workflow is allowed to
  call. Any service-graph edge that is *not* in this set raises a finding.

Both default to empty (fully generic discovery). Provide your own values via a
JSON file referenced by the ``SPM_CONFIG_FILE`` environment variable. See
``config/spm-config.example.json`` for the format.
"""
from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("spm.config")

# Example structure (kept empty by default so discovery is environment-agnostic):
#
# {
#   "known_workflows": {
#     "MyWorkflow": {"queue": "my-queue", "type": "orchestrator"}
#   },
#   "expected_dependencies": {
#     "MyWorkflow": ["LLM-Gateway", "Some-External-API"]
#   }
# }

KNOWN_WORKFLOWS: dict[str, dict] = {}
EXPECTED_DEPS: dict[str, set[str]] = {}


def _load() -> None:
    global KNOWN_WORKFLOWS, EXPECTED_DEPS
    path = os.getenv("SPM_CONFIG_FILE", "")
    if not path or not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        KNOWN_WORKFLOWS = data.get("known_workflows", {}) or {}
        EXPECTED_DEPS = {
            name: set(deps)
            for name, deps in (data.get("expected_dependencies", {}) or {}).items()
        }
        logger.info(
            "Loaded SPM config from %s (%d workflows, %d dependency baselines)",
            path,
            len(KNOWN_WORKFLOWS),
            len(EXPECTED_DEPS),
        )
    except Exception as e:  # pragma: no cover - config is best-effort
        logger.warning("Failed to load SPM config from %s: %s", path, e)


_load()
