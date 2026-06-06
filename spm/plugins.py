"""Plugin autoloader.

Importing a plugin module is what registers its detectors/rules/scanners/sinks
(the decorators run at import time). This module imports the built-in plugins and
then any third-party modules listed in the ``SPM_PLUGINS`` environment variable
(comma-separated import paths), so AI SPM can be extended without core edits:

    SPM_PLUGINS="acme.spm_detectors,acme.spm_rules"

Call ``load_plugins()`` once at process start (the API and scanners do this).
"""
from __future__ import annotations

import importlib
import logging
import os

logger = logging.getLogger("spm.plugins")

# Built-in plugin modules. Each registers one or more extensions on import.
_BUILTIN_MODULES = [
    "spm.defender.detectors",     # runtime detectors (Defend)
    "spm.defender.guardrails",    # Bedrock Guardrails detector (Defend)
    "spm.engine.rules",           # posture rules (Govern)
    "spm.scanner.builtins",       # discovery scanners (Observe)
    "spm.integrations",           # finding/event sinks (AIDR)
]

_loaded = False


def load_plugins(force: bool = False) -> dict:
    """Import built-in and third-party plugin modules. Idempotent."""
    global _loaded
    if _loaded and not force:
        return {"status": "already_loaded"}

    loaded, failed = [], []

    for mod in _BUILTIN_MODULES:
        try:
            importlib.import_module(mod)
            loaded.append(mod)
        except Exception as e:  # pragma: no cover - a broken builtin shouldn't kill startup
            logger.warning("Failed to load built-in plugin %s: %s", mod, e)
            failed.append({"module": mod, "error": str(e)})

    for path in os.getenv("SPM_PLUGINS", "").split(","):
        path = path.strip()
        if not path:
            continue
        try:
            importlib.import_module(path)
            loaded.append(path)
            logger.info("Loaded third-party plugin: %s", path)
        except Exception as e:
            logger.warning("Failed to load plugin %s: %s", path, e)
            failed.append({"module": path, "error": str(e)})

    _loaded = True
    return {"status": "loaded", "loaded": loaded, "failed": failed}
