"""Optional external red-team integration.

The built-in benchmark (``spm.redteam.runner``) scores the detector registry
against a curated corpus with no external dependencies. For deeper, evolving
adversarial coverage you can point industry red-team frameworks at the SPM
transparent proxy (``/v1/chat/completions``), which exercises the full detection
pipeline:

* **garak** (https://github.com/NVIDIA/garak) — LLM vulnerability scanner.
* **Microsoft PyRIT** (https://github.com/Azure/PyRIT) — risk identification toolkit.

This module provides a thin, optional wrapper around the garak CLI when it is
installed (``pip install "ai-spm[redteam]"``). It is intentionally minimal and
safe: if garak is not present, it returns guidance instead of failing.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

# garak probe specs are comma-separated module[.Class] names. Rejecting anything
# else stops a caller from smuggling extra CLI flags (e.g. "--report_prefix").
_PROBES_RE = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*(,[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*)*$")


def garak_available() -> bool:
    return shutil.which("garak") is not None


def run_garak(rest_endpoint: str | None = None, probes: str = "promptinject,dan",
              timeout_sec: int = 1800) -> dict:
    """Run garak against the SPM proxy (REST generator) if garak is installed.

    rest_endpoint defaults to the local SPM proxy. Returns a summary dict; the
    caller is responsible for providing a valid garak REST generator config if a
    non-default endpoint is used.
    """
    if not _PROBES_RE.fullmatch(probes or ""):
        return {"status": "error", "error": "invalid probes; expected comma-separated garak probe names"}
    if not garak_available():
        return {
            "status": "garak_not_installed",
            "hint": "pip install 'ai-spm[redteam]' then point garak's REST generator "
                    "at the SPM proxy /v1/chat/completions endpoint.",
        }
    endpoint = rest_endpoint or os.getenv("SPM_PROXY_URL", "http://localhost:8001/v1/chat/completions")
    try:
        # Minimal invocation; production use should supply a garak REST config file.
        # Static executable, argument list (no shell), and validated probe names.
        proc = subprocess.run(  # nosec B603
            ["garak", "--model_type", "rest", "--probes", probes],
            capture_output=True, text=True, timeout=timeout_sec,
            env={**os.environ, "SPM_PROXY_URL": endpoint},
        )
        return {"status": "completed", "returncode": proc.returncode,
                "stdout_tail": proc.stdout[-4000:], "stderr_tail": proc.stderr[-2000:]}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "timeout_sec": timeout_sec}
    except Exception as e:
        return {"status": "error", "error": str(e)}
