"""Optional, best-in-class open-source detectors, registered as plugins.

These wrap established OSS security libraries and register **only if the library
is importable**, so the core solution runs with zero extra dependencies and
gains stronger detection when you install the `security` extra:

    pip install "ai-spm[security]"   # presidio-analyzer, presidio-anonymizer, llm-guard

Detectors added when available:
  * oss.presidio_pii        — Microsoft Presidio PII detection on responses
  * oss.llm_guard_injection — ProtectAI LLM Guard ML prompt-injection (DeBERTa)
  * oss.llm_guard_secrets   — ProtectAI LLM Guard secret detection on prompts

Models are loaded lazily on first use and cached. Detection failures degrade to
a no-op so they never break the request path.
"""
from __future__ import annotations

import logging

from spm.core.registry import Detection, DetectionContext, detector

logger = logging.getLogger("spm.oss_detectors")

# ------------------------------------------------------------------
# Microsoft Presidio — high-fidelity PII detection (post phase)
# ------------------------------------------------------------------
try:
    from presidio_analyzer import AnalyzerEngine  # type: ignore
    _PRESIDIO = True
except Exception:
    _PRESIDIO = False

_analyzer = None
_PII_THRESHOLD = 0.5


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        _analyzer = AnalyzerEngine()
    return _analyzer


if _PRESIDIO:
    @detector("oss.presidio_pii", phases=("post",),
              description="Microsoft Presidio PII detection on responses")
    def presidio_pii(ctx: DetectionContext) -> list[Detection]:
        if not ctx.response_text:
            return []
        try:
            results = _get_analyzer().analyze(text=ctx.response_text, language="en")
        except Exception as e:
            logger.warning("Presidio analyze failed: %s", e)
            return []
        entities = sorted({r.entity_type for r in results if r.score >= _PII_THRESHOLD})
        if entities:
            return [Detection("data_exfiltration", "critical",
                              {"engine": "presidio", "pii_types": entities, "model": ctx.model},
                              block=True)]
        return []
    logger.info("Registered oss.presidio_pii")


# ------------------------------------------------------------------
# ProtectAI LLM Guard — ML prompt-injection + secret scanners (pre phase)
# ------------------------------------------------------------------
try:
    from llm_guard.input_scanners import PromptInjection as _LGPromptInjection  # type: ignore
    from llm_guard.input_scanners.prompt_injection import MatchType as _LGMatchType  # type: ignore
    _LLM_GUARD_PI = True
except Exception:
    _LLM_GUARD_PI = False

try:
    from llm_guard.input_scanners import Secrets as _LGSecrets  # type: ignore
    _LLM_GUARD_SECRETS = True
except Exception:
    _LLM_GUARD_SECRETS = False

_pi_scanner = None
_secrets_scanner = None


def _get_pi_scanner():
    global _pi_scanner
    if _pi_scanner is None:
        _pi_scanner = _LGPromptInjection(threshold=0.5, match_type=_LGMatchType.FULL)
    return _pi_scanner


def _get_secrets_scanner():
    global _secrets_scanner
    if _secrets_scanner is None:
        _secrets_scanner = _LGSecrets()
    return _secrets_scanner


if _LLM_GUARD_PI:
    @detector("oss.llm_guard_injection", phases=("pre",),
              description="ProtectAI LLM Guard ML prompt-injection (DeBERTa) classifier")
    def llm_guard_injection(ctx: DetectionContext) -> list[Detection]:
        if not ctx.prompt_text:
            return []
        try:
            _, is_valid, risk = _get_pi_scanner().scan(ctx.prompt_text)
        except Exception as e:
            logger.warning("LLM Guard injection scan failed: %s", e)
            return []
        if not is_valid:
            return [Detection("prompt_injection", "critical",
                              {"engine": "llm_guard", "risk_score": float(risk), "model": ctx.model},
                              block=True)]
        return []
    logger.info("Registered oss.llm_guard_injection")


if _LLM_GUARD_SECRETS:
    @detector("oss.llm_guard_secrets", phases=("pre",),
              description="ProtectAI LLM Guard secret detection on prompts")
    def llm_guard_secrets(ctx: DetectionContext) -> list[Detection]:
        if not ctx.prompt_text:
            return []
        try:
            _, is_valid, risk = _get_secrets_scanner().scan(ctx.prompt_text)
        except Exception as e:
            # Log only the exception type: scanner errors can echo prompt text,
            # which is the very content that may hold a secret.
            logger.warning("LLM Guard scan failed (scanner=%s, error=%s)",
                           "Secrets", type(e).__name__)
            return []
        if not is_valid:
            return [Detection("secret_in_prompt", "high",
                              {"engine": "llm_guard", "risk_score": float(risk), "model": ctx.model},
                              block=True)]
        return []
    logger.info("Registered oss.llm_guard_secrets")
