"""LiteLLM custom callback — runtime monitoring + inline blocking (Defend pillar).

Register in LiteLLM config:
  litellm_settings:
    callbacks: ["spm.defender.litellm_callback.SPMCallback"]
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from litellm.integrations.custom_logger import CustomLogger

from spm.core import db
from spm.core.models import RuntimeEvent

# Prompt injection patterns (common attack signatures)
INJECTION_PATTERNS = [
    # --- Original: Direct instruction override ---
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"ignore\s+(all\s+|the\s+)?above\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+)?prior", re.I),
    re.compile(r"do\s+anything\s+now", re.I),
    re.compile(r"jailbreak", re.I),

    # --- Role hijacking ---
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.I),
    re.compile(r"switch\s+to\s+\w+\s+mode", re.I),
    re.compile(r"enter\s+\w+\s+mode", re.I),
    re.compile(r"activate\s+\w+\s+mode", re.I),
    re.compile(r"developer\s+mode", re.I),
    re.compile(r"god\s+mode", re.I),

    # --- Prompt leaking ---
    re.compile(r"repeat\s+(everything|all|the\s+text)\s+(above|before)", re.I),
    re.compile(r"(print|output|show|reveal|display)\s+(me\s+)?(your|the)\s+(system\s+prompt|instructions|initial\s+prompt)", re.I),
    re.compile(r"what\s+(are|were)\s+your\s+(initial|original|system)\s+instructions", re.I),
    re.compile(r"(show|tell)\s+me\s+your\s+(prompt|instructions|rules)", re.I),

    # --- Token smuggling / encoding ---
    re.compile(r"<\|im_start\|>system", re.I),
    re.compile(r"\[INST\].*\[/INST\]", re.I),
    re.compile(r"\[SYSTEM\]", re.I),
    re.compile(r"system\s*:\s*you\s+are", re.I),

    # --- Indirect injection (hidden in data) ---
    re.compile(r"override\s*:\s*ignore", re.I),
    re.compile(r"actually,?\s+(disregard|ignore|forget)", re.I),

    # --- Resource abuse ---
    re.compile(r"(write|generate)\s+\w*\s*\d{4,}\s+word", re.I),
]

# Rate limiting state (in-memory, per-process)
_rate_counts: dict[str, list[float]] = defaultdict(list)
RATE_WINDOW_SEC = 60


class SPMCallback(CustomLogger):
    """LiteLLM callback for AI SPM runtime monitoring and enforcement."""

    def _get_mode(self) -> str:
        try:
            policy = db.get_policy("defender-config")
            return policy.get("config", {}).get("mode", "monitor") if policy else "monitor"
        except Exception:
            return "monitor"

    def _get_bypass_keys(self) -> list[str]:
        try:
            policy = db.get_policy("defender-config")
            return policy.get("config", {}).get("bypass_keys", []) if policy else []
        except Exception:
            return []

    def _extract_prompt_text(self, kwargs: dict) -> str:
        messages = kwargs.get("messages", [])
        return " ".join(m.get("content", "") for m in messages if isinstance(m, dict))

    def _check_prompt_injection(self, text: str) -> str | None:
        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                return pattern.pattern
        return None

    def _check_rate_limit(self, api_key: str, rpm_limit: int = 60) -> bool:
        now = time.time()
        window = _rate_counts[api_key]
        # Prune old entries
        _rate_counts[api_key] = [t for t in window if now - t < RATE_WINDOW_SEC]
        _rate_counts[api_key].append(now)
        return len(_rate_counts[api_key]) > rpm_limit

    def _store_event(self, event_type: str, severity: str, agent_id: str,
                     details: dict, trace_id: str = "") -> None:
        try:
            event = RuntimeEvent(
                agent_id=agent_id, event_type=event_type,
                severity=severity, trace_id=trace_id, details=details,
            )
            db.put_runtime_event(asdict(event))
        except Exception as e:
            print(f"[SPM] Failed to store runtime event: {e}")

    # --- LiteLLM callback hooks ---

    async def async_pre_call_hook(self, user_api_key_dict: dict, cache, data: dict, call_type: str):
        """Called BEFORE the LLM request — can block in enforce mode."""
        api_key = user_api_key_dict.get("api_key", user_api_key_dict.get("token", "unknown"))
        agent_id = f"litellm-key-{api_key[-8:]}" if len(api_key) > 8 else "unknown"
        mode = self._get_mode()

        # Skip bypass keys
        if api_key in self._get_bypass_keys():
            return data

        prompt_text = self._extract_prompt_text(data)

        # Check 1: Prompt injection
        injection_match = self._check_prompt_injection(prompt_text)
        if injection_match:
            self._store_event(
                "prompt_injection", "critical", agent_id,
                {"pattern": injection_match, "model": data.get("model", ""),
                 "prompt_length": len(prompt_text)},
            )
            if mode == "enforce":
                from litellm.exceptions import RejectedRequestError
                raise RejectedRequestError(
                    message="Request blocked by AI SPM: prompt injection detected",
                    model=data.get("model", ""), llm_provider="spm",
                )

        # Check 2: Rate limiting
        if self._check_rate_limit(api_key):
            self._store_event(
                "rate_limit", "high", agent_id,
                {"api_key_suffix": api_key[-4:], "model": data.get("model", "")},
            )
            if mode == "enforce":
                from litellm.exceptions import RejectedRequestError
                raise RejectedRequestError(
                    message="Request blocked by AI SPM: rate limit exceeded",
                    model=data.get("model", ""), llm_provider="spm",
                )

        return data

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Log successful LLM calls as runtime events."""
        try:
            api_key = kwargs.get("litellm_params", {}).get("api_key", "unknown")
            agent_id = f"litellm-key-{api_key[-8:]}" if len(api_key) > 8 else "unknown"
            model = kwargs.get("model", "")
            prompt_text = self._extract_prompt_text(kwargs)

            usage = getattr(response_obj, "usage", None)
            prompt_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
            completion_tokens = getattr(usage, "completion_tokens", 0) if usage else 0
            latency_ms = (end_time - start_time).total_seconds() * 1000 if start_time and end_time else 0

            self._store_event(
                "llm_call", "low", agent_id,
                {"model": model, "prompt_tokens": prompt_tokens,
                 "completion_tokens": completion_tokens,
                 "latency_ms": round(latency_ms, 2),
                 "prompt_length": len(prompt_text)},
            )
        except Exception as e:
            print(f"[SPM] Error logging success event: {e}")

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Log failed LLM calls."""
        try:
            api_key = kwargs.get("litellm_params", {}).get("api_key", "unknown")
            agent_id = f"litellm-key-{api_key[-8:]}" if len(api_key) > 8 else "unknown"
            error = str(response_obj) if response_obj else "unknown error"
            self._store_event(
                "llm_failure", "medium", agent_id,
                {"model": kwargs.get("model", ""), "error": error[:500]},
            )
        except Exception as e:
            print(f"[SPM] Error logging failure event: {e}")
