"""Built-in runtime detectors, registered as plugins.

Each detector is a thin adapter around a pure detection function in
``advanced_detectors``. The transparent proxy iterates the detector registry
(pre-phase before the LLM call, post-phase after) so new detectors can be added
without touching the proxy code — define a function decorated with
``@detector(...)`` in your own module and load it via ``SPM_PLUGINS``.
"""
from __future__ import annotations

from spm.core.registry import Detection, DetectionContext, detector
from spm.defender import advanced_detectors as ad


# ---------------- PRE phase (inspect the prompt) ----------------

@detector("builtin.prompt_injection", phases=("pre",),
          description="Regex prompt-injection signatures")
def prompt_injection(ctx: DetectionContext) -> list[Detection]:
    match = ad.check_prompt_injection(ctx.prompt_text)
    if match:
        return [Detection("prompt_injection", "critical",
                          {"pattern": match, "model": ctx.model}, block=True)]
    return []


@detector("builtin.jailbreak", phases=("pre",),
          description="Known jailbreak signatures (DAN, safety-bypass, etc.)")
def jailbreak(ctx: DetectionContext) -> list[Detection]:
    match = ad.detect_jailbreak(ctx.prompt_text)
    if match:
        return [Detection("jailbreak", "critical",
                          {"pattern": match, "model": ctx.model}, block=True)]
    return []


@detector("builtin.system_prompt_extraction", phases=("pre",),
          description="Attempts to extract/leak the system prompt")
def system_prompt_extraction(ctx: DetectionContext) -> list[Detection]:
    match = ad.detect_system_prompt_extraction(ctx.prompt_text)
    if match:
        return [Detection("system_prompt_extraction", "high",
                          {"pattern": match, "model": ctx.model}, block=True)]
    return []


@detector("builtin.memory_poisoning", phases=("pre",),
          description="Injected system messages / role confusion / context stuffing")
def memory_poisoning(ctx: DetectionContext) -> list[Detection]:
    issues = ad.detect_memory_poisoning(ctx.messages)
    return [Detection("memory_poisoning", "high", issue) for issue in issues]


@detector("builtin.rate_limit", phases=("pre",),
          description="Per-key sliding-window rate limiting")
def rate_limit(ctx: DetectionContext) -> list[Detection]:
    if ctx.api_key and ad.check_rate_limit(ctx.api_key):
        return [Detection("rate_limit", "high",
                          {"api_key_suffix": ctx.api_key[-4:], "model": ctx.model}, block=True)]
    return []


@detector("builtin.semantic_injection", phases=("pre",), is_async=True,
          description="Bedrock-powered semantic prompt-injection classification")
async def semantic_injection(ctx: DetectionContext) -> list[Detection]:
    # Only run if the cheap regex detector did not already flag it.
    if ad.check_prompt_injection(ctx.prompt_text) or len(ctx.prompt_text) <= 20:
        return []
    try:
        is_inj, reason = await ad.classify_injection_semantic(ctx.prompt_text)
    except Exception:
        return []
    if is_inj:
        return [Detection("semantic_injection", "critical",
                          {"reason": reason, "model": ctx.model}, block=True)]
    return []


# ---------------- POST phase (inspect the response) ----------------

@detector("builtin.data_exfiltration", phases=("post",),
          description="PII / secrets in the model response")
def data_exfiltration(ctx: DetectionContext) -> list[Detection]:
    pii = ad.scan_response_for_pii(ctx.response_text)
    if pii:
        return [Detection("data_exfiltration", "critical",
                          {"pii_types": pii, "model": ctx.model}, block=True)]
    return []


@detector("builtin.insecure_output", phases=("post",),
          description="Dangerous constructs in output (scripts, exfil links, shell)")
def insecure_output(ctx: DetectionContext) -> list[Detection]:
    dets = ad.detect_insecure_output(ctx.response_text)
    return [Detection("insecure_output", "high", d, block=True) for d in dets]


@detector("builtin.mcp_tool_usage", phases=("post",),
          description="MCP/tool invocations and unknown-tool detection")
def mcp_tool_usage(ctx: DetectionContext) -> list[Detection]:
    dets = ad.detect_mcp_tool_usage(ctx.messages, ctx.response_text)
    return [Detection("mcp_tool_usage", "medium", d) for d in dets]


@detector("builtin.excessive_agency", phases=("post",),
          description="Excessive tool calls / wide tool spread in one turn")
def excessive_agency(ctx: DetectionContext) -> list[Detection]:
    dets = ad.detect_excessive_agency(ctx.messages, ctx.response_text)
    return [Detection("excessive_agency", "high", d) for d in dets]
