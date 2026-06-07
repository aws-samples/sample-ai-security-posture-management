"""Built-in discovery scanners, registered as plugins.

The orchestrator iterates the scanner registry, so adding a new discovery source
is just a matter of registering a function that returns a list of inventory item
dicts (each shaped like ``AgentInventoryItem``). X-Ray remains a dedicated
enrichment step (it returns topology + baselines rather than inventory items).
"""
from __future__ import annotations

from spm.core.registry import scanner
from spm.scanner import aws_platform_scanner, litellm_scanner, temporal_scanner
from spm.scanner import bedrock_scanner  # noqa: F401  (registers builtin.bedrock_security)
from spm.scanner import agentcore_scanner  # noqa: F401  (registers builtin.bedrock_agentcore)

scanner("builtin.litellm", source="litellm", is_async=True,
        description="LiteLLM models, keys, spend")(litellm_scanner.scan)

scanner("builtin.temporal", source="temporal", is_async=True,
        description="Temporal workflows + execution stats")(temporal_scanner.scan)

scanner("builtin.aws_platform", source="aws", is_async=False,
        description="Bedrock agents, SageMaker endpoints, AI Lambdas, shadow AI")(aws_platform_scanner.scan)
