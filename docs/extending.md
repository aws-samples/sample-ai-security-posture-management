# Extending AI SPM

AI SPM is built around four decorator-based plugin registries, so you can add
capabilities **without modifying core code**. A plugin is just a module that
registers one or more extensions on import; you load it by listing its import
path in the `SPM_PLUGINS` environment variable.

| Extension point | Pillar | Decorator | Registry |
|-----------------|--------|-----------|----------|
| Detector | Defend | `@detector` | `spm.core.registry.DETECTORS` |
| Rule | Govern | `@rule` | `spm.core.registry.RULES` |
| Scanner | Observe | `@scanner` | `spm.core.registry.SCANNERS` |
| Sink | AIDR | `@finding_sink` | `spm.core.registry.SINKS` |

Inspect everything currently registered at runtime: `GET /spm/api/plugins`.

## Loading third-party plugins

```bash
# Comma-separated import paths; modules are imported at startup.
export SPM_PLUGINS="acme.spm_detectors,acme.spm_rules"
uvicorn spm.api.main:app --port 8001
```

The module(s) must be importable on `PYTHONPATH` (e.g. `pip install` your
package, or bake it into the container). Built-in plugins are always loaded.

## Add a detector (Defend)

A detector inspects one request/response and returns `Detection`s. It runs in
the `pre` phase (before the LLM call), the `post` phase (after), or both.

```python
from spm.core.registry import detector, Detection, DetectionContext

@detector("acme.ssn_blocker", phases=("post",),
          description="Block responses containing SSNs")
def ssn_blocker(ctx: DetectionContext) -> list[Detection]:
    import re
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", ctx.response_text):
        return [Detection("ssn_leak", "critical", {"model": ctx.model}, block=True)]
    return []
```

* `block=True` means the request is rejected when the defender is in `enforce`
  mode (logged only in `monitor` mode).
* Async detectors are supported — declare `@detector(..., is_async=True)` and
  make the function `async def` (used e.g. for Bedrock-backed classification).
* The transparent proxy iterates the registry automatically; no proxy edits.

## Add a rule (Govern)

A rule evaluates an inventory item and returns a `Finding` (or `None`).

```python
from spm.core.registry import rule
from spm.core.models import Finding

@rule("acme.prod_key_no_expiry", name="Prod key without expiry",
      description="Production keys must have an expiry",
      severity="high", applies_to="key",
      compliance=["OWASP_LLM_TOP10:LLM06", "NIST_AI_RMF"])
def prod_key_no_expiry(agent: dict):
    if "prod" in agent.get("name", "").lower() and not agent.get("metadata", {}).get("expires"):
        return Finding(agent_id=agent["agent_id"], severity="high",
                       rule_id="acme.prod_key_no_expiry",
                       title=f"Prod key without expiry: {agent.get('name')}",
                       description="Production key has no expiry set.",
                       remediation="Set an expiry on the key.",
                       compliance_frameworks=["OWASP_LLM_TOP10:LLM06", "NIST_AI_RMF"])
    return None
```

`applies_to` is one of `key`, `model`, `workflow`, `agent`, `*` (any), or
`topology`. Topology rules use `scope="topology"` and receive
`(topology, inventory)` returning a list of `Finding`s.

## Add a scanner (Observe)

A scanner returns a list of inventory item dicts (shaped like
`AgentInventoryItem`). It can be sync or async.

```python
from dataclasses import asdict
from spm.core.registry import scanner
from spm.core.models import AgentInventoryItem

@scanner("acme.vertex", source="vertex", is_async=False,
         description="Discover Google Vertex AI agents")
def scan_vertex() -> list[dict]:
    items = []
    # ... call your platform's API ...
    items.append(asdict(AgentInventoryItem(
        agent_id="vertex-agent-123", source="vertex", agent_type="agent",
        name="my-vertex-agent")))
    return items
```

The orchestrator runs every registered scanner on each discovery cycle and
merges the results into the inventory.

## Add a sink (AIDR integration)

A sink exports findings (`kind="findings"`) or runtime events (`kind="events"`)
to an external system.

```python
from spm.core.registry import finding_sink

@finding_sink("acme.slack", kind="events", description="Post alerts to Slack")
def to_slack(events: list[dict]) -> dict:
    import os, json, urllib.request
    url = os.getenv("ACME_SLACK_WEBHOOK", "")
    if not url:
        return {"sink": "acme.slack", "skipped": "no webhook"}
    sent = 0
    for e in events:
        if e.get("severity") in ("critical", "high"):
            req = urllib.request.Request(url, data=json.dumps({"text": str(e)}).encode(),
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            sent += 1
    return {"sink": "acme.slack", "sent": sent}
```

Sinks are invoked by `spm.integrations.dispatch_findings()` /
`dispatch_events()` (findings on demand via the Security Hub sync endpoint;
events automatically from the proxy on high-severity detections).

## Tuning built-ins

Most built-ins read configuration from environment variables (no code changes):

* `SPM_APPROVED_MODELS`, `SPM_REQUIRE_GUARDRAIL` — activate posture rules.
* `SPM_BEDROCK_GUARDRAIL_ID` / `_VERSION` — enable the Bedrock Guardrails detector.
* `SPM_SECURITY_HUB_ENABLED`, `SPM_SNS_TOPIC_ARN`, `SPM_EVENT_BUS_NAME` — enable sinks.
* `SPM_CONFIG_FILE` — supply `known_workflows` / `expected_dependencies` baselines.

To disable a built-in entirely, set its registry entry's `enabled = False` from
your own plugin module at import time, e.g.:

```python
from spm.core.registry import DETECTORS
spec = DETECTORS.get("builtin.mcp_tool_usage")
if spec:
    spec.enabled = False
```
