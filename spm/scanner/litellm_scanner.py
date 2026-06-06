"""LiteLLM discovery scanner — discovers models, keys, and spend from LiteLLM admin API."""
from __future__ import annotations

import os
from dataclasses import asdict
from datetime import datetime, timezone

import httpx
from opentelemetry import trace

from spm.core.models import AgentInventoryItem

LITELLM_URL = os.getenv("LITELLM_URL", "http://localhost:4000")
LITELLM_KEY = os.getenv("LITELLM_KEY", "")

tracer = trace.get_tracer("spm.scanner.litellm")


async def _get(path: str) -> dict | list:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{LITELLM_URL}{path}",
            headers={"Authorization": f"Bearer {LITELLM_KEY}"},
        )
        resp.raise_for_status()
        return resp.json()


async def scan_models() -> list[dict]:
    """Discover all models registered in LiteLLM."""
    with tracer.start_as_current_span("spm.scan.litellm.models"):
        data = await _get("/model/info")
        models = data.get("data", []) if isinstance(data, dict) else data
        items = []
        for m in models:
            info = m.get("model_info", {}) or {}
            params = m.get("litellm_params", {}) or {}
            item = AgentInventoryItem(
                agent_id=f"litellm-model-{info.get('id', m.get('model_name', 'unknown'))}",
                source="litellm",
                agent_type="model",
                name=m.get("model_name", ""),
                config={
                    "provider_model": params.get("model", ""),
                    "max_tokens": params.get("max_tokens"),
                    "api_base": params.get("api_base", ""),
                },
                permissions={
                    "mode": info.get("mode", ""),
                },
                metadata={
                    "created_at": info.get("created_at", ""),
                    "updated_at": info.get("updated_at", ""),
                    "db_model": info.get("db_model", False),
                },
            )
            items.append(asdict(item))
        return items


async def scan_keys() -> list[dict]:
    """Discover all API keys registered in LiteLLM."""
    with tracer.start_as_current_span("spm.scan.litellm.keys"):
        try:
            data = await _get("/key/list")
        except Exception:
            # Fallback: try /key/info with empty body
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(
                        f"{LITELLM_URL}/key/info",
                        headers={"Authorization": f"Bearer {LITELLM_KEY}"},
                        json={},
                    )
                    resp.raise_for_status()
                    data = resp.json()
            except Exception:
                return []
        keys = data if isinstance(data, list) else data.get("keys", data.get("info", []))
        if isinstance(keys, dict):
            keys = [keys]
        items = []
        for k in (keys if isinstance(keys, list) else []):
            token = k.get("token", k.get("key", ""))
            # Mask the key — show only last 4 chars
            masked = f"sk-...{token[-4:]}" if len(token) > 4 else "sk-***"
            item = AgentInventoryItem(
                agent_id=f"litellm-key-{k.get('token_id', token[-8:])}",
                source="litellm",
                agent_type="key",
                name=k.get("key_alias", k.get("key_name", masked)),
                config={
                    "models": k.get("models", []),
                    "max_budget": k.get("max_budget"),
                    "max_parallel_requests": k.get("max_parallel_requests"),
                    "tpm_limit": k.get("tpm_limit"),
                    "rpm_limit": k.get("rpm_limit"),
                    "duration": k.get("duration"),
                },
                permissions={
                    "team_id": k.get("team_id", ""),
                    "user_id": k.get("user_id", ""),
                    "allowed_models": k.get("models", []),
                },
                metadata={
                    "spend": k.get("spend", 0),
                    "max_budget": k.get("max_budget"),
                    "expires": k.get("expires"),
                    "created_at": k.get("created_at", ""),
                    "last_used": k.get("updated_at", ""),
                },
            )
            items.append(asdict(item))
        return items


async def scan_spend() -> dict:
    """Get global spend summary from LiteLLM."""
    with tracer.start_as_current_span("spm.scan.litellm.spend"):
        try:
            data = await _get("/global/spend")
            return data if isinstance(data, dict) else {"raw": data}
        except Exception:
            return {}


async def scan() -> list[dict]:
    """Run full LiteLLM discovery — returns all inventory items."""
    with tracer.start_as_current_span("spm.scan.litellm"):
        models = await scan_models()
        keys = await scan_keys()
        spend = await scan_spend()
        # Enrich keys with spend data if available
        for item in keys:
            item.setdefault("metadata", {})["global_spend"] = spend
        return models + keys
