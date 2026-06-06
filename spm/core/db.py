"""DynamoDB persistence for AI SPM tables."""
from __future__ import annotations

import os
from dataclasses import asdict
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import boto3

ENV = os.getenv("ENVIRONMENT_NAME", "ai-spm")
INVENTORY_TABLE = os.getenv("SPM_INVENTORY_TABLE", f"{ENV}-spm-inventory")
FINDINGS_TABLE = os.getenv("SPM_FINDINGS_TABLE", f"{ENV}-spm-findings")
POLICIES_TABLE = os.getenv("SPM_POLICIES_TABLE", f"{ENV}-spm-policies")
RUNTIME_TABLE = os.getenv("SPM_RUNTIME_TABLE", f"{ENV}-spm-runtime-events")

_dynamodb = None


def _resource():
    global _dynamodb
    if not _dynamodb:
        _dynamodb = boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION", "us-east-1"))
    return _dynamodb


def _table(name: str):
    return _resource().Table(name)


# --- DynamoDB serialization helpers (float<->Decimal, drop empty values) ---

def _to_dynamo(obj: Any) -> Any:
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_dynamo(v) for k, v in obj.items() if v is not None and v != ""}
    if isinstance(obj, list):
        return [_to_dynamo(i) for i in obj if i is not None]
    if isinstance(obj, str) and obj == "":
        return None
    return obj


def _from_dynamo(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return float(obj) if obj % 1 else int(obj)
    if isinstance(obj, dict):
        return {k: _from_dynamo(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_from_dynamo(i) for i in obj]
    return obj


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# Inventory CRUD
# ============================================================

def put_inventory(item: dict) -> None:
    item["updated_at"] = _now()
    _table(INVENTORY_TABLE).put_item(Item=_to_dynamo(item))


def get_inventory(agent_id: str) -> dict | None:
    resp = _table(INVENTORY_TABLE).get_item(Key={"agent_id": agent_id})
    item = resp.get("Item")
    return _from_dynamo(item) if item else None


def list_inventory(source: str | None = None, limit: int = 100) -> list[dict]:
    tbl = _table(INVENTORY_TABLE)
    if source:
        resp = tbl.query(
            IndexName="source-index",
            KeyConditionExpression="#src = :s",
            ExpressionAttributeNames={"#src": "source"},
            ExpressionAttributeValues={":s": source},
            Limit=limit,
        )
    else:
        resp = tbl.scan(Limit=limit)
    return [_from_dynamo(i) for i in resp.get("Items", [])]


def delete_inventory(agent_id: str) -> None:
    _table(INVENTORY_TABLE).delete_item(Key={"agent_id": agent_id})


# ============================================================
# Findings CRUD
# ============================================================

def put_finding(item: dict) -> None:
    item["updated_at"] = _now()
    _table(FINDINGS_TABLE).put_item(Item=_to_dynamo(item))


def get_finding(finding_id: str) -> dict | None:
    resp = _table(FINDINGS_TABLE).get_item(Key={"finding_id": finding_id})
    item = resp.get("Item")
    return _from_dynamo(item) if item else None


def list_findings(agent_id: str | None = None, severity: str | None = None,
                  status: str | None = None, limit: int = 100) -> list[dict]:
    tbl = _table(FINDINGS_TABLE)
    if agent_id:
        resp = tbl.query(
            IndexName="agent_id-index",
            KeyConditionExpression="agent_id = :a",
            ExpressionAttributeValues={":a": agent_id},
            Limit=limit,
        )
    else:
        kwargs: dict[str, Any] = {"Limit": limit}
        filters, values = [], {}
        if severity:
            filters.append("severity = :sev")
            values[":sev"] = severity
        if status:
            filters.append("#st = :st")
            values[":st"] = status
            kwargs["ExpressionAttributeNames"] = {"#st": "status"}
        if filters:
            kwargs["FilterExpression"] = " AND ".join(filters)
            kwargs["ExpressionAttributeValues"] = values
        resp = tbl.scan(**kwargs)
    return [_from_dynamo(i) for i in resp.get("Items", [])]


def update_finding_status(finding_id: str, status: str) -> None:
    _table(FINDINGS_TABLE).update_item(
        Key={"finding_id": finding_id},
        UpdateExpression="SET #st = :s, updated_at = :u",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": status, ":u": _now()},
    )


# ============================================================
# Policies CRUD
# ============================================================

def put_policy(item: dict) -> None:
    item["updated_at"] = _now()
    _table(POLICIES_TABLE).put_item(Item=_to_dynamo(item))


def get_policy(policy_id: str) -> dict | None:
    resp = _table(POLICIES_TABLE).get_item(Key={"policy_id": policy_id})
    item = resp.get("Item")
    return _from_dynamo(item) if item else None


def list_policies(limit: int = 100) -> list[dict]:
    resp = _table(POLICIES_TABLE).scan(Limit=limit)
    return [_from_dynamo(i) for i in resp.get("Items", [])]


def update_policy_enabled(policy_id: str, enabled: bool) -> None:
    _table(POLICIES_TABLE).update_item(
        Key={"policy_id": policy_id},
        UpdateExpression="SET enabled = :e, updated_at = :u",
        ExpressionAttributeValues={":e": enabled, ":u": _now()},
    )


# ============================================================
# Runtime Events CRUD
# ============================================================

def put_runtime_event(item: dict) -> None:
    if not item.get("ttl"):
        # Default 30-day TTL
        from datetime import timedelta
        item["ttl"] = int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp())
    _table(RUNTIME_TABLE).put_item(Item=_to_dynamo(item))


def get_runtime_event(event_id: str) -> dict | None:
    resp = _table(RUNTIME_TABLE).get_item(Key={"event_id": event_id})
    item = resp.get("Item")
    return _from_dynamo(item) if item else None


def list_runtime_events(agent_id: str | None = None, limit: int = 50,
                        last_key: dict | None = None) -> tuple[list[dict], dict | None]:
    """Returns (items, last_evaluated_key) for pagination."""
    tbl = _table(RUNTIME_TABLE)
    kwargs: dict[str, Any] = {"Limit": limit}
    if last_key:
        kwargs["ExclusiveStartKey"] = last_key
    if agent_id:
        kwargs.update({
            "IndexName": "agent_id-index",
            "KeyConditionExpression": "agent_id = :a",
            "ExpressionAttributeValues": {":a": agent_id},
            "ScanIndexForward": False,
        })
        resp = tbl.query(**kwargs)
    else:
        resp = tbl.scan(**kwargs)
    items = [_from_dynamo(i) for i in resp.get("Items", [])]
    items = sorted(items, key=lambda x: x.get("timestamp", ""), reverse=True)
    next_key = _from_dynamo(resp.get("LastEvaluatedKey")) if resp.get("LastEvaluatedKey") else None
    return items, next_key


def count_runtime_events() -> int:
    """Get approximate count of runtime events."""
    tbl = _table(RUNTIME_TABLE)
    resp = tbl.scan(Select="COUNT")
    return resp.get("Count", 0)
