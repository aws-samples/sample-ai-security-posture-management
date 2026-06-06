"""Tests for spm.core.db against moto-mocked DynamoDB."""
import importlib
import os

import pytest

pytest.importorskip("boto3")
moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

TABLES = {
    "SPM_INVENTORY_TABLE": "test-spm-inventory",
    "SPM_FINDINGS_TABLE": "test-spm-findings",
    "SPM_POLICIES_TABLE": "test-spm-policies",
    "SPM_RUNTIME_TABLE": "test-spm-runtime-events",
}


def _create_tables(client):
    client.create_table(
        TableName=TABLES["SPM_INVENTORY_TABLE"], BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "agent_id", "AttributeType": "S"},
                              {"AttributeName": "source", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "agent_id", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[{"IndexName": "source-index",
                                 "KeySchema": [{"AttributeName": "source", "KeyType": "HASH"}],
                                 "Projection": {"ProjectionType": "ALL"}}])
    client.create_table(
        TableName=TABLES["SPM_FINDINGS_TABLE"], BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"},
                              {"AttributeName": "agent_id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[{"IndexName": "agent_id-index",
                                 "KeySchema": [{"AttributeName": "agent_id", "KeyType": "HASH"}],
                                 "Projection": {"ProjectionType": "ALL"}}])
    client.create_table(
        TableName=TABLES["SPM_POLICIES_TABLE"], BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "policy_id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "policy_id", "KeyType": "HASH"}])
    client.create_table(
        TableName=TABLES["SPM_RUNTIME_TABLE"], BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"},
                              {"AttributeName": "agent_id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[{"IndexName": "agent_id-index",
                                 "KeySchema": [{"AttributeName": "agent_id", "KeyType": "HASH"}],
                                 "Projection": {"ProjectionType": "ALL"}}])


@mock_aws
def test_db_crud_roundtrip(monkeypatch):
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ.update(TABLES)
    import boto3
    client = boto3.client("dynamodb", region_name="us-east-1")
    _create_tables(client)

    # Import fresh so table-name env vars are picked up, and reset client cache.
    from spm.core import db
    importlib.reload(db)
    db._dynamodb = None

    # Inventory
    db.put_inventory({"agent_id": "a1", "source": "litellm", "agent_type": "model", "name": "m"})
    got = db.get_inventory("a1")
    assert got and got["name"] == "m"
    assert any(i["agent_id"] == "a1" for i in db.list_inventory(source="litellm"))

    # Findings + GSI query + status update
    db.put_finding({"finding_id": "f1", "agent_id": "a1", "severity": "high",
                    "rule_id": "r", "status": "open"})
    assert len(db.list_findings(agent_id="a1")) == 1
    db.update_finding_status("f1", "resolved")
    assert db.get_finding("f1")["status"] == "resolved"

    # Policies
    db.put_policy({"policy_id": "defender-config", "config": {"mode": "enforce"}})
    assert db.get_policy("defender-config")["config"]["mode"] == "enforce"

    # Runtime events (float -> Decimal serialization path)
    db.put_runtime_event({"event_id": "e1", "agent_id": "a1", "event_type": "llm_call",
                          "severity": "low", "details": {"latency_ms": 12.5}})
    items, _ = db.list_runtime_events(agent_id="a1")
    assert items and items[0]["details"]["latency_ms"] == 12.5
