"""SNS + EventBridge notifiers (AIDR integration), registered as event sinks.

Push high-severity runtime events to your incident pipeline:

    SPM_SNS_TOPIC_ARN=arn:aws:sns:...:ai-spm-alerts
    SPM_EVENT_BUS_NAME=default            # or a custom EventBridge bus
"""
from __future__ import annotations

import json
import os

import boto3

from spm.core.registry import finding_sink
from spm.core.errors import public_error

REGION = os.getenv("AWS_REGION", "us-east-1")
_ALERT_SEVERITIES = {"critical", "high"}


@finding_sink("sns", kind="events", description="Publish high-severity events to SNS")
def publish_sns(events: list[dict]) -> dict:
    topic = os.getenv("SPM_SNS_TOPIC_ARN", "")
    if not topic:
        return {"sink": "sns", "skipped": "SPM_SNS_TOPIC_ARN not set"}
    alerts = [e for e in events if e.get("severity") in _ALERT_SEVERITIES]
    if not alerts:
        return {"sink": "sns", "published": 0}
    try:
        sns = boto3.client("sns", region_name=REGION)
    except Exception:
        return {"sink": "sns", "error": public_error("sns client")}
    published = 0
    for e in alerts:
        subject = f"[AI SPM] {e.get('severity', '').upper()} {e.get('event_type', 'event')}"
        try:
            sns.publish(TopicArn=topic, Subject=subject[:100], Message=json.dumps(e, default=str))
            published += 1
        except Exception as ex:
            print(f"[SPM] SNS publish error: {ex}")
    return {"sink": "sns", "published": published}


@finding_sink("eventbridge", kind="events", description="Emit events to EventBridge")
def emit_eventbridge(events: list[dict]) -> dict:
    bus = os.getenv("SPM_EVENT_BUS_NAME", "")
    if not bus:
        return {"sink": "eventbridge", "skipped": "SPM_EVENT_BUS_NAME not set"}
    try:
        eb = boto3.client("events", region_name=REGION)
    except Exception:
        return {"sink": "eventbridge", "error": public_error("eventbridge client")}
    entries = [{
        "Source": "ai.spm",
        "DetailType": f"AI SPM {e.get('event_type', 'event')}",
        "Detail": json.dumps(e, default=str),
        "EventBusName": bus,
    } for e in events if e.get("severity") in _ALERT_SEVERITIES]
    sent = 0
    for i in range(0, len(entries), 10):  # PutEvents max 10
        batch = entries[i:i + 10]
        if not batch:
            continue
        try:
            resp = eb.put_events(Entries=batch)
            sent += len(batch) - resp.get("FailedEntryCount", 0)
        except Exception as ex:
            print(f"[SPM] EventBridge put_events error: {ex}")
    return {"sink": "eventbridge", "emitted": sent}
