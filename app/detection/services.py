"""
CyberDefense XDR
Detection Engine Services
"""

import json
import secrets

from app.extensions import db

from app.detection.models import (
    DetectionRule,
    DetectionEvent,
)


# ============================================================
# HELPERS
# ============================================================

def generate_rule_id():
    while True:
        rule_id = f"DET-{secrets.randbelow(900000) + 100000}"

        if not DetectionRule.query.filter_by(rule_id=rule_id).first():
            return rule_id


def generate_event_id():
    while True:
        event_id = f"EVT-{secrets.randbelow(900000) + 100000}"

        if not DetectionEvent.query.filter_by(event_id=event_id).first():
            return event_id


def json_text(value):
    if value is None:
        return "[]"

    if not isinstance(value, list):
        raise ValueError("Expected a list.")

    return json.dumps(value)


# ============================================================
# RULE SERVICES
# ============================================================

def create_rule(data, author=None):

    name = str(data.get("name", "")).strip()

    if not name:
        raise ValueError("Rule name is required.")

    severity = str(
        data.get("severity", "medium")
    ).strip().lower()

    allowed_severities = {
        "critical",
        "high",
        "medium",
        "low",
    }

    if severity not in allowed_severities:
        raise ValueError("Invalid severity.")

    status = str(
        data.get("status", "active")
    ).strip().lower()

    allowed_statuses = {
        "active",
        "testing",
        "disabled",
    }

    if status not in allowed_statuses:
        raise ValueError("Invalid rule status.")

    rule = DetectionRule(
        rule_id=generate_rule_id(),
        name=name,
        description=str(
            data.get("description", "")
        ).strip(),

        category=str(
            data.get("category", "Malware")
        ).strip(),

        severity=severity,

        mitre_id=str(
            data.get("mitreId", "")
        ).strip() or None,

        mitre_name=str(
            data.get("mitreName", "")
        ).strip() or None,

        status=status,

        source=str(
            data.get("source", "")
        ).strip() or None,

        author=author
        or str(data.get("author", "")).strip()
        or None,

        triggers_30d=0,

        false_positive_rate=0.0,

        conditions=json_text(
            data.get("conditions", [])
        ),

        actions=json_text(
            data.get("actions", [])
        ),

        tags=json_text(
            data.get("tags", [])
        ),
    )

    db.session.add(rule)
    db.session.commit()

    return rule


def update_rule(rule, data):

    if "name" in data:
        name = str(data["name"]).strip()

        if not name:
            raise ValueError("Rule name is required.")

        rule.name = name

    if "description" in data:
        rule.description = str(
            data["description"]
        ).strip()

    if "category" in data:
        rule.category = str(
            data["category"]
        ).strip()

    if "severity" in data:

        severity = str(
            data["severity"]
        ).strip().lower()

        if severity not in {
            "critical",
            "high",
            "medium",
            "low",
        }:
            raise ValueError("Invalid severity.")

        rule.severity = severity

    if "status" in data:

        status = str(
            data["status"]
        ).strip().lower()

        if status not in {
            "active",
            "testing",
            "disabled",
        }:
            raise ValueError("Invalid rule status.")

        rule.status = status

    if "mitreId" in data:
        rule.mitre_id = str(
            data["mitreId"]
        ).strip() or None

    if "mitreName" in data:
        rule.mitre_name = str(
            data["mitreName"]
        ).strip() or None

    if "source" in data:
        rule.source = str(
            data["source"]
        ).strip() or None

    if "conditions" in data:
        rule.conditions = json_text(
            data["conditions"]
        )

    if "actions" in data:
        rule.actions = json_text(
            data["actions"]
        )

    if "tags" in data:
        rule.tags = json_text(
            data["tags"]
        )

    db.session.commit()

    return rule


def delete_rule(rule):

    db.session.delete(rule)
    db.session.commit()


def duplicate_rule(rule):

    clone = DetectionRule(
        rule_id=generate_rule_id(),
        name=f"{rule.name} (Copy)",
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        mitre_id=rule.mitre_id,
        mitre_name=rule.mitre_name,
        status="testing",
        source=rule.source,
        author=rule.author,
        triggers_30d=0,
        false_positive_rate=rule.false_positive_rate,
        conditions=rule.conditions,
        actions=rule.actions,
        tags=rule.tags,
    )

    db.session.add(clone)
    db.session.commit()

    return clone


# ============================================================
# DETECTION EVENT
# ============================================================

def create_detection_event(
    rule,
    source,
    host=None,
    severity=None,
    status="new",
    raw_event=None,
):

    event = DetectionEvent(
        event_id=generate_event_id(),
        rule_id=rule.id if rule else None,
        source=source,
        host=host,
        severity=severity or (rule.severity if rule else "medium"),
        status=status,
        mitre_id=rule.mitre_id if rule else None,
        raw_event=json.dumps(raw_event)
        if isinstance(raw_event, dict)
        else raw_event,
    )

    if rule:
        rule.triggers_30d += 1

    db.session.add(event)
    db.session.commit()

    return event