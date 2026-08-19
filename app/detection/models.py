"""
CyberDefense XDR
Detection Engine Models
"""

from datetime import datetime

from app.extensions import db


# ============================================================
# DETECTION RULE
# ============================================================

class DetectionRule(db.Model):

    __tablename__ = "detection_rules"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    rule_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        index=True
    )

    name = db.Column(
        db.String(255),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    category = db.Column(
        db.String(100),
        nullable=False,
        index=True
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="medium",
        index=True
    )

    mitre_id = db.Column(
        db.String(50),
        nullable=True,
        index=True
    )

    mitre_name = db.Column(
        db.String(255),
        nullable=True
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="active",
        index=True
    )

    source = db.Column(
        db.String(255),
        nullable=True
    )

    author = db.Column(
        db.String(255),
        nullable=True
    )

    triggers_30d = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    false_positive_rate = db.Column(
        db.Float,
        nullable=False,
        default=0.0
    )

    # Stored as JSON text for PostgreSQL portability
    conditions = db.Column(
        db.Text,
        nullable=False,
        default="[]"
    )

    actions = db.Column(
        db.Text,
        nullable=False,
        default="[]"
    )

    tags = db.Column(
        db.Text,
        nullable=False,
        default="[]"
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    def __repr__(self):
        return f"<DetectionRule {self.rule_id}>"

    def to_dict(self):
        import json

        def load_json(value):
            try:
                return json.loads(value or "[]")
            except (TypeError, ValueError):
                return []

        return {
            "id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "mitreId": self.mitre_id,
            "mitreName": self.mitre_name,
            "status": self.status,
            "source": self.source,
            "author": self.author,
            "triggers30d": self.triggers_30d,
            "falsePositiveRate": self.false_positive_rate,
            "conditions": load_json(self.conditions),
            "actions": load_json(self.actions),
            "tags": load_json(self.tags),
            "createdAt": self.created_at.isoformat() + "Z"
            if self.created_at else None,
            "modifiedAt": self.updated_at.isoformat() + "Z"
            if self.updated_at else None,
        }


# ============================================================
# DETECTION EVENT
# ============================================================

class DetectionEvent(db.Model):

    __tablename__ = "detection_events"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    event_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        index=True
    )

    rule_id = db.Column(
        db.Integer,
        db.ForeignKey("detection_rules.id"),
        nullable=True,
        index=True
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True
    )

    source = db.Column(
        db.String(255),
        nullable=False
    )

    host = db.Column(
        db.String(255),
        nullable=True,
        index=True
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="medium",
        index=True
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="new",
        index=True
    )

    mitre_id = db.Column(
        db.String(50),
        nullable=True
    )

    raw_event = db.Column(
        db.Text,
        nullable=True
    )

    rule = db.relationship(
        "DetectionRule",
        backref=db.backref(
            "events",
            lazy="dynamic"
        )
    )

    def __repr__(self):
        return f"<DetectionEvent {self.event_id}>"

    def to_dict(self):

        return {
            "id": self.event_id,
            "ts": self.timestamp.isoformat() + "Z"
            if self.timestamp else None,
            "ruleId": self.rule.rule_id
            if self.rule else None,
            "ruleName": self.rule.name
            if self.rule else "Unknown Rule",
            "severity": self.severity,
            "source": self.source,
            "host": self.host,
            "status": self.status,
            "mitreId": self.mitre_id
            or (self.rule.mitre_id if self.rule else None),
        }