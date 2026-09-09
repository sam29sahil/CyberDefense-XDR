"""
CyberDefense XDR
Audit Logs Database Models
Provides tamper-resistant, structured persistent records for administrative,
authentication, security policy, and operational compliance events.
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional

from app.extensions import db


class AuditLog(db.Model):
    """
    Centralized Audit Log Model.
    Represents an immutable record of an administrative, operational, or
    security-sensitive action performed within the CyberDefense XDR platform.
    """

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    audit_id = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        index=True,
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    actor = db.Column(
        db.String(120),
        nullable=False,
        index=True,
        default="System",
    )

    actor_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    action = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    category = db.Column(
        db.String(60),
        nullable=False,
        index=True,
    )

    resource_type = db.Column(
        db.String(60),
        nullable=True,
        index=True,
    )

    resource_id = db.Column(
        db.String(100),
        nullable=True,
        index=True,
    )

    result = db.Column(
        db.String(20),
        nullable=False,
        default="SUCCESS",
        index=True,
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="info",
        index=True,
    )

    source_ip = db.Column(
        db.String(64),
        nullable=True,
        index=True,
    )

    user_agent = db.Column(
        db.String(255),
        nullable=True,
    )

    message = db.Column(
        db.Text,
        nullable=False,
    )

    details_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    actor_user = db.relationship(
        "User",
        foreign_keys=[actor_id],
        lazy="joined",
    )

    @property
    def details(self) -> Dict[str, Any]:
        """Deserialized JSON details dictionary."""
        try:
            return json.loads(self.details_json or "{}")
        except (TypeError, ValueError):
            return {}

    @details.setter
    def details(self, val: Any) -> None:
        if isinstance(val, dict):
            self.details_json = json.dumps(val)
        elif isinstance(val, str):
            self.details_json = val
        else:
            self.details_json = "{}"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the audit record into a clean dictionary representation."""
        return {
            "id": self.id,
            "audit_id": self.audit_id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else None,
            "iso_timestamp": self.timestamp.isoformat() + "Z" if self.timestamp else None,
            "actor": self.actor,
            "actor_id": self.actor_id,
            "actor_role": (self.actor_user.role if self.actor_user else None) or self.details.get("actor_role"),
            "action": self.action,
            "category": self.category,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "result": self.result,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "message": self.message,
            "details": self.details,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<AuditLog {self.audit_id} [{self.category}] {self.action} by {self.actor} - {self.result}>"
