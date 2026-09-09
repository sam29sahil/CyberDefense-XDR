"""
CyberDefense XDR
Notifications Model
"""

from datetime import datetime
import json
from app.extensions import db


class Notification(db.Model):
    """
    Persistent in-app notification entity.
    Tracks security alerts, system events, SOAR approvals, and operational updates per recipient.
    """

    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)

    # Unique public reference ID, e.g. NOTIF-XXXXXXXXXX
    notification_id = db.Column(
        db.String(36), unique=True, nullable=False, index=True
    )

    # Recipient user ID (enforces referential integrity with cascade)
    recipient_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Notification content
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)

    # Classification & Severity
    # Category: ALERT, INCIDENT, IDS, SCANNER, SOAR, SYSTEM, SECURITY, REPORT
    category = db.Column(
        db.String(50), nullable=False, default="SYSTEM", index=True
    )

    # Severity: info, low, medium, high, critical
    severity = db.Column(
        db.String(20), nullable=False, default="info", index=True
    )

    # Originating system / module
    source = db.Column(
        db.String(100), nullable=False, default="System"
    )

    # Optional linked resource reference
    resource_type = db.Column(
        db.String(60), nullable=True, index=True
    )
    resource_id = db.Column(
        db.String(100), nullable=True, index=True
    )

    # Direct navigation action URL (safe relative path)
    action_url = db.Column(
        db.String(255), nullable=True
    )

    # Read tracking
    is_read = db.Column(
        db.Boolean, nullable=False, default=False, index=True
    )
    read_at = db.Column(
        db.DateTime, nullable=True
    )

    # Dismissal tracking
    is_dismissed = db.Column(
        db.Boolean, nullable=False, default=False, index=True
    )
    dismissed_at = db.Column(
        db.DateTime, nullable=True
    )

    # Deduplication & Flood mitigation
    dedup_hash = db.Column(
        db.String(64), nullable=True, index=True
    )
    occurrence_count = db.Column(
        db.Integer, nullable=False, default=1
    )

    # Metadata & Extensibility
    metadata_json = db.Column(
        db.Text, nullable=False, default="{}"
    )

    # Timestamps
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, index=True
    )
    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    expires_at = db.Column(
        db.DateTime, nullable=True
    )

    # Relationship to recipient User
    recipient = db.relationship(
        "User",
        backref=db.backref("notifications", lazy="dynamic", cascade="all, delete-orphan"),
        foreign_keys=[recipient_user_id],
    )

    def to_dict(self):
        """Serializes notification entity to clean JSON-compatible dictionary."""
        try:
            meta = json.loads(self.metadata_json) if self.metadata_json else {}
        except Exception:
            meta = {}

        return {
            "id": self.id,
            "notification_id": self.notification_id,
            "recipient_user_id": self.recipient_user_id,
            "recipient_username": self.recipient.username if self.recipient else None,
            "title": self.title,
            "message": self.message,
            "category": self.category,
            "severity": self.severity,
            "source": self.source,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action_url": self.action_url,
            "is_read": self.is_read,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "is_dismissed": self.is_dismissed,
            "dismissed_at": self.dismissed_at.isoformat() if self.dismissed_at else None,
            "occurrence_count": self.occurrence_count,
            "metadata": meta,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    def __repr__(self):
        return (
            f"<Notification {self.notification_id} "
            f"user_id={self.recipient_user_id} severity={self.severity} read={self.is_read}>"
        )

