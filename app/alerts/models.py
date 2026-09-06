from datetime import datetime

from app.extensions import db


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)

    # Public alert identifier
    alert_id = db.Column(
        db.String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    # Basic alert information
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Classification
    severity = db.Column(
        db.String(20),
        nullable=False,
        default="medium",
        index=True,
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="new",
        index=True,
    )

    category = db.Column(
        db.String(100),
        nullable=True,
        index=True,
    )

    source = db.Column(
        db.String(100),
        nullable=True,
        index=True,
    )

    # Detection relationship/reference
    rule_id = db.Column(
        db.String(50),
        nullable=True,
        index=True,
    )

    detection_event_id = db.Column(
        db.Integer,
        db.ForeignKey("detection_events.id"),
        nullable=True,
        index=True,
    )

    # Affected infrastructure
    affected_host = db.Column(
        db.String(255),
        nullable=True,
    )

    affected_asset = db.Column(
        db.String(255),
        nullable=True,
    )

    # MITRE ATT&CK information
    mitre_id = db.Column(
        db.String(50),
        nullable=True,
    )

    mitre_name = db.Column(
        db.String(255),
        nullable=True,
    )

    # Assignment
    assigned_to = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    # Incident created from this alert
    incident_id = db.Column(
        db.String(50),
        nullable=True,
        index=True,
    )

    # Analyst notes
    investigation_notes = db.Column(
        db.Text,
        nullable=True,
    )

    resolution_notes = db.Column(
        db.Text,
        nullable=True,
    )

    # Flexible source metadata
    metadata_json = db.Column(
        db.Text,
        nullable=True,
        default="{}",
    )

    # Lifecycle timestamps
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    acknowledged_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    resolved_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    # Relationships
    detection_event = db.relationship(
        "DetectionEvent",
        foreign_keys=[detection_event_id],
        lazy=True,
    )

    assignee = db.relationship(
        "User",
        foreign_keys=[assigned_to],
        lazy=True,
    )

    def to_dict(self):
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "category": self.category,
            "source": self.source,
            "rule_id": self.rule_id,
            "detection_event_id": self.detection_event_id,
            "affected_host": self.affected_host,
            "affected_asset": self.affected_asset,
            "mitre_id": self.mitre_id,
            "mitre_name": self.mitre_name,
            "assigned_to": self.assigned_to,
            "incident_id": self.incident_id,
            "investigation_notes": self.investigation_notes,
            "resolution_notes": self.resolution_notes,
            "metadata_json": self.metadata_json,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
            "updated_at": (
                self.updated_at.isoformat()
                if self.updated_at
                else None
            ),
            "acknowledged_at": (
                self.acknowledged_at.isoformat()
                if self.acknowledged_at
                else None
            ),
            "resolved_at": (
                self.resolved_at.isoformat()
                if self.resolved_at
                else None
            ),
        }

    def __repr__(self):
        return (
            f"<Alert alert_id={self.alert_id!r} "
            f"severity={self.severity!r} "
            f"status={self.status!r}>"
        )