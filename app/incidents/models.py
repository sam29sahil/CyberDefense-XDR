"""
CyberDefense XDR
Incident Response Models
"""

from datetime import datetime

from app.extensions import db


# ============================================================
# INCIDENT
# ============================================================

class Incident(db.Model):

    __tablename__ = "incidents"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    incident_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        index=True
    )

    title = db.Column(
        db.String(255),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    category = db.Column(
        db.String(100),
        nullable=False,
        default="Security"
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="medium",
        index=True
    )

    priority = db.Column(
        db.String(20),
        nullable=False,
        default="medium",
        index=True
    )

    # --------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------

    status = db.Column(
        db.String(30),
        nullable=False,
        default="new",
        index=True
    )

    # --------------------------------------------------------
    # Ownership
    # --------------------------------------------------------

    assigned_to = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,
        index=True
    )

    created_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,
        index=True
    )

    # --------------------------------------------------------
    # Source / Detection
    # --------------------------------------------------------

    source = db.Column(
        db.String(255),
        nullable=True
    )

    detection_event_id = db.Column(
        db.Integer,
        db.ForeignKey("detection_events.id"),
        nullable=True,
        index=True
    )

    # --------------------------------------------------------
    # Asset / Host
    # --------------------------------------------------------

    affected_host = db.Column(
        db.String(255),
        nullable=True,
        index=True
    )

    affected_asset = db.Column(
        db.String(255),
        nullable=True,
        index=True
    )

    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    mitre_id = db.Column(
        db.String(50),
        nullable=True,
        index=True
    )

    mitre_name = db.Column(
        db.String(255),
        nullable=True
    )

    # --------------------------------------------------------
    # Investigation
    # --------------------------------------------------------

    investigation_notes = db.Column(
        db.Text,
        nullable=True
    )

    containment_notes = db.Column(
        db.Text,
        nullable=True
    )

    resolution_notes = db.Column(
        db.Text,
        nullable=True
    )

    # --------------------------------------------------------
    # Timestamps
    # --------------------------------------------------------

    detected_at = db.Column(
        db.DateTime,
        nullable=True,
        default=datetime.utcnow,
        index=True
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

    resolved_at = db.Column(
        db.DateTime,
        nullable=True
    )

    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    assigned_user = db.relationship(
        "User",
        foreign_keys=[assigned_to],
        backref=db.backref(
            "assigned_incidents",
            lazy="dynamic"
        )
    )

    creator = db.relationship(
        "User",
        foreign_keys=[created_by],
        backref=db.backref(
            "created_incidents",
            lazy="dynamic"
        )
    )

    detection_event = db.relationship(
        "DetectionEvent",
        foreign_keys=[detection_event_id],
        backref=db.backref(
            "incident",
            uselist=False
        )
    )

    # --------------------------------------------------------
    # Representation
    # --------------------------------------------------------

    def __repr__(self):
        return f"<Incident {self.incident_id}>"

    # --------------------------------------------------------
    # Serialization
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.incident_id,
            "title": self.title,
            "description": self.description,

            "category": self.category,
            "severity": self.severity,
            "priority": self.priority,

            "status": self.status,

            "assignedTo": self.assigned_user.email
            if self.assigned_user else None,

            "createdBy": self.creator.email
            if self.creator else None,

            "source": self.source,

            "detectionEventId": (
                self.detection_event.event_id
                if self.detection_event
                else None
            ),

            "affectedHost": self.affected_host,
            "affectedAsset": self.affected_asset,

            "mitreId": self.mitre_id,
            "mitreName": self.mitre_name,

            "investigationNotes": self.investigation_notes,
            "containmentNotes": self.containment_notes,
            "resolutionNotes": self.resolution_notes,

            "detectedAt": (
                self.detected_at.isoformat() + "Z"
                if self.detected_at
                else None
            ),

            "createdAt": (
                self.created_at.isoformat() + "Z"
                if self.created_at
                else None
            ),

            "updatedAt": (
                self.updated_at.isoformat() + "Z"
                if self.updated_at
                else None
            ),

            "resolvedAt": (
                self.resolved_at.isoformat() + "Z"
                if self.resolved_at
                else None
            ),
        }