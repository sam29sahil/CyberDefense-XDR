"""
CyberDefense XDR
Threat Intelligence - IOC Model
"""

import json
from datetime import datetime

from app.extensions import db


class IOC(db.Model):
    """Indicator of Compromise."""

    __tablename__ = "threat_iocs"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    ioc_id = db.Column(
        db.String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    value = db.Column(
        db.Text,
        nullable=False,
        index=True,
    )

    type = db.Column(
        db.String(30),
        nullable=False,
        index=True,
    )

    threat_level = db.Column(
        db.String(20),
        nullable=False,
        default="medium",
        index=True,
    )

    confidence = db.Column(
        db.String(20),
        nullable=False,
        default="Medium",
    )

    source = db.Column(
        db.String(255),
        nullable=True,
        index=True,
    )

    first_seen = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    last_seen = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    sightings = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    tags = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    campaign_id = db.Column(
        db.String(50),
        nullable=True,
        index=True,
    )

    campaign_name = db.Column(
        db.String(255),
        nullable=True,
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="active",
        index=True,
    )

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

    def get_tags(self):
        """Return stored tags as a Python list."""
        try:
            return json.loads(self.tags or "[]")
        except (TypeError, ValueError):
            return []

    def set_tags(self, tags):
        """Store tags as JSON text."""
        self.tags = json.dumps(tags or [])

    def to_dict(self):
        """Return frontend-compatible IOC data."""
        return {
            "id": self.ioc_id,
            "value": self.value,
            "type": self.type,
            "threatLevel": self.threat_level,
            "confidence": self.confidence,
            "source": self.source,
            "firstSeen": (
                self.first_seen.isoformat() + "Z"
                if self.first_seen
                else None
            ),
            "lastSeen": (
                self.last_seen.isoformat() + "Z"
                if self.last_seen
                else None
            ),
            "sightings": self.sightings,
            "tags": self.get_tags(),
            "campaignId": self.campaign_id,
            "campaignName": self.campaign_name,
            "status": self.status,
        }

    def __repr__(self):
        return (
            f"<IOC ioc_id={self.ioc_id!r} "
            f"type={self.type!r} "
            f"threat_level={self.threat_level!r}>"
        )