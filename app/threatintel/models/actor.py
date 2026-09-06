"""
CyberDefense XDR
Threat Intelligence - Threat Actor Model
"""

import json
from datetime import datetime

from app.extensions import db


class ThreatActor(db.Model):
    """Threat actor / adversary profile."""

    __tablename__ = "threat_actors"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    actor_id = db.Column(
        db.String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    name = db.Column(
        db.String(255),
        nullable=False,
        index=True,
    )

    origin = db.Column(
        db.String(100),
        nullable=True,
        index=True,
    )

    sophistication = db.Column(
        db.String(100),
        nullable=True,
    )

    motivation = db.Column(
        db.String(255),
        nullable=True,
    )

    campaign_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    last_activity = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    first_seen = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    description = db.Column(
        db.Text,
        nullable=True,
    )

    target_sectors = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    mitre_tactics = db.Column(
        db.Text,
        nullable=False,
        default="[]",
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

    def get_target_sectors(self):
        """Return target sectors."""
        try:
            return json.loads(self.target_sectors or "[]")
        except (TypeError, ValueError):
            return []

    def set_target_sectors(self, sectors):
        """Store target sectors."""
        self.target_sectors = json.dumps(sectors or [])

    def get_mitre_tactics(self):
        """Return MITRE tactics."""
        try:
            return json.loads(self.mitre_tactics or "[]")
        except (TypeError, ValueError):
            return []

    def set_mitre_tactics(self, tactics):
        """Store MITRE tactics."""
        self.mitre_tactics = json.dumps(tactics or [])

    def to_dict(self):
        """Return frontend-compatible actor data."""
        return {
            "id": self.actor_id,
            "name": self.name,
            "origin": self.origin,
            "sophistication": self.sophistication,
            "motivation": self.motivation,
            "campaignCount": self.campaign_count,
            "lastActivity": (
                self.last_activity.isoformat() + "Z"
                if self.last_activity
                else None
            ),
            "firstSeen": (
                self.first_seen.isoformat() + "Z"
                if self.first_seen
                else None
            ),
            "description": self.description,
            "targetSectors": self.get_target_sectors(),
            "mitreTactics": self.get_mitre_tactics(),
        }

    def __repr__(self):
        return (
            f"<ThreatActor "
            f"actor_id={self.actor_id!r} "
            f"name={self.name!r}>"
        )