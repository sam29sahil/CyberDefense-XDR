"""
CyberDefense XDR
Threat Intelligence - Campaign Model
"""

import json
from datetime import datetime

from app.extensions import db


class ThreatCampaign(db.Model):
    """Threat campaign tracked by the XDR platform."""

    __tablename__ = "threat_campaigns"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    campaign_id = db.Column(
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

    actor_id = db.Column(
        db.String(50),
        nullable=True,
        index=True,
    )

    actor_name = db.Column(
        db.String(255),
        nullable=True,
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="active",
        index=True,
    )

    first_observed = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    target_sectors = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    ioc_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    ttps = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    description = db.Column(
        db.Text,
        nullable=True,
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
        try:
            return json.loads(self.target_sectors or "[]")
        except (TypeError, ValueError):
            return []

    def set_target_sectors(self, sectors):
        self.target_sectors = json.dumps(sectors or [])

    def get_ttps(self):
        try:
            return json.loads(self.ttps or "[]")
        except (TypeError, ValueError):
            return []

    def set_ttps(self, ttps):
        self.ttps = json.dumps(ttps or [])

    def to_dict(self):
        return {
            "id": self.campaign_id,
            "name": self.name,
            "actorId": self.actor_id,
            "actorName": self.actor_name,
            "status": self.status,
            "firstObserved": (
                self.first_observed.isoformat() + "Z"
                if self.first_observed
                else None
            ),
            "targetSectors": self.get_target_sectors(),
            "iocCount": self.ioc_count,
            "ttps": self.get_ttps(),
            "description": self.description,
        }

    def __repr__(self):
        return (
            f"<ThreatCampaign "
            f"campaign_id={self.campaign_id!r} "
            f"name={self.name!r}>"
        )