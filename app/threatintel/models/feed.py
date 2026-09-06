"""
CyberDefense XDR
Threat Intelligence - Feed Model
"""

from datetime import datetime

from app.extensions import db


class ThreatFeed(db.Model):
    """Threat intelligence feed."""

    __tablename__ = "threat_feeds"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    feed_id = db.Column(
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

    provider = db.Column(
        db.String(255),
        nullable=True,
    )

    feed_type = db.Column(
        db.String(100),
        nullable=False,
        default="Open Source",
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="active",
        index=True,
    )

    ioc_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    last_sync = db.Column(
        db.DateTime,
        nullable=True,
        index=True,
    )

    reliability = db.Column(
        db.String(100),
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

    def to_dict(self):
        """Return frontend-compatible feed data."""
        return {
            "id": self.feed_id,
            "name": self.name,
            "provider": self.provider,
            "type": self.feed_type,
            "status": self.status,
            "iocCount": self.ioc_count,
            "lastSync": (
                self.last_sync.isoformat() + "Z"
                if self.last_sync
                else None
            ),
            "reliability": self.reliability,
        }

    def __repr__(self):
        return (
            f"<ThreatFeed "
            f"feed_id={self.feed_id!r} "
            f"name={self.name!r}>"
        )