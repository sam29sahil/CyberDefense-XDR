"""
CyberDefense XDR
Threat Hunting Database Models
Stores hunt queries, search history, and saved hunt bookmarks.
Does NOT duplicate security telemetry.
"""

from datetime import datetime
from app.extensions import db


class ThreatHuntQuery(db.Model):
    """Stores analyst threat hunting queries and saved searches."""

    __tablename__ = "threat_hunt_queries"

    id = db.Column(db.Integer, primary_key=True)
    hunt_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=True)
    query_text = db.Column(db.String(255), nullable=False)
    entity_type = db.Column(db.String(64), nullable=False, default="general")
    filters_json = db.Column(db.Text, nullable=True, default="{}")
    result_count = db.Column(db.Integer, nullable=False, default=0)
    is_saved = db.Column(db.Boolean, nullable=False, default=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    def to_dict(self):
        import json
        filters = {}
        if self.filters_json:
            try:
                filters = json.loads(self.filters_json)
            except (ValueError, TypeError):
                filters = {}

        return {
            "id": self.id,
            "hunt_id": self.hunt_id,
            "title": self.title or self.query_text,
            "query_text": self.query_text,
            "entity_type": self.entity_type,
            "filters": filters,
            "result_count": self.result_count,
            "is_saved": self.is_saved,
            "user_id": self.user_id,
            "created_at": self.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.created_at else None,
        }

