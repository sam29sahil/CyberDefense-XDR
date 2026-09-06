"""
CyberDefense XDR
SIEM & Log Explorer Database Models
"""

import json
from datetime import datetime

from app.extensions import db


class SiemEvent(db.Model):
    """
    Centralized Security Event / Log model.
    Stores raw, normalized, and parsed event fields.
    """

    __tablename__ = "siem_events"

    id = db.Column(db.Integer, primary_key=True)

    event_id = db.Column(
        db.String(32),
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

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="info",
        index=True,
    )

    category = db.Column(
        db.String(50),
        nullable=False,
        default="Application",
        index=True,
    )

    source = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    host = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    message = db.Column(
        db.Text,
        nullable=False,
    )

    raw_log = db.Column(
        db.Text,
        nullable=False,
    )

    # Parsed key-value fields stored as JSON text
    fields_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    # Tags stored as JSON array text
    tags_json = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    # Threat Intelligence correlation: Matched IOC ID or value
    ioc_match_id = db.Column(
        db.String(100),
        nullable=True,
        index=True,
    )

    # Detection Engine correlation: Triggered Detection Event ID
    detection_event_id = db.Column(
        db.Integer,
        db.ForeignKey("detection_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    detection_event = db.relationship(
        "DetectionEvent",
        backref=db.backref("siem_events", lazy="dynamic"),
        foreign_keys=[detection_event_id],
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    @property
    def fields(self):
        """Deserialized fields dictionary."""
        try:
            return json.loads(self.fields_json or "{}")
        except (TypeError, ValueError):
            return {}

    @fields.setter
    def fields(self, val):
        self.fields_json = json.dumps(val if isinstance(val, dict) else {})

    @property
    def tags(self):
        """Deserialized tags list."""
        try:
            return json.loads(self.tags_json or "[]")
        except (TypeError, ValueError):
            return []

    @tags.setter
    def tags(self, val):
        self.tags_json = json.dumps(val if isinstance(val, list) else [])

    def __repr__(self):
        return f"<SiemEvent {self.event_id} - {self.severity} - {self.host}>"

    def to_dict(self):
        """
        Serialize to dictionary matching frontend LOGS_DATA contract.
        """
        ts_str = self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if self.timestamp else None
        return {
            "id": self.event_id,
            "ts": ts_str,
            "sev": self.severity.lower(),
            "host": self.host,
            "source": self.source,
            "category": self.category,
            "message": self.message,
            "raw": self.raw_log,
            "fields": self.fields,
            "tags": self.tags,
            "ioc_match_id": self.ioc_match_id,
            "detection_event_id": self.detection_event_id,
        }


class SiemSavedSearch(db.Model):
    """
    Saved Search queries for Log Explorer and SIEM Dashboard.
    """

    __tablename__ = "siem_saved_searches"

    id = db.Column(db.Integer, primary_key=True)

    search_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        index=True,
    )

    name = db.Column(
        db.String(255),
        nullable=False,
    )

    query_text = db.Column(
        "query",
        db.Text,
        nullable=False,
    )

    def __init__(self, **kwargs):
        if "query" in kwargs and "query_text" not in kwargs:
            kwargs["query_text"] = kwargs.pop("query")
        super().__init__(**kwargs)

    description = db.Column(
        db.Text,
        nullable=True,
    )

    owner = db.Column(
        db.String(100),
        nullable=False,
        default="Aria Reyes",
    )

    scope = db.Column(
        db.String(20),
        nullable=False,
        default="Team",
        index=True,
    )

    pinned = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    alerting = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    hits = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    last_run = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    filters_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    @property
    def filters(self):
        try:
            return json.loads(self.filters_json or "{}")
        except (TypeError, ValueError):
            return {}

    @filters.setter
    def filters(self, val):
        self.filters_json = json.dumps(val if isinstance(val, dict) else {})

    def __repr__(self):
        return f"<SiemSavedSearch {self.search_id} - {self.name}>"

    def to_dict(self):
        """
        Serialize to dictionary matching frontend SAVED_SEARCHES_DATA contract.
        """
        # Relative time string for last_run
        last_run_str = "just now"
        if self.last_run:
            diff = (datetime.utcnow() - self.last_run).total_seconds()
            if diff < 60:
                last_run_str = "just now"
            elif diff < 3600:
                last_run_str = f"{int(diff // 60)} min ago"
            elif diff < 86400:
                last_run_str = f"{int(diff // 3600)}h ago"
            else:
                last_run_str = f"{int(diff // 86400)}d ago"

        return {
            "id": self.search_id,
            "name": self.name,
            "query": self.query_text,
            "owner": self.owner,
            "scope": self.scope,
            "pinned": self.pinned,
            "alerting": self.alerting,
            "lastRun": last_run_str,
            "hits": self.hits,
            "description": self.description or "",
            "filters": self.filters,
        }
