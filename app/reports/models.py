"""
CyberDefense XDR
Security Reports Database Models
Provides SQLAlchemy model for enterprise security reports, execution parameters,
telemetry summaries, and export artifacts.
"""

from datetime import datetime
import json
import secrets

from app.extensions import db


def generate_report_id():
    """Generates unique, human-readable identifier: RPT-YYYYMMDD-XXXX"""
    date_str = datetime.utcnow().strftime("%Y%m%d")
    suffix = secrets.token_hex(3).upper()
    return f"RPT-{date_str}-{suffix}"


class Report(db.Model):
    """
    Represents an exported or generated security report.
    Tracks report type, scope filters, executive metrics snapshot,
    file artifact locations, and execution audit trails.
    """

    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)

    report_id = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True,
        default=generate_report_id,
    )

    report_type = db.Column(
        db.String(64),
        nullable=False,
        index=True,
    )

    title = db.Column(
        db.String(255),
        nullable=False,
    )

    description = db.Column(
        db.Text,
        nullable=True,
    )

    format = db.Column(
        db.String(16),
        nullable=False,
        default="pdf",
        index=True,
    )

    status = db.Column(
        db.String(32),
        nullable=False,
        default="completed",
        index=True,
    )

    date_from = db.Column(
        db.DateTime,
        nullable=True,
    )

    date_to = db.Column(
        db.DateTime,
        nullable=True,
    )

    filters_json = db.Column(
        db.Text,
        nullable=True,
        default="{}",
    )

    summary_json = db.Column(
        db.Text,
        nullable=True,
        default="{}",
    )

    file_path = db.Column(
        db.String(512),
        nullable=True,
    )

    file_size_bytes = db.Column(
        db.Integer,
        default=0,
    )

    generated_by = db.Column(
        db.String(128),
        nullable=False,
        default="SOC Analyst",
    )

    error_message = db.Column(
        db.Text,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    @property
    def filters(self):
        """Returns parsed filter dictionary."""
        if not self.filters_json:
            return {}
        try:
            return json.loads(self.filters_json)
        except Exception:
            return {}

    @filters.setter
    def filters(self, val):
        """Sets JSON string from dictionary."""
        if isinstance(val, dict):
            self.filters_json = json.dumps(val)
        else:
            self.filters_json = str(val) if val else "{}"

    @property
    def summary(self):
        """Returns parsed summary dictionary."""
        if not self.summary_json:
            return {}
        try:
            return json.loads(self.summary_json)
        except Exception:
            return {}

    @summary.setter
    def summary(self, val):
        """Sets JSON string from summary dictionary."""
        if isinstance(val, dict):
            self.summary_json = json.dumps(val)
        else:
            self.summary_json = str(val) if val else "{}"

    def to_dict(self):
        """Serialize report instance to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "report_id": self.report_id,
            "report_type": self.report_type,
            "title": self.title,
            "description": self.description or "",
            "format": self.format,
            "status": self.status,
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
            "filters": self.filters,
            "summary": self.summary,
            "file_size_bytes": self.file_size_bytes,
            "generated_by": self.generated_by,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<Report {self.report_id} ({self.report_type}) - {self.status}>"
