"""
CyberDefense XDR
Security Settings Model
"""

from datetime import datetime

from app.extensions import db


class SecuritySettings(db.Model):

    __tablename__ = "security_settings"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        unique=True,
        index=True
    )

    # ========================================================
    # Password Policy
    # ========================================================

    pw_min_length = db.Column(
        db.Integer,
        nullable=False,
        default=12
    )

    pw_expiry = db.Column(
        db.Integer,
        nullable=False,
        default=90
    )

    require_case = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    require_numbers = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    require_symbols = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    prevent_reuse = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    # ========================================================
    # Authentication
    # ========================================================

    enforce_mfa = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    max_sessions = db.Column(
        db.String(20),
        nullable=False,
        default="3"
    )

    # ========================================================
    # IP Allowlist
    # ========================================================

    allowlist = db.Column(
        db.Text,
        nullable=False,
        default="[]"
    )

    # ========================================================
    # Timestamps
    # ========================================================

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

    def __repr__(self):
        return (
            f"<SecuritySettings user_id={self.user_id}>"
        )