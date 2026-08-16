"""
CyberDefense XDR
Settings Models
"""

from datetime import datetime

from app.extensions import db

# ============================================================
# SECURITY SETTINGS
# ============================================================


class SecuritySettings(db.Model):

    __tablename__ = "security_settings"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True, index=True
    )

    # ========================================================
    # Password Policy
    # ========================================================

    pw_min_length = db.Column(db.Integer, nullable=False, default=12)

    pw_expiry = db.Column(db.Integer, nullable=False, default=90)

    require_case = db.Column(db.Boolean, nullable=False, default=True)

    require_numbers = db.Column(db.Boolean, nullable=False, default=True)

    require_symbols = db.Column(db.Boolean, nullable=False, default=False)

    prevent_reuse = db.Column(db.Boolean, nullable=False, default=True)

    # ========================================================
    # Authentication
    # ========================================================

    enforce_mfa = db.Column(db.Boolean, nullable=False, default=True)

    max_sessions = db.Column(db.String(20), nullable=False, default="3")

    # ========================================================
    # IP Allowlist
    # ========================================================

    allowlist = db.Column(db.Text, nullable=False, default="[]")

    # ========================================================
    # Timestamps
    # ========================================================

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self):

        return f"<SecuritySettings user_id={self.user_id}>"


# ============================================================
# NOTIFICATION SETTINGS
# ============================================================


class NotificationSettings(db.Model):

    __tablename__ = "notification_settings"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True, index=True
    )

    # ========================================================
    # Notification Channels
    # ========================================================

    email_enabled = db.Column(db.Boolean, nullable=False, default=True)

    slack_enabled = db.Column(db.Boolean, nullable=False, default=True)

    sms_enabled = db.Column(db.Boolean, nullable=False, default=False)

    webhook_enabled = db.Column(db.Boolean, nullable=False, default=False)

    # ========================================================
    # Notification Matrix
    #
    # Stored as JSON text:
    #
    # {
    #     "critical": {
    #         "email": true,
    #         "slack": true,
    #         "sms": true
    #     }
    # }
    # ========================================================

    notification_matrix = db.Column(db.Text, nullable=False, default="{}")

    # ========================================================
    # Severity Threshold
    # ========================================================

    min_severity = db.Column(db.String(20), nullable=False, default="medium")

    # ========================================================
    # Quiet Hours
    # ========================================================

    quiet_hours_enabled = db.Column(db.Boolean, nullable=False, default=False)

    quiet_hours_from = db.Column(db.String(5), nullable=False, default="20:00")

    quiet_hours_to = db.Column(db.String(5), nullable=False, default="07:00")

    # ========================================================
    # Timestamps
    # ========================================================

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self):

        return f"<NotificationSettings user_id={self.user_id}>"


# ============================================================
# API KEYS
# ============================================================


class APIKey(db.Model):

    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )

    # ========================================================
    # Key Information
    # ========================================================

    name = db.Column(db.String(150), nullable=False)

    key_prefix = db.Column(db.String(20), nullable=False)

    key_hash = db.Column(db.String(255), nullable=False, unique=True)

    # ========================================================
    # Permissions / Scopes
    # ========================================================

    scopes = db.Column(db.Text, nullable=False, default="[]")

    # ========================================================
    # Status
    # ========================================================

    status = db.Column(db.String(20), nullable=False, default="active")

    # ========================================================
    # Usage Information
    # ========================================================

    last_used = db.Column(db.DateTime, nullable=True)

    # ========================================================
    # Timestamps
    # ========================================================

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self):

        return (
            f"<APIKey id={self.id} " f"name={self.name!r} " f"user_id={self.user_id}>"
        )


# ============================================================
# INTEGRATIONS
# ============================================================


class Integration(db.Model):

    __tablename__ = "integrations"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )

    # ========================================================
    # Integration Identity
    # ========================================================

    integration_key = db.Column(db.String(50), nullable=False)

    name = db.Column(db.String(100), nullable=False)

    category = db.Column(db.String(100), nullable=False)

    icon = db.Column(db.String(100), nullable=False)

    description = db.Column(db.Text, nullable=False)

    # ========================================================
    # Connection State
    # ========================================================

    connected = db.Column(db.Boolean, nullable=False, default=False)

    status = db.Column(db.String(30), nullable=False, default="disconnected")

    # ========================================================
    # Configuration
    # ========================================================

    webhook_url = db.Column(db.Text, nullable=True)

    token_hash = db.Column(db.String(255), nullable=True)

    # ========================================================
    # Timestamps
    # ========================================================

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self):

        return f"<Integration " f"name={self.name!r} " f"user_id={self.user_id}>"


# ============================================================
# GENERAL SETTINGS
# ============================================================


class GeneralSettings(db.Model):

    __tablename__ = "general_settings"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True, index=True
    )

    # ========================================================
    # Organization
    # ========================================================

    organization_name = db.Column(
        db.String(255), nullable=False, default="CyberDefense XDR"
    )

    timezone = db.Column(db.String(100), nullable=False, default="America/New_York")

    date_format = db.Column(db.String(30), nullable=False, default="YYYY-MM-DD")

    language = db.Column(db.String(20), nullable=False, default="en-US")

    # ========================================================
    # Defaults
    # ========================================================

    default_landing = db.Column(db.String(50), nullable=False, default="dashboard")

    session_timeout = db.Column(db.Integer, nullable=False, default=30)

    compact_density = db.Column(db.Boolean, nullable=False, default=False)

    # ========================================================
    # Organization Logo
    # ========================================================

    logo_path = db.Column(db.String(500), nullable=True)

    # ========================================================
    # Timestamps
    # ========================================================

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self):

        return f"<GeneralSettings user_id={self.user_id}>"
