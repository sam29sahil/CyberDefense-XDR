"""
CyberDefense XDR
Settings Routes
"""
import json

from app.settings.models import SecuritySettings
from flask import render_template, request, jsonify
from flask_login import login_required, current_user

from app.extensions import db
from app.settings import settings


# ============================================================
# SETTINGS HOME
# ============================================================

@settings.route("/")
@login_required
def index():
    return render_template(
        "settings/profile.html",
        user=current_user
    )


# ============================================================
# PROFILE
# ============================================================

@settings.route("/profile", methods=["GET", "POST"])
@login_required
def profile():

    if request.method == "GET":
        return render_template(
            "settings/profile.html",
            user=current_user
        )

    data = request.get_json(silent=True) or {}

    first_name = str(
        data.get("first_name", "")
    ).strip()

    last_name = str(
        data.get("last_name", "")
    ).strip()

    company = str(
        data.get("company", "")
    ).strip()

    if not first_name:
        return jsonify({
            "success": False,
            "message": "First name is required."
        }), 400

    if not last_name:
        return jsonify({
            "success": False,
            "message": "Last name is required."
        }), 400

    current_user.first_name = first_name
    current_user.last_name = last_name
    current_user.company = company or None

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Profile updated successfully."
    }), 200


# ============================================================
# CHANGE PASSWORD
# ============================================================

@settings.route("/profile/password", methods=["POST"])
@login_required
def change_password():

    data = request.get_json(silent=True) or {}

    current_password = str(
        data.get("current_password", "")
    )

    new_password = str(
        data.get("new_password", "")
    )

    confirm_password = str(
        data.get("confirm_password", "")
    )

    if not current_password:
        return jsonify({
            "success": False,
            "message": "Current password is required."
        }), 400

    if not new_password:
        return jsonify({
            "success": False,
            "message": "New password is required."
        }), 400

    if len(new_password) < 12:
        return jsonify({
            "success": False,
            "message": (
                "New password must contain at least "
                "12 characters."
            )
        }), 400

    if new_password != confirm_password:
        return jsonify({
            "success": False,
            "message": "New passwords do not match."
        }), 400

    if not current_user.check_password(
        current_password
    ):
        return jsonify({
            "success": False,
            "message": "Current password is incorrect."
        }), 401

    if current_password == new_password:
        return jsonify({
            "success": False,
            "message": (
                "New password must be different "
                "from your current password."
            )
        }), 400

    current_user.set_password(new_password)

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Password changed successfully."
    }), 200


# ============================================================
# GENERAL SETTINGS
# ============================================================

@settings.route("/general")
@login_required
def general():

    return render_template(
        "settings/general-settings.html",
        user=current_user
    )


# ============================================================
# SECURITY SETTINGS
# ============================================================

@settings.route("/security")
@login_required
def security():

    return render_template(
        "settings/security-settings.html",
        user=current_user
    )


# ============================================================
# SECURITY SETTINGS API
# ============================================================

# ============================================================
# SAVE SECURITY SETTINGS
# ============================================================

@settings.route("/security/save", methods=["POST"])
@login_required
def save_security_settings():

    data = request.get_json(silent=True) or {}

    # --------------------------------------------------------
    # Password policy
    # --------------------------------------------------------

    try:
        pw_min_length = int(
            data.get("pw_min_length", 12)
        )
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Invalid minimum password length."
        }), 400

    try:
        pw_expiry = int(
            data.get("pw_expiry", 90)
        )
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Invalid password expiry value."
        }), 400

    if pw_min_length < 8 or pw_min_length > 32:
        return jsonify({
            "success": False,
            "message": "Password length must be between 8 and 32."
        }), 400

    if pw_expiry < 0:
        return jsonify({
            "success": False,
            "message": "Password expiry cannot be negative."
        }), 400

    # --------------------------------------------------------
    # Boolean settings
    # --------------------------------------------------------

    require_case = bool(
        data.get("require_case", True)
    )

    require_numbers = bool(
        data.get("require_numbers", True)
    )

    require_symbols = bool(
        data.get("require_symbols", False)
    )

    prevent_reuse = bool(
        data.get("prevent_reuse", True)
    )

    enforce_mfa = bool(
        data.get("enforce_mfa", True)
    )

    # --------------------------------------------------------
    # Maximum sessions
    # --------------------------------------------------------

    max_sessions = str(
        data.get("max_sessions", "3")
    ).strip()

    allowed_sessions = {
        "1",
        "3",
        "5",
        "Unlimited"
    }

    if max_sessions not in allowed_sessions:
        return jsonify({
            "success": False,
            "message": "Invalid maximum session value."
        }), 400

    # --------------------------------------------------------
    # IP Allowlist
    # --------------------------------------------------------

    allowlist = data.get("allowlist", [])

    if not isinstance(allowlist, list):
        return jsonify({
            "success": False,
            "message": "Invalid IP allowlist."
        }), 400

    cleaned_allowlist = []

    for entry in allowlist:

        entry = str(entry).strip()

        if entry and entry not in cleaned_allowlist:
            cleaned_allowlist.append(entry)

    # --------------------------------------------------------
    # Find existing settings
    # --------------------------------------------------------

    security_settings = SecuritySettings.query.filter_by(
        user_id=current_user.id
    ).first()

    # --------------------------------------------------------
    # Create if this user doesn't have settings yet
    # --------------------------------------------------------

    if security_settings is None:

        security_settings = SecuritySettings(
            user_id=current_user.id
        )

        db.session.add(security_settings)

    # --------------------------------------------------------
    # Update settings
    # --------------------------------------------------------

    security_settings.pw_min_length = pw_min_length

    security_settings.pw_expiry = pw_expiry

    security_settings.require_case = require_case

    security_settings.require_numbers = require_numbers

    security_settings.require_symbols = require_symbols

    security_settings.prevent_reuse = prevent_reuse

    security_settings.enforce_mfa = enforce_mfa

    security_settings.max_sessions = max_sessions

    security_settings.allowlist = json.dumps(
        cleaned_allowlist
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Security settings saved successfully."
    }), 200


# ============================================================
# GET SECURITY SETTINGS
# ============================================================

@settings.route("/security/data", methods=["GET"])
@login_required
def security_data():

    security_settings = SecuritySettings.query.filter_by(
        user_id=current_user.id
    ).first()

    # --------------------------------------------------------
    # Defaults for a new user
    # --------------------------------------------------------

    if security_settings is None:

        return jsonify({
            "success": True,
            "settings": {
                "pw_min_length": 12,
                "pw_expiry": 90,
                "require_case": True,
                "require_numbers": True,
                "require_symbols": False,
                "prevent_reuse": True,
                "enforce_mfa": True,
                "max_sessions": "3",
                "allowlist": []
            }
        }), 200

    # --------------------------------------------------------
    # Decode allowlist
    # --------------------------------------------------------

    try:
        allowlist = json.loads(
            security_settings.allowlist or "[]"
        )
    except (TypeError, ValueError):

        allowlist = []

    # --------------------------------------------------------
    # Return settings
    # --------------------------------------------------------

    return jsonify({
        "success": True,
        "settings": {
            "pw_min_length":
                security_settings.pw_min_length,

            "pw_expiry":
                security_settings.pw_expiry,

            "require_case":
                security_settings.require_case,

            "require_numbers":
                security_settings.require_numbers,

            "require_symbols":
                security_settings.require_symbols,

            "prevent_reuse":
                security_settings.prevent_reuse,

            "enforce_mfa":
                security_settings.enforce_mfa,

            "max_sessions":
                security_settings.max_sessions,

            "allowlist":
                allowlist
        }
    }), 200

# ============================================================
# NOTIFICATIONS
# ============================================================

@settings.route("/notifications")
@login_required
def notifications():

    return render_template(
        "settings/notifications-settings.html",
        user=current_user
    )


# ============================================================
# INTEGRATIONS
# ============================================================

@settings.route("/integrations")
@login_required
def integrations():

    return render_template(
        "settings/integrations.html",
        user=current_user
    )


# ============================================================
# API SETTINGS
# ============================================================

@settings.route("/api")
@login_required
def api_settings():

    return render_template(
        "settings/api-settings.html",
        user=current_user
    )