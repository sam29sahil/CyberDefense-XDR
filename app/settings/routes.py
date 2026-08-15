"""
CyberDefense XDR
Settings Routes
"""

from flask import render_template, request, jsonify
from flask_login import login_required, current_user

from app.extensions import db
from app.settings import settings


@settings.route("/")
@login_required
def index():
    return render_template(
        "settings/profile.html",
        user=current_user
    )


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


@settings.route("/general")
@login_required
def general():
    return render_template(
        "settings/general-settings.html",
        user=current_user
    )


@settings.route("/security")
@login_required
def security():
    return render_template(
        "settings/security-settings.html",
        user=current_user
    )


@settings.route("/notifications")
@login_required
def notifications():
    return render_template(
        "settings/notifications-settings.html",
        user=current_user
    )


@settings.route("/integrations")
@login_required
def integrations():
    return render_template(
        "settings/integrations.html",
        user=current_user
    )


@settings.route("/api")
@login_required
def api_settings():
    return render_template(
        "settings/api-settings.html",
        user=current_user
    )
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
            "message": "New password must contain at least 12 characters."
        }), 400


    if new_password != confirm_password:
        return jsonify({
            "success": False,
            "message": "New passwords do not match."
        }), 400


    if not current_user.check_password(current_password):
        return jsonify({
            "success": False,
            "message": "Current password is incorrect."
        }), 401


    if current_password == new_password:
        return jsonify({
            "success": False,
            "message": "New password must be different from your current password."
        }), 400


    current_user.set_password(new_password)

    db.session.commit()


    return jsonify({
        "success": True,
        "message": "Password changed successfully."
    }), 200   