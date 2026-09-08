"""
CyberDefense XDR
SOC Dashboard Web & REST API Routes
"""

import logging
from flask import render_template, jsonify
from flask_login import login_required

from app.soc_dashboard import soc_dashboard
from app.soc_dashboard.services import get_soc_dashboard_data

logger = logging.getLogger("cyberdefense.soc_dashboard")


@soc_dashboard.route("/")
@soc_dashboard.route("/dashboard")
@login_required
def index():
    """Renders the main SOC Dashboard page."""
    return render_template("soc_dashboard/dashboard.html")


@soc_dashboard.route("/api/dashboard", methods=["GET"])
@login_required
def api_dashboard():
    """
    Primary API endpoint returning real aggregated telemetry across
    Assets, Alerts, Incidents, Vulnerabilities, IDS, SIEM, Detection, and Threat Intel.
    """
    try:
        data = get_soc_dashboard_data()
        return jsonify(data), 200
    except Exception as e:
        logger.exception("Failed to aggregate SOC dashboard telemetry: %s", e)
        return jsonify({
            "success": False,
            "error": "Failed to load SOC dashboard telemetry. Please check application logs.",
        }), 500

