"""
CyberDefense XDR
Analytics Web Views and REST APIs
"""

import logging
from flask import render_template, request, jsonify
from flask_login import login_required

from app.analytics import analytics
from app.analytics.services import (
    parse_time_range,
    get_analytics_dashboard_data,
    get_analytics_overview,
    get_alert_analytics,
    get_incident_analytics,
    get_vulnerability_analytics,
    get_ids_analytics,
    get_siem_analytics,
    get_detection_analytics,
    get_threat_intel_analytics,
    get_asset_analytics,
    get_trend_analytics,
    get_correlation_analytics,
)

logger = logging.getLogger("cyberdefense.analytics")


def _extract_filter_params():
    """Extracts range and date query params from request."""
    range_param = request.args.get("range", "7d")
    start_param = (
        request.args.get("start")
        or request.args.get("start_date")
        or request.args.get("from")
    )
    end_param = (
        request.args.get("end")
        or request.args.get("end_date")
        or request.args.get("to")
    )
    return range_param, start_param, end_param


# ============================================================================
# Page Views
# ============================================================================

@analytics.route("/", methods=["GET"])
@analytics.route("/dashboard", methods=["GET"])
@login_required
def dashboard_view():
    """Renders the main Analytics Operations Dashboard."""
    return render_template("analytics/dashboard.html")


# ============================================================================
# REST APIs
# ============================================================================

@analytics.route("/api/dashboard", methods=["GET"])
@login_required
def api_dashboard():
    """
    Primary API: returns comprehensive analytics data across all security domains
    for the selected time window.
    """
    try:
        range_param, start_param, end_param = _extract_filter_params()
        data = get_analytics_dashboard_data(range_param, start_param, end_param)
        return jsonify(data)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling analytics dashboard: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics aggregation error."}), 500


@analytics.route("/api/overview", methods=["GET"])
@login_required
def api_overview():
    """Returns high-level summary KPIs."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, interval = parse_time_range(
            range_param, start_param, end_param
        )
        overview = get_analytics_overview(start_dt, end_dt)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "overview": overview,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling analytics overview: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/alerts", methods=["GET"])
@login_required
def api_alerts():
    """Returns security alert analytics."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, _ = parse_time_range(
            range_param, start_param, end_param
        )
        data = get_alert_analytics(start_dt, end_dt)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "alerts": data,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling alert analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/incidents", methods=["GET"])
@login_required
def api_incidents():
    """Returns incident response analytics and MTTR."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, _ = parse_time_range(
            range_param, start_param, end_param
        )
        data = get_incident_analytics(start_dt, end_dt)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "incidents": data,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling incident analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/vulnerabilities", methods=["GET"])
@login_required
def api_vulnerabilities():
    """Returns vulnerability findings analytics."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, _ = parse_time_range(
            range_param, start_param, end_param
        )
        data = get_vulnerability_analytics(start_dt, end_dt)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "vulnerabilities": data,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling vulnerability analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/assets", methods=["GET"])
@login_required
def api_assets():
    """Returns asset inventory risk profiling."""
    try:
        data = get_asset_analytics()
        return jsonify({
            "success": True,
            "assets": data,
        })
    except Exception as e:
        logger.error(f"Error compiling asset analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/ids", methods=["GET"])
@login_required
def api_ids():
    """Returns Network IDS analytics with diagnostic isolation."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, _ = parse_time_range(
            range_param, start_param, end_param
        )
        data = get_ids_analytics(start_dt, end_dt)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ids": data,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling IDS analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/siem", methods=["GET"])
@login_required
def api_siem():
    """Returns SIEM log ingestion analytics."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, _ = parse_time_range(
            range_param, start_param, end_param
        )
        data = get_siem_analytics(start_dt, end_dt)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "siem": data,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling SIEM analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/detection", methods=["GET"])
@login_required
def api_detection():
    """Returns Detection Engine analytics."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, _ = parse_time_range(
            range_param, start_param, end_param
        )
        data = get_detection_analytics(start_dt, end_dt)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "detection": data,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling detection analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/threat-intelligence", methods=["GET"])
@login_required
def api_threat_intelligence():
    """Returns Threat Intelligence database analytics."""
    try:
        data = get_threat_intel_analytics()
        return jsonify({
            "success": True,
            "threat_intel": data,
        })
    except Exception as e:
        logger.error(f"Error compiling threat intelligence analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/trends", methods=["GET"])
@login_required
def api_trends():
    """Returns multi-series time-series trends."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, interval = parse_time_range(
            range_param, start_param, end_param
        )
        data = get_trend_analytics(start_dt, end_dt, interval)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "interval": interval,
            "trends": data,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling trend analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500


@analytics.route("/api/correlations", methods=["GET"])
@login_required
def api_correlations():
    """Returns cross-module correlation matrices."""
    try:
        range_param, start_param, end_param = _extract_filter_params()
        start_dt, end_dt, effective_range, _ = parse_time_range(
            range_param, start_param, end_param
        )
        data = get_correlation_analytics(start_dt, end_dt)
        return jsonify({
            "success": True,
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "correlations": data,
        })
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error compiling correlation analytics: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Internal analytics error."}), 500
