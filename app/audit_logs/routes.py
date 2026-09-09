"""
CyberDefense XDR
Audit Logs Blueprint Routes & APIs
Provides Web page views, RESTful query endpoints, statistics analytics,
and safe CSV export for administrative compliance and security audit trails.
"""

from datetime import datetime
from flask import (
    render_template,
    request,
    jsonify,
    Response,
    redirect,
    url_for,
    flash,
)
from flask_login import login_required, current_user

from app.audit_logs import audit_logs
from app.user_management.decorators import permission_required
from app.audit_logs.services import (
    list_audit_logs,
    get_audit_log_by_id,
    get_audit_statistics,
    export_audit_logs_csv,
)


# ==============================================================================
# HTML Page Views
# ==============================================================================

@audit_logs.route("/", methods=["GET"])
@login_required
@permission_required("audit.view")
def index():
    """Renders the main Audit Logs monitoring and search dashboard."""
    stats = get_audit_statistics()
    categories = [
        "Authentication",
        "Authorization",
        "User Management",
        "Alert Center",
        "Incident Response",
        "Detection Engine",
        "Asset Management",
        "Vulnerability Scanner",
        "Network IDS",
        "Threat Intelligence",
        "Threat Hunting",
        "Correlation",
        "AI Assistant",
        "SOAR",
        "Reports",
        "Settings",
    ]
    return render_template(
        "audit_logs/audit_logs.html",
        stats=stats,
        categories=categories,
    )


@audit_logs.route("/details/<audit_id>", methods=["GET"])
@login_required
@permission_required("audit.view")
def audit_detail(audit_id):
    """Renders the comprehensive record inspection view for a single audit event."""
    log = get_audit_log_by_id(audit_id)
    if not log:
        flash(f"Audit record '{audit_id}' was not found.", "warning")
        return redirect(url_for("audit_logs.index"))

    return render_template(
        "audit_logs/audit_details.html",
        audit=log,
        audit_id=log.get("audit_id"),
    )


# ==============================================================================
# REST APIs
# ==============================================================================

@audit_logs.route("/api", methods=["GET"])
@login_required
@permission_required("audit.view")
def api_audit_logs():
    """
    Returns paginated audit records matching optional query and filter parameters.
    Consistent JSON schema: { success: true, data: [...], pagination: {...} }
    """
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        filters = {
            "search": request.args.get("search"),
            "actor": request.args.get("actor"),
            "action": request.args.get("action"),
            "category": request.args.get("category"),
            "resource_type": request.args.get("resource_type"),
            "resource_id": request.args.get("resource_id"),
            "result": request.args.get("result"),
            "severity": request.args.get("severity"),
            "source_ip": request.args.get("source_ip"),
            "start_time": request.args.get("start_time"),
            "end_time": request.args.get("end_time"),
        }

        res = list_audit_logs(page=page, per_page=per_page, filters=filters)

        return jsonify({
            "success": True,
            "data": res["items"],
            "pagination": {
                "page": res["page"],
                "per_page": res["per_page"],
                "total": res["total"],
                "pages": res["pages"],
            },
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Query Error",
            "message": str(e),
        }), 500


@audit_logs.route("/api/<audit_id>", methods=["GET"])
@login_required
@permission_required("audit.view")
def api_get_audit_log(audit_id):
    """Retrieves detailed record metadata and context for a single audit entry."""
    try:
        log = get_audit_log_by_id(audit_id)
        if not log:
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": f"Audit record '{audit_id}' does not exist.",
            }), 404

        return jsonify({
            "success": True,
            "data": log,
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Internal Error",
            "message": str(e),
        }), 500


@audit_logs.route("/api/stats", methods=["GET"])
@login_required
@permission_required("audit.view")
def api_stats():
    """Returns real database-backed audit metrics and operational distributions."""
    try:
        stats = get_audit_statistics()
        return jsonify({
            "success": True,
            "data": stats,
            "stats": stats,
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Stats Error",
            "message": str(e),
        }), 500


@audit_logs.route("/api/export", methods=["GET"])
@login_required
@permission_required("audit.view")
def api_export():
    """
    Exports filtered audit records as a safe CSV download.
    Mitigates CSV injection and enforces safe streaming boundaries.
    """
    try:
        filters = {
            "search": request.args.get("search"),
            "actor": request.args.get("actor"),
            "action": request.args.get("action"),
            "category": request.args.get("category"),
            "resource_type": request.args.get("resource_type"),
            "resource_id": request.args.get("resource_id"),
            "result": request.args.get("result"),
            "severity": request.args.get("severity"),
            "source_ip": request.args.get("source_ip"),
            "start_time": request.args.get("start_time"),
            "end_time": request.args.get("end_time"),
        }

        csv_content = export_audit_logs_csv(filters=filters)
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"cyberdefense_audit_logs_{timestamp_str}.csv"

        return Response(
            csv_content,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "text/csv; charset=utf-8",
            },
        )

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Export Failed",
            "message": str(e),
        }), 500
