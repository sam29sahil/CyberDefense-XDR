"""
CyberDefense XDR
Security Reports Web Routes & REST APIs
Provides routes for report viewing, builder, generation, downloading, and management.
"""

import os
from flask import (
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
)
from flask_login import current_user, login_required

from app.reports import reports
from app.reports.services import (
    REPORT_TYPES,
    create_report,
    delete_report,
    get_report_by_id,
    get_safe_report_path,
    list_reports,
)


# ============================================================
# WEB VIEWS
# ============================================================

@reports.route("/", methods=["GET"])
@login_required
def index():
    """Renders the central Security Reports dashboard & builder page."""
    return render_template(
        "reports/reports.html",
        report_types=list(REPORT_TYPES.values()),
    )


@reports.route("/<report_id>", methods=["GET"])
@login_required
def details(report_id: str):
    """Renders detailed interactive view of an individual generated report."""
    report = get_report_by_id(report_id)
    if not report:
        abort(404, description=f"Report '{report_id}' not found.")
    return render_template(
        "reports/report_details.html",
        report=report,
    )


# ============================================================
# REST APIS
# ============================================================

@reports.route("/api/types", methods=["GET"])
@login_required
def get_types():
    """Returns catalog of all supported security report types."""
    return jsonify({
        "success": True,
        "types": list(REPORT_TYPES.values()),
    })


@reports.route("/api/history", methods=["GET"])
@login_required
def get_history():
    """Returns paginated list of generated reports with optional filters."""
    try:
        page = int(request.args.get("page", 1))
        per_page = min(int(request.args.get("per_page", 20)), 100)
    except (ValueError, TypeError):
        page = 1
        per_page = 20

    report_type = request.args.get("type")
    file_format = request.args.get("format")
    status = request.args.get("status")
    search = request.args.get("search")

    result = list_reports(
        page=page,
        per_page=per_page,
        report_type=report_type,
        file_format=file_format,
        status=status,
        search=search,
    )
    result["success"] = True
    return jsonify(result)


@reports.route("/api/generate", methods=["POST"])
@login_required
def generate():
    """
    Generates a new security report from live telemetry.
    Parses payload, gathers DB telemetry, creates PDF/CSV, and returns report dict.
    """
    data = request.get_json(silent=True) or {}
    report_type = data.get("report_type")
    if not report_type:
        return jsonify({"success": False, "error": "Missing required 'report_type' field."}), 400

    if report_type not in REPORT_TYPES:
        return jsonify({"success": False, "error": f"Invalid report_type '{report_type}'."}), 400

    file_format = data.get("format", "pdf").lower()
    if file_format not in ("pdf", "csv"):
        return jsonify({"success": False, "error": "Invalid format. Supported formats: 'pdf', 'csv'."}), 400

    title = data.get("title")
    description = data.get("description")
    date_preset = data.get("date_range_preset")
    date_from = data.get("date_from")
    date_to = data.get("date_to")
    filters = data.get("filters", {})

    generated_by = getattr(current_user, "username", "SOC Analyst") if hasattr(current_user, "username") else "SOC Analyst"

    try:
        report = create_report(
            report_type=report_type,
            title=title,
            description=description,
            file_format=file_format,
            date_range_preset=date_preset,
            date_from_str=date_from,
            date_to_str=date_to,
            filters=filters,
            generated_by=generated_by,
        )
        return jsonify({
            "success": True,
            "message": f"Report '{report.report_id}' generated successfully.",
            "report": report.to_dict(),
        }), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@reports.route("/api/<report_id>", methods=["GET"])
@login_required
def get_report(report_id: str):
    """Fetches specific report metadata and telemetry summary."""
    report = get_report_by_id(report_id)
    if not report:
        return jsonify({"success": False, "error": f"Report '{report_id}' not found."}), 404
    return jsonify({
        "success": True,
        "report": report.to_dict(),
    })


@reports.route("/api/<report_id>/download", methods=["GET"])
@login_required
def download_report(report_id: str):
    """
    Safely serves the generated PDF or CSV file artifact as an attachment.
    Applies strict path verification to prevent directory traversal.
    """
    report = get_report_by_id(report_id)
    if not report:
        return jsonify({"success": False, "error": f"Report '{report_id}' not found."}), 404

    try:
        safe_path = get_safe_report_path(report.report_id, report.format)
    except ValueError:
        return jsonify({"success": False, "error": "Security error: Invalid report path."}), 400

    if not os.path.isfile(safe_path):
        return jsonify({"success": False, "error": "Report artifact file not found on server."}), 404

    mimetype = "application/pdf" if report.format == "pdf" else "text/csv"
    filename = f"{report.report_id}.{report.format}"

    return send_file(
        safe_path,
        as_attachment=True,
        download_name=filename,
        mimetype=mimetype,
    )


@reports.route("/api/<report_id>", methods=["DELETE"])
@login_required
def remove_report(report_id: str):
    """Deletes a generated report from database and file storage."""
    success = delete_report(report_id)
    if not success:
        return jsonify({"success": False, "error": f"Report '{report_id}' not found."}), 404

    return jsonify({
        "success": True,
        "message": f"Report '{report_id}' successfully deleted.",
    })
