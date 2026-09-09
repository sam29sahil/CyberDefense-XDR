"""
CyberDefense XDR
Vulnerability Scanner & Scan History Routes & REST APIs
"""

from flask import (
    render_template,
    request,
    jsonify,
    current_app,
)
from flask_login import current_user

from app.scanner import scanner
from app.scanner import services
from app.audit_logs.services import record_audit_event


# ============================================================
# PAGE ROUTES
# ============================================================

@scanner.route("/")
@scanner.route("/dashboard")
def index():
    """Renders the Vulnerability Scanner Dashboard."""
    try:
        services.seed_initial_scanner_data()
    except Exception:
        pass
    return render_template("scanner/scanner-dashboard.html")


@scanner.route("/history")
def history():
    """Renders the Scan History page."""
    try:
        services.seed_initial_scanner_data()
    except Exception:
        pass
    return render_template("scanner/scan-history.html")


@scanner.route("/new")
def new_scan():
    """Renders the New Scan creation form."""
    try:
        services.seed_initial_scanner_data()
    except Exception:
        pass
    return render_template("scanner/new-scan.html")


@scanner.route("/details")
@scanner.route("/details/<scan_id>")
def scan_details(scan_id=None):
    """Renders the Scan Details page."""
    try:
        services.seed_initial_scanner_data()
    except Exception:
        pass
    selected_id = scan_id or request.args.get("id")
    return render_template("scanner/scan-details.html", scan_id=selected_id)


@scanner.route("/vulnerability-details")
@scanner.route("/vulnerabilities/<vuln_id>")
def vulnerability_details(vuln_id=None):
    """Renders the Vulnerability Details page."""
    try:
        services.seed_initial_scanner_data()
    except Exception:
        pass
    selected_id = vuln_id or request.args.get("id")
    return render_template("scanner/vulnerability-details.html", vuln_id=selected_id)


@scanner.route("/targets", endpoint="targets")
@scanner.route("/targets", endpoint="targets_view")
def targets():
    """Renders the Scan Targets management page."""
    try:
        services.seed_initial_scanner_data()
    except Exception:
        pass
    return render_template("scanner/targets.html")


# ============================================================
# REST API ENDPOINTS
# ============================================================

@scanner.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    """Returns aggregated scanner dashboard KPIs, charts, and tables."""
    try:
        services.seed_initial_scanner_data()
        data = services.get_scanner_dashboard_stats()
        return jsonify({
            "success": True,
            "data": data,
            "kpis": data.get("kpi") or [],
            "kpi": data.get("kpi") or [],
            "trend": data.get("trend") or [],
            "severity_distribution": data.get("severity_distribution") or {},
            "recent_scans": data.get("recent_scans") or [],
            "top_affected_hosts": data.get("top_hosts") or [],
            "top_hosts": data.get("top_hosts") or [],
            "critical_vulnerabilities": data.get("critical_vulns") or [],
            "critical_vulns": data.get("critical_vulns") or [],
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Failed to load scanner dashboard metrics: {str(e)}",
        }), 500


@scanner.route("/api/scans", methods=["GET"])
def api_get_scans():
    """Returns paginated, searchable, and filtered scans list."""
    try:
        services.seed_initial_scanner_data()
        status = request.args.get("status")
        scan_type = request.args.get("type")
        search = request.args.get("q") or request.args.get("search")
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", request.args.get("limit", 10, type=int), type=int)

        result = services.get_scans(
            status=status,
            scan_type=scan_type,
            search=search,
            page=page,
            per_page=per_page,
        )
        return jsonify({
            "success": True,
            "data": result["items"],
            "scans": result["items"],
            "pagination": {
                "total": result["total"],
                "page": result["page"],
                "per_page": result["per_page"],
                "pages": result["pages"],
            },
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Failed to retrieve scans: {str(e)}",
        }), 500


@scanner.route("/api/scans", methods=["POST"])
def api_create_scan():
    """
    Creates and launches a new vulnerability scan.
    Enforces authorized local/lab target validation.
    """
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({
            "success": False,
            "message": "Missing JSON payload.",
        }), 400

    try:
        user_name = "Analyst"
        if hasattr(current_user, "is_authenticated") and current_user.is_authenticated:
            user_name = getattr(current_user, "username", "Analyst")

        app_obj = current_app._get_current_object()
        scan = services.create_scan(
            data=payload,
            user_name=user_name,
            run_immediately=True,
            app=app_obj,
        )

        try:
            record_audit_event(
                action="SCAN_LAUNCH",
                category="Vulnerability Scanner",
                resource_type="scan",
                resource_id=scan.scan_id,
                severity="low",
                details={
                    "name": scan.name,
                    "targets": getattr(scan, "targets", None) or getattr(scan, "targets_json", None),
                    "tool": getattr(scan, "scan_type", "Scan"),
                },
                result="success",
                sync_to_siem=True,
            )
        except Exception as audit_err:
            current_app.logger.warning(f"Failed to record scan audit event: {audit_err}")

        return jsonify({
            "success": True,
            "message": f"Scan '{scan.name}' ({scan.scan_id}) initiated successfully.",
            "data": scan.to_dict(),
            "scan": scan.to_dict(),
        }), 201
    except ValueError as ve:
        return jsonify({
            "success": False,
            "error": str(ve),
            "message": str(ve),
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Failed to launch scan: {str(e)}",
        }), 500


@scanner.route("/api/scans/<scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    """Returns detailed information and findings for a single scan."""
    try:
        services.seed_initial_scanner_data()
        data = services.get_scan_by_id(scan_id)
        if not data:
            return jsonify({
                "success": False,
                "message": f"Scan '{scan_id}' not found.",
            }), 404

        return jsonify({
            "success": True,
            "data": data,
            "scan": data,
            "findings": data.get("findings", []),
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve scan details: {str(e)}",
        }), 500


@scanner.route("/api/scans/<scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    """Deletes a scan and its associated findings."""
    try:
        deleted = services.delete_scan(scan_id)
        if not deleted:
            return jsonify({
                "success": False,
                "message": f"Scan '{scan_id}' not found.",
            }), 404

        record_audit_event(
            action="SCAN_DELETE",
            category="Vulnerability Scanner",
            resource_type="scan",
            resource_id=scan_id,
            severity="low",
            details={},
            result="success",
        )

        return jsonify({
            "success": True,
            "message": f"Scan '{scan_id}' deleted successfully.",
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to delete scan: {str(e)}",
        }), 500


@scanner.route("/api/tools", methods=["GET"])
def api_get_tools():
    """Returns dynamic availability and versions of scanner security tools."""
    try:
        tools = services.get_available_tools()
        availability = {k: v.get("available", False) for k, v in tools.items()}
        return jsonify({
            "success": True,
            "data": tools,
            "tools": tools,
            "availability": availability,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Failed to retrieve tools: {str(e)}",
        }), 500


@scanner.route("/api/scans/<scan_id>/services", methods=["GET"])
def api_get_scan_services(scan_id):
    """Returns discovered service/exposure observations for a specific scan."""
    try:
        services.seed_initial_scanner_data()
        scan = services.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({
                "success": False,
                "message": f"Scan with ID '{scan_id}' not found.",
            }), 404

        obs = scan.get("serviceObservations") or []
        return jsonify({
            "success": True,
            "scan_id": scan.get("id") or scan_id,
            "count": len(obs),
            "services": obs,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve scan services: {str(e)}",
        }), 500



@scanner.route("/api/scans/<scan_id>/findings", methods=["GET"])
def api_get_scan_findings(scan_id):
    """Returns paginated/filtered findings for a specific scan."""
    try:
        services.seed_initial_scanner_data()
        severity = request.args.get("severity") or request.args.get("sev")
        tool = request.args.get("tool")
        search = request.args.get("q") or request.args.get("search")
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", request.args.get("limit", 50, type=int), type=int)

        result = services.get_scan_findings(
            scan_id=scan_id,
            severity=severity,
            tool=tool,
            search=search,
            page=page,
            per_page=per_page,
        )
        if result is None:
            return jsonify({
                "success": False,
                "message": f"Scan '{scan_id}' not found.",
            }), 404

        return jsonify({
            "success": True,
            "data": result["items"],
            "findings": result["items"],
            "pagination": {
                "total": result["total"],
                "page": result["page"],
                "per_page": result["per_page"],
                "pages": result["pages"],
            },
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Failed to retrieve findings for scan: {str(e)}",
        }), 500


@scanner.route("/api/vulnerabilities", methods=["GET"])
def api_get_vulnerabilities():
    """Returns filtered and paginated vulnerabilities list."""
    try:
        services.seed_initial_scanner_data()
        severity = request.args.get("severity") or request.args.get("sev")
        status = request.args.get("status")
        search = request.args.get("q") or request.args.get("search")
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", request.args.get("limit", 20, type=int), type=int)

        result = services.get_vulnerabilities(
            severity=severity,
            status=status,
            search=search,
            page=page,
            per_page=per_page,
        )
        return jsonify({
            "success": True,
            "data": result["items"],
            "pagination": {
                "total": result["total"],
                "page": result["page"],
                "per_page": result["per_page"],
                "pages": result["pages"],
            },
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve vulnerabilities: {str(e)}",
        }), 500


@scanner.route("/api/vulnerabilities/<vuln_id>", methods=["GET"])
def api_get_vulnerability(vuln_id):
    """Returns single vulnerability finding by ID."""
    try:
        services.seed_initial_scanner_data()
        vuln = services.get_vulnerability_by_id(vuln_id)
        if not vuln:
            return jsonify({
                "success": False,
                "message": f"Vulnerability '{vuln_id}' not found.",
            }), 404

        return jsonify({
            "success": True,
            "data": vuln,
            "vulnerability": vuln,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve vulnerability: {str(e)}",
        }), 500


@scanner.route("/api/vulnerabilities/<vuln_id>/status", methods=["POST", "PATCH"])
def api_update_vulnerability_status(vuln_id):
    """Updates the lifecycle status of a vulnerability finding."""
    payload = request.get_json(silent=True) or {}
    new_status = payload.get("status") or request.form.get("status")
    if not new_status:
        return jsonify({
            "success": False,
            "message": "Missing 'status' field.",
        }), 400

    try:
        updated = services.update_vulnerability_status(vuln_id, new_status)
        if not updated:
            return jsonify({
                "success": False,
                "message": f"Vulnerability '{vuln_id}' not found.",
            }), 404

        return jsonify({
            "success": True,
            "message": f"Vulnerability '{vuln_id}' status updated to '{new_status}'.",
            "data": updated,
        }), 200
    except ValueError as ve:
        return jsonify({
            "success": False,
            "message": str(ve),
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to update status: {str(e)}",
        }), 500


@scanner.route("/api/targets", methods=["GET"])
def api_get_targets():
    """Returns list of configured scan targets."""
    try:
        services.seed_initial_scanner_data()
        targets_list = services.get_targets()
        return jsonify({
            "success": True,
            "data": targets_list,
            "targets": targets_list,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Failed to load targets: {str(e)}",
        }), 500


@scanner.route("/api/targets", methods=["POST"])
def api_create_target():
    """Adds a new scan target."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({
            "success": False,
            "error": "Missing JSON payload.",
            "message": "Missing JSON payload.",
        }), 400

    try:
        user_name = "Analyst"
        if hasattr(current_user, "is_authenticated") and current_user.is_authenticated:
            user_name = getattr(current_user, "username", "Analyst")

        target = services.create_target(payload, owner=user_name)
        record_audit_event(
            action="TARGET_CREATE",
            category="Vulnerability Scanner",
            resource_type="target",
            resource_id=str(target.id),
            severity="low",
            details={"name": target.name, "target": target.target, "target_type": target.target_type},
            result="success",
        )
        return jsonify({
            "success": True,
            "message": f"Target '{target.name}' added successfully.",
            "data": target.to_dict(),
            "target": target.to_dict(),
        }), 201
    except ValueError as ve:
        return jsonify({
            "success": False,
            "error": str(ve),
            "message": str(ve),
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Failed to create target: {str(e)}",
        }), 500


@scanner.route("/api/targets/<target_id>", methods=["DELETE"])
def api_delete_target(target_id):
    """Deletes a configured scan target."""
    try:
        deleted = services.delete_target(target_id)
        if not deleted:
            return jsonify({
                "success": False,
                "message": f"Target '{target_id}' not found.",
            }), 404

        record_audit_event(
            action="TARGET_DELETE",
            category="Vulnerability Scanner",
            resource_type="target",
            resource_id=str(target_id),
            severity="low",
            details={},
            result="success",
        )

        return jsonify({
            "success": True,
            "message": f"Target '{target_id}' deleted successfully.",
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": f"Failed to delete target: {str(e)}",
        }), 500

