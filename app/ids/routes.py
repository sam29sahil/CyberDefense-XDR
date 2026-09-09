"""
CyberDefense XDR
Network IDS Routes & REST APIs
"""

from flask import (
    render_template,
    request,
    jsonify,
    current_app,
)
from flask_login import current_user

from app.ids import ids
from app.ids import services
from app.audit_logs.services import record_audit_event


# ============================================================
# PAGE ROUTES
# ============================================================

@ids.route("")
@ids.route("/")
@ids.route("/dashboard")
def dashboard():
    """Renders the Network IDS Dashboard."""
    return render_template("ids/dashboard.html")


@ids.route("/events")
def events():
    """Renders the Network IDS Events Explorer."""
    return render_template("ids/events.html")


@ids.route("/events/<event_id>")
def event_details(event_id):
    """Renders the Network IDS Event Detail view."""
    event = services.get_ids_event_by_id(event_id)
    if not event:
        return render_template("ids/event_details.html", event=None, event_id=event_id), 404
    return render_template("ids/event_details.html", event=event.to_dict(), event_id=event_id)


# ============================================================
# REST API ENDPOINTS
# ============================================================

@ids.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    """Returns aggregated Network IDS dashboard KPIs, charts, and top lists."""
    try:
        data = services.get_ids_dashboard_stats()
        return jsonify({
            "success": True,
            "data": data,
            **data,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve IDS dashboard statistics: {str(e)}",
        }), 500


@ids.route("/api/events", methods=["GET"])
def api_events():
    """Returns paginated and filtered Network IDS events."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", request.args.get("limit", 25, type=int), type=int)
        per_page = min(max(per_page, 1), 100)

        filters = {
            "search": request.args.get("q") or request.args.get("search"),
            "severity": request.args.get("severity") or request.args.get("sev"),
            "event_type": request.args.get("event_type") or request.args.get("type"),
            "classification": request.args.get("classification") or request.args.get("class"),
            "protocol": request.args.get("protocol") or request.args.get("proto"),
            "src_ip": request.args.get("src_ip"),
            "dest_ip": request.args.get("dest_ip"),
            "alert_only": request.args.get("alert_only") in ("true", "1", True),
        }

        data = services.get_ids_events(filters=filters, page=page, per_page=per_page)
        return jsonify({
            "success": True,
            **data,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve IDS events: {str(e)}",
        }), 500


@ids.route("/api/events/<event_id>", methods=["GET"])
def api_event_detail(event_id):
    """Returns detailed information for a single Network IDS event."""
    try:
        event = services.get_ids_event_by_id(event_id)
        if not event:
            return jsonify({
                "success": False,
                "message": f"Event '{event_id}' not found.",
            }), 404
        return jsonify({
            "success": True,
            "event": event.to_dict(),
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to fetch event: {str(e)}",
        }), 500


@ids.route("/api/sensor", methods=["GET"])
def api_sensor_status():
    """Returns the verified live operational status of the Network IDS Sensor."""
    try:
        sensor = services.get_sensor_status()
        return jsonify({
            "success": True,
            "sensor": sensor,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve sensor status: {str(e)}",
        }), 500


@ids.route("/api/sensor/start", methods=["POST"])
def api_sensor_start():
    """Starts the Suricata Network IDS sensor on the specified interface."""
    try:
        body = request.get_json(silent=True) or {}
        interface = body.get("interface") or services.DEFAULT_INTERFACE

        success, message = services.start_sensor(
            interface=interface,
            app=current_app._get_current_object(),
        )

        status_code = 200 if success else 400
        sensor_status = services.get_sensor_status()

        record_audit_event(
            action="IDS_SENSOR_START",
            category="Network IDS",
            resource_type="sensor",
            resource_id=interface,
            severity="medium",
            details={"interface": interface, "message": message},
            result="success" if success else "failure",
            sync_to_siem=True,
        )

        return jsonify({
            "success": success,
            "message": message,
            "sensor": sensor_status,
        }), status_code
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Sensor start error: {str(e)}",
        }), 500


@ids.route("/api/sensor/stop", methods=["POST"])
def api_sensor_stop():
    """Stops the Suricata Network IDS sensor."""
    try:
        success, message = services.stop_sensor()
        sensor_status = services.get_sensor_status()

        record_audit_event(
            action="IDS_SENSOR_STOP",
            category="Network IDS",
            resource_type="sensor",
            resource_id="suricata",
            severity="medium",
            details={"message": message},
            result="success" if success else "failure",
            sync_to_siem=True,
        )

        return jsonify({
            "success": success,
            "message": message,
            "sensor": sensor_status,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Sensor stop error: {str(e)}",
        }), 500


@ids.route("/api/sensor/restart", methods=["POST"])
def api_sensor_restart():
    """Restarts the Suricata Network IDS sensor."""
    try:
        body = request.get_json(silent=True) or {}
        interface = body.get("interface") or services.DEFAULT_INTERFACE

        success, message = services.restart_sensor(
            interface=interface,
            app=current_app._get_current_object(),
        )

        status_code = 200 if success else 400
        sensor_status = services.get_sensor_status()

        record_audit_event(
            action="IDS_SENSOR_RESTART",
            category="Network IDS",
            resource_type="sensor",
            resource_id=interface,
            severity="medium",
            details={"interface": interface, "message": message},
            result="success" if success else "failure",
            sync_to_siem=True,
        )

        return jsonify({
            "success": success,
            "message": message,
            "sensor": sensor_status,
        }), status_code
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Sensor restart error: {str(e)}",
        }), 500


@ids.route("/api/rules/update", methods=["POST"])
def api_rules_update():
    """Triggers suricata-update to fetch and compile latest threat rules."""
    try:
        result = services.update_suricata_rules()
        status_code = 200 if result.get("success") else 500

        record_audit_event(
            action="IDS_RULES_UPDATE",
            category="Network IDS",
            resource_type="rules",
            resource_id="suricata-rules",
            severity="low",
            details={"result": result},
            result="success" if result.get("success") else "failure",
        )

        return jsonify(result), status_code
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Rule update execution failed: {str(e)}",
        }), 500


@ids.route("/api/events/<event_id>/create-incident", methods=["POST"])
def api_event_create_incident(event_id):
    """Allows an analyst to escalate an IDS alert into an Incident."""
    try:
        body = request.get_json(silent=True) or {}
        notes = body.get("notes")
        user_id = current_user.id if current_user and current_user.is_authenticated else None

        incident = services.escalate_event_to_incident(
            event_id=event_id,
            user_id=user_id,
            notes=notes,
        )

        return jsonify({
            "success": True,
            "message": f"Incident '{incident.incident_id}' created successfully from IDS alert.",
            "incidentId": incident.incident_id,
        }), 201
    except ValueError as ve:
        return jsonify({
            "success": False,
            "message": str(ve),
        }), 404
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to escalate event: {str(e)}",
        }), 500


@ids.route("/api/logs/status", methods=["GET"])
def api_logs_status():
    """Returns real filesystem metrics for Network IDS log files and archives."""
    try:
        metrics = services.get_ids_log_metrics()
        return jsonify({
            "success": True,
            "data": metrics,
            **metrics,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve IDS log status: {str(e)}",
        }), 500


@ids.route("/api/logs/rotate", methods=["POST"])
def api_logs_rotate():
    """Triggers manual rotation of Network IDS log files exceeding threshold (or force)."""
    try:
        body = request.get_json(silent=True) or {}
        force = bool(body.get("force", False))
        result = services.rotate_ids_logs(force=force)
        metrics = services.get_ids_log_metrics()

        record_audit_event(
            action="IDS_LOG_ROTATE",
            category="Network IDS",
            resource_type="logs",
            resource_id="ids_logs",
            severity="medium" if result.get("rotated") else "low",
            details={
                "rotated_files": result.get("rotated", []),
                "skipped": result.get("skipped", []),
                "force": force,
            },
            result="success" if not result.get("errors") else "partial",
        )

        return jsonify({
            "success": True,
            "message": f"IDS log rotation executed successfully. Rotated: {len(result.get('rotated', []))} file(s).",
            "result": result,
            "metrics": metrics,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Manual log rotation failed: {str(e)}",
        }), 500

