"""
CyberDefense XDR
Alert Center Routes
"""

import logging
from flask import (
    render_template,
    request,
    jsonify,
    abort,
)
from flask_login import (
    login_required,
    current_user,
)

from app.extensions import db
from app.alerts import alerts
from app.alerts.models import Alert
from app.alerts.services import (
    get_alert,
    get_alert_by_id,
    get_alerts,
    get_alert_statistics,
    create_alert,
    acknowledge_alert,
    change_alert_status,
    assign_alert,
    resolve_alert,
    link_alert_to_incident,
    create_incident_from_alert,
)
from app.users.models import User
from app.user_management.decorators import permission_required
from app.audit_logs.services import record_audit_event

logger = logging.getLogger(__name__)


# ============================================================
# ALERT CENTER PAGE & DATA
# ============================================================

@alerts.route("/", methods=["GET"])
@login_required
def index():
    """
    Render main Alert Center dashboard.
    """
    stats = get_alert_statistics()
    users = User.query.filter_by(is_active=True).order_by(User.first_name.asc()).all()
    return render_template(
        "alerts/alert-center.html",
        user=current_user,
        stats=stats,
        users=users,
    )


@alerts.route("/data", methods=["GET"])
@login_required
def alert_data():
    """
    Fetch paginated alert records with filters and KPI metrics.
    """
    try:
        page = request.args.get("page", 1, type=int)
        per_page = min(request.args.get("per_page", 20, type=int), 100)

        filters = {
            "search": request.args.get("search"),
            "severity": request.args.get("severity"),
            "status": request.args.get("status"),
            "category": request.args.get("category"),
            "source": request.args.get("source"),
            "assigned_to": request.args.get("assigned_to"),
            "start_date": request.args.get("start_date"),
            "end_date": request.args.get("end_date"),
        }

        result = get_alerts(filters=filters, page=page, per_page=per_page)
        stats = get_alert_statistics()

        return jsonify({
            "success": True,
            "data": [item.to_dict() for item in result["items"]],
            "total": result["total"],
            "page": result["page"],
            "per_page": result["per_page"],
            "stats": stats,
        }), 200

    except Exception as exc:
        logger.error(f"Error fetching alerts data: {exc}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Unable to load alerts.",
        }), 500


# ============================================================
# ALERT DETAILS & SINGLE DATA
# ============================================================

@alerts.route("/api/stats", methods=["GET"])
@alerts.route("/stats", methods=["GET"])
@login_required
@permission_required("alerts.view")
def alert_stats():
    """
    Return alert statistics KPI metrics.
    """
    stats = get_alert_statistics()
    return jsonify({
        "success": True,
        "data": stats,
    }), 200


@alerts.route("/<string:alert_id>", methods=["GET"])
@login_required
def alert_details(alert_id):
    """
    Render detail view for a specific alert.
    """
    alert = get_alert(alert_id)
    if not alert:
        abort(404)

    users = User.query.filter_by(is_active=True).order_by(User.first_name.asc()).all()
    return render_template(
        "alerts/alert-details.html",
        user=current_user,
        alert=alert,
        users=users,
    )


@alerts.route("/<string:alert_id>/data", methods=["GET"])
@login_required
def alert_data_single(alert_id):
    """
    Return JSON data for a single alert and related alerts.
    """
    alert = get_alert(alert_id)
    if not alert:
        return jsonify({
            "success": False,
            "message": f"Alert '{alert_id}' not found.",
        }), 404

    # Related alerts by same host or source (limit 5)
    related = []
    if alert.affected_host:
        related = (
            Alert.query.filter(
                Alert.affected_host == alert.affected_host,
                Alert.id != alert.id,
            )
            .order_by(Alert.created_at.desc())
            .limit(5)
            .all()
        )

    assignee_info = None
    if alert.assignee:
        assignee_info = {
            "id": alert.assignee.id,
            "name": alert.assignee.full_name or alert.assignee.username,
            "email": alert.assignee.email,
            "role": alert.assignee.role,
        }

    return jsonify({
        "success": True,
        "data": alert.to_dict(),
        "assignee": assignee_info,
        "related": [r.to_dict() for r in related],
        "message": None,
    }), 200


# ============================================================
# ALERT ACTIONS & MUTATIONS
# ============================================================

@alerts.route("/create", methods=["POST"])
@login_required
@permission_required("alerts.modify")
def create_alert_route():
    """
    Create a new manual alert.
    """
    data = request.get_json(silent=True) or {}
    try:
        alert = create_alert(data, user=current_user)
        record_audit_event(
            action="ALERT_CREATE",
            category="Alert Center",
            resource_type="alert",
            resource_id=alert.alert_id,
            severity="low",
            details={"title": alert.title, "severity": alert.severity, "source": alert.source},
            result="success",
            sync_to_siem=True,
        )
        return jsonify({
            "success": True,
            "message": f"Alert {alert.alert_id} created successfully.",
            "data": alert.to_dict(),
        }), 201
    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Error creating alert: {exc}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Unable to create alert.",
        }), 500


@alerts.route("/<string:alert_id>/acknowledge", methods=["POST"])
@login_required
@permission_required("alerts.modify")
def acknowledge_alert_route(alert_id):
    """
    Acknowledge an alert.
    """
    alert = get_alert(alert_id)
    if not alert:
        return jsonify({
            "success": False,
            "message": f"Alert '{alert_id}' not found.",
        }), 404

    try:
        alert = acknowledge_alert(alert, user=current_user)
        record_audit_event(
            action="ALERT_ACKNOWLEDGE",
            category="Alert Center",
            resource_type="alert",
            resource_id=alert.alert_id,
            severity="low",
            details={"status": alert.status},
            result="success",
        )
        return jsonify({
            "success": True,
            "message": f"Alert {alert.alert_id} acknowledged.",
            "data": alert.to_dict(),
        }), 200
    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Error acknowledging alert: {exc}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Unable to acknowledge alert.",
        }), 500


@alerts.route("/<string:alert_id>/resolve", methods=["POST"])
@login_required
@permission_required("alerts.modify")
def resolve_alert_route(alert_id):
    """
    Resolve an alert with closing notes.
    """
    alert = get_alert(alert_id)
    if not alert:
        return jsonify({
            "success": False,
            "message": f"Alert '{alert_id}' not found.",
        }), 404

    data = request.get_json(silent=True) or {}
    resolution_notes = data.get("resolution_notes") or data.get("notes")

    try:
        alert = resolve_alert(alert, resolution_notes, user=current_user)
        record_audit_event(
            action="ALERT_RESOLVE",
            category="Alert Center",
            resource_type="alert",
            resource_id=alert.alert_id,
            severity="low",
            details={"status": alert.status, "resolution_notes": resolution_notes},
            result="success",
        )
        return jsonify({
            "success": True,
            "message": f"Alert {alert.alert_id} resolved.",
            "data": alert.to_dict(),
        }), 200
    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Error resolving alert: {exc}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Unable to resolve alert.",
        }), 500


@alerts.route("/<string:alert_id>/assign", methods=["POST"])
@login_required
@permission_required("alerts.modify")
def assign_alert_route(alert_id):
    """
    Assign an alert to an analyst.
    """
    alert = get_alert(alert_id)
    if not alert:
        return jsonify({
            "success": False,
            "message": f"Alert '{alert_id}' not found.",
        }), 404

    data = request.get_json(silent=True) or {}
    user_id = data.get("assigned_to") or data.get("user_id")
    notes = data.get("notes")

    try:
        alert = assign_alert(alert, user_id=user_id, notes=notes, current_user=current_user)
        record_audit_event(
            action="ALERT_ASSIGN",
            category="Alert Center",
            resource_type="alert",
            resource_id=alert.alert_id,
            severity="low",
            details={"assigned_to": user_id, "notes": notes},
            result="success",
        )
        return jsonify({
            "success": True,
            "message": f"Alert {alert.alert_id} assignment updated.",
            "data": alert.to_dict(),
        }), 200
    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Error assigning alert: {exc}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Unable to assign alert.",
        }), 500


@alerts.route("/<string:alert_id>/status", methods=["POST"])
@login_required
@permission_required("alerts.modify")
def change_status_route(alert_id):
    """
    Change alert status respecting the lifecycle state machine.
    """
    alert = get_alert(alert_id)
    if not alert:
        return jsonify({
            "success": False,
            "message": f"Alert '{alert_id}' not found.",
        }), 404

    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    notes = data.get("notes")

    if not new_status:
        return jsonify({
            "success": False,
            "message": "Status field is required.",
        }), 400

    try:
        alert = change_alert_status(alert, new_status, notes=notes, user=current_user)
        record_audit_event(
            action="ALERT_STATUS_UPDATE",
            category="Alert Center",
            resource_type="alert",
            resource_id=alert.alert_id,
            severity="low",
            details={"new_status": new_status, "notes": notes},
            result="success",
        )
        return jsonify({
            "success": True,
            "message": f"Alert {alert.alert_id} status updated to {alert.status}.",
            "data": alert.to_dict(),
        }), 200
    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Error updating alert status: {exc}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Unable to update alert status.",
        }), 500


@alerts.route("/<string:alert_id>/escalate", methods=["POST"])
@alerts.route("/<string:alert_id>/link-incident", methods=["POST"])
@login_required
@permission_required("alerts.modify")
def link_incident_route(alert_id):
    """
    Link an existing incident or create a new incident from the alert.
    Also handles alert escalation to incident via /<alert_id>/escalate.
    """
    alert = get_alert(alert_id)
    if not alert:
        return jsonify({
            "success": False,
            "message": f"Alert '{alert_id}' not found.",
        }), 404

    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    is_escalate_route = request.path.endswith("/escalate")
    create_new = data.get("create_new", True if is_escalate_route and not incident_id else False)

    try:
        if incident_id and not create_new:
            # Link existing incident
            alert = link_alert_to_incident(alert, incident_id)
            return jsonify({
                "success": True,
                "message": f"Alert {alert.alert_id} linked to Incident {incident_id}.",
                "data": alert.to_dict(),
            }), 200
        else:
            # Create a new incident from this alert
            incident = create_incident_from_alert(alert, current_user=current_user, extra_data=data)
            return jsonify({
                "success": True,
                "message": f"Incident {incident.incident_id} created from alert {alert.alert_id}.",
                "data": {
                    "alert": alert.to_dict(),
                    "incident": incident.to_dict(),
                },
            }), 201
    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Error linking/creating incident for alert: {exc}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Unable to link or create incident.",
        }), 500

