"""
CyberDefense XDR
Incident Response Routes
"""

from flask import (
    render_template,
    request,
    jsonify,
)

from flask_login import (
    login_required,
    current_user,
)

from app.extensions import db

from app.incidents import incidents

from app.incidents.models import Incident

from app.incidents.services import (
    create_incident,
    update_incident,
    assign_incident,
    change_status,
    resolve_incident,
    close_incident,
    delete_incident,
    create_incident_from_detection,
)

from app.detection.models import DetectionEvent

from app.users.models import User


# ============================================================
# DASHBOARD
# ============================================================

@incidents.route("/dashboard")
@login_required
def dashboard():

    total = Incident.query.count()

    new_count = Incident.query.filter_by(
        status="new"
    ).count()

    investigating_count = Incident.query.filter_by(
        status="investigating"
    ).count()

    contained_count = Incident.query.filter_by(
        status="contained"
    ).count()

    resolved_count = Incident.query.filter_by(
        status="resolved"
    ).count()

    critical_count = Incident.query.filter_by(
        severity="critical"
    ).filter(
        Incident.status.notin_(["resolved", "closed"])
    ).count()

    recent = Incident.query.order_by(
        Incident.created_at.desc()
    ).limit(10).all()

    return render_template(
        "incidents/incident-dashboard.html",
        user=current_user,
        total=total,
        new_count=new_count,
        investigating_count=investigating_count,
        contained_count=contained_count,
        resolved_count=resolved_count,
        critical_count=critical_count,
        recent=recent,
    )


# ============================================================
# INCIDENT LIST
# ============================================================

@incidents.route("/")
@login_required
def incident_list():

    incidents_list = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()

    return render_template(
        "incidents/incident-list.html",
        user=current_user,
        incidents=incidents_list,
    )


# ============================================================
# INCIDENT DATA
# ============================================================

@incidents.route("/data")
@login_required
def incident_data():

    incidents_list = Incident.query.order_by(
        Incident.created_at.desc()
    ).all()

    return jsonify({
        "success": True,
        "data": [
            incident.to_dict()
            for incident in incidents_list
        ],
    })


# ============================================================
# CREATE INCIDENT
# ============================================================

@incidents.route(
    "/create",
    methods=["GET", "POST"]
)
@login_required
def create_incident_page():

    if request.method == "GET":

        users = User.query.order_by(
            User.email.asc()
        ).all()

        return render_template(
            "incidents/create-incident.html",
            user=current_user,
            users=users,
        )

    data = request.get_json(
        silent=True
    ) or {}

    try:

        incident = create_incident(
            data,
            created_by=current_user,
        )

        return jsonify({
            "success": True,
            "message": (
                "Incident created successfully."
            ),
            "data": incident.to_dict(),
        }), 201

    except ValueError as exc:

        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to create incident."
            ),
        }), 500


# ============================================================
# INCIDENT DETAILS
# ============================================================

@incidents.route(
    "/<string:incident_id>"
)
@login_required
def incident_details(incident_id):

    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    return render_template(
        "incidents/incident-details.html",
        user=current_user,
        incident=incident,
    )


# ============================================================
# SINGLE INCIDENT DATA
# ============================================================

@incidents.route(
    "/<string:incident_id>/data"
)
@login_required
def incident_data_single(incident_id):

    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    return jsonify({
        "success": True,
        "data": incident.to_dict(),
    })


# ============================================================
# UPDATE INCIDENT
# ============================================================

@incidents.route(
    "/<string:incident_id>/update",
    methods=["POST"]
)
@login_required
def update_incident_route(incident_id):

    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    data = request.get_json(
        silent=True
    ) or {}

    try:

        update_incident(
            incident,
            data,
        )

        return jsonify({
            "success": True,
            "message": (
                "Incident updated successfully."
            ),
            "data": incident.to_dict(),
        })

    except ValueError as exc:

        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to update incident."
            ),
        }), 500


# ============================================================
# ASSIGN INCIDENT
# ============================================================

@incidents.route(
    "/<string:incident_id>/assign",
    methods=["POST"]
)
@login_required
def assign_incident_route(incident_id):

    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    data = request.get_json(
        silent=True
    ) or {}

    user_id = data.get(
        "userId"
    )

    if not user_id:

        return jsonify({
            "success": False,
            "message": "User ID is required.",
        }), 400

    user = User.query.get(user_id)

    if not user:

        return jsonify({
            "success": False,
            "message": "User not found.",
        }), 404

    try:

        assign_incident(
            incident,
            user.id,
        )

        return jsonify({
            "success": True,
            "message": (
                "Incident assigned successfully."
            ),
            "data": incident.to_dict(),
        })

    except ValueError as exc:

        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to assign incident."
            ),
        }), 500


# ============================================================
# CHANGE STATUS
# ============================================================

@incidents.route(
    "/<string:incident_id>/status",
    methods=["POST"]
)
@login_required
def change_incident_status(incident_id):

    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    data = request.get_json(
        silent=True
    ) or {}

    status = data.get(
        "status"
    )

    if not status:

        return jsonify({
            "success": False,
            "message": "Status is required.",
        }), 400

    try:

        change_status(
            incident,
            status,
        )

        return jsonify({
            "success": True,
            "message": (
                "Incident status updated."
            ),
            "data": incident.to_dict(),
        })

    except ValueError as exc:

        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to change incident status."
            ),
        }), 500


# ============================================================
# RESOLVE INCIDENT
# ============================================================

@incidents.route(
    "/<string:incident_id>/resolve",
    methods=["POST"]
)
@login_required
def resolve_incident_route(incident_id):

    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    data = request.get_json(
        silent=True
    ) or {}

    try:

        resolve_incident(
            incident,
            resolution_notes=data.get(
                "resolutionNotes"
            ),
        )

        return jsonify({
            "success": True,
            "message": (
                "Incident resolved successfully."
            ),
            "data": incident.to_dict(),
        })

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to resolve incident."
            ),
        }), 500


# ============================================================
# CLOSE INCIDENT
# ============================================================

@incidents.route(
    "/<string:incident_id>/close",
    methods=["POST"]
)
@login_required
def close_incident_route(incident_id):

    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    try:

        close_incident(
            incident
        )

        return jsonify({
            "success": True,
            "message": (
                "Incident closed successfully."
            ),
            "data": incident.to_dict(),
        })

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to close incident."
            ),
        }), 500


# ============================================================
# DELETE INCIDENT
# ============================================================

@incidents.route(
    "/<string:incident_id>/delete",
    methods=["POST"]
)
@login_required
def delete_incident_route(incident_id):

    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    try:

        delete_incident(
            incident
        )

        return jsonify({
            "success": True,
            "message": (
                "Incident deleted successfully."
            ),
        })

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to delete incident."
            ),
        }), 500


# ============================================================
# CREATE INCIDENT FROM DETECTION EVENT
# ============================================================

@incidents.route(
    "/from-detection/<string:event_id>",
    methods=["POST"]
)
@login_required
def incident_from_detection(event_id):

    event = DetectionEvent.query.filter_by(
        event_id=event_id
    ).first_or_404()

    try:

        incident = create_incident_from_detection(
            event,
            created_by=current_user,
        )

        return jsonify({
            "success": True,
            "message": (
                "Incident created from "
                "detection event."
            ),
            "data": incident.to_dict(),
        }), 201

    except ValueError as exc:

        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to create incident "
                "from detection event."
            ),
        }), 500

# ============================================================
# INCIDENT RESPONSE SUPPORT PAGES
# ============================================================

@incidents.route("/<string:incident_id>/evidence")
@login_required
def evidence(incident_id):
    """Incident evidence locker page."""
    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    return render_template(
        "incidents/evidence.html",
        incident=incident
    )


@incidents.route("/<string:incident_id>/timeline")
@login_required
def timeline(incident_id):
    """Incident investigation timeline page."""
    incident = Incident.query.filter_by(
        incident_id=incident_id
    ).first_or_404()

    return render_template(
        "incidents/timeline.html",
        incident=incident
    )


@incidents.route("/playbooks")
@login_required
def playbooks():
    """Incident response playbooks page."""
    return render_template(
        "incidents/playbooks.html"
    )       