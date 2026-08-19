"""
CyberDefense XDR
Detection Engine Routes
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

from app.detection import detection
from app.detection.models import (
    DetectionRule,
    DetectionEvent,
)

from app.detection.services import (
    create_rule,
    update_rule,
    delete_rule,
    duplicate_rule,
    create_detection_event,
)


# ============================================================
# DASHBOARD
# ============================================================

@detection.route("/dashboard")
@login_required
def dashboard():

    rules = DetectionRule.query.all()

    events = DetectionEvent.query.count()

    active_rules = DetectionRule.query.filter_by(
        status="active"
    ).count()

    return render_template(
        "detection/detection-dashboard.html",
        user=current_user,
        rules=rules,
        event_count=events,
        active_rules=active_rules,
    )


# ============================================================
# RULES
# ============================================================

@detection.route("/rules")
@login_required
def rules_page():

    return render_template(
        "detection/detection-rules.html",
        user=current_user,
    )


@detection.route("/rules/data")
@login_required
def rules_data():

    rules = DetectionRule.query.order_by(
        DetectionRule.created_at.desc()
    ).all()

    return jsonify({
        "success": True,
        "data": [
            rule.to_dict()
            for rule in rules
        ],
    })


# ============================================================
# CREATE RULE
# ============================================================

@detection.route("/rules/create", methods=["GET", "POST"])
@login_required
def create_rule_page():

    if request.method == "GET":

        return render_template(
            "detection/create-rule.html",
            user=current_user,
        )

    data = request.get_json(silent=True) or {}

    try:

        author = (
            f"{current_user.first_name} "
            f"{current_user.last_name}"
        ).strip()

        rule = create_rule(
            data,
            author=author,
        )

        return jsonify({
            "success": True,
            "message": "Detection rule created successfully.",
            "data": rule.to_dict(),
        }), 201

    except ValueError as exc:

        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except Exception:

        from app.extensions import db

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": "Unable to create detection rule.",
        }), 500


# ============================================================
# SINGLE RULE
# ============================================================

@detection.route("/rules/<string:rule_id>")
@login_required
def rule_details(rule_id):

    rule = DetectionRule.query.filter_by(
        rule_id=rule_id
    ).first_or_404()

    return render_template(
        "detection/rule-details.html",
        user=current_user,
        rule=rule,
    )


@detection.route("/rules/<string:rule_id>/data")
@login_required
def rule_data(rule_id):

    rule = DetectionRule.query.filter_by(
        rule_id=rule_id
    ).first_or_404()

    return jsonify({
        "success": True,
        "data": rule.to_dict(),
    })


# ============================================================
# UPDATE RULE
# ============================================================

@detection.route(
    "/rules/<string:rule_id>/update",
    methods=["POST"]
)
@login_required
def update_rule_route(rule_id):

    rule = DetectionRule.query.filter_by(
        rule_id=rule_id
    ).first_or_404()

    data = request.get_json(silent=True) or {}

    try:

        update_rule(
            rule,
            data,
        )

        return jsonify({
            "success": True,
            "message": "Detection rule updated successfully.",
            "data": rule.to_dict(),
        })

    except ValueError as exc:

        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except Exception:

        from app.extensions import db

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": "Unable to update detection rule.",
        }), 500


# ============================================================
# ENABLE / DISABLE
# ============================================================

@detection.route(
    "/rules/<string:rule_id>/toggle",
    methods=["POST"]
)
@login_required
def toggle_rule(rule_id):

    rule = DetectionRule.query.filter_by(
        rule_id=rule_id
    ).first_or_404()

    if rule.status == "disabled":
        rule.status = "active"
    else:
        rule.status = "disabled"

    from app.extensions import db

    db.session.commit()

    return jsonify({
        "success": True,
        "status": rule.status,
        "data": rule.to_dict(),
    })


# ============================================================
# DUPLICATE
# ============================================================

@detection.route(
    "/rules/<string:rule_id>/duplicate",
    methods=["POST"]
)
@login_required
def duplicate_rule_route(rule_id):

    rule = DetectionRule.query.filter_by(
        rule_id=rule_id
    ).first_or_404()

    clone = duplicate_rule(rule)

    return jsonify({
        "success": True,
        "message": "Detection rule duplicated.",
        "data": clone.to_dict(),
    }), 201


# ============================================================
# DELETE
# ============================================================

@detection.route(
    "/rules/<string:rule_id>/delete",
    methods=["POST"]
)
@login_required
def delete_rule_route(rule_id):

    rule = DetectionRule.query.filter_by(
        rule_id=rule_id
    ).first_or_404()

    delete_rule(rule)

    return jsonify({
        "success": True,
        "message": "Detection rule deleted.",
    })


# ============================================================
# DETECTION HISTORY
# ============================================================

@detection.route("/history")
@login_required
def history_page():

    return render_template(
        "detection/detection-history.html",
        user=current_user,
    )


@detection.route("/history/data")
@login_required
def history_data():

    events = DetectionEvent.query.order_by(
        DetectionEvent.timestamp.desc()
    ).all()

    return jsonify({
        "success": True,
        "data": [
            event.to_dict()
            for event in events
        ],
    })


# ============================================================
# CREATE DETECTION EVENT
# ============================================================

@detection.route(
    "/events",
    methods=["POST"]
)
@login_required
def create_event():

    data = request.get_json(silent=True) or {}

    rule_id = data.get("ruleId")

    rule = None

    if rule_id:

        rule = DetectionRule.query.filter_by(
            rule_id=rule_id
        ).first()

        if not rule:
            return jsonify({
                "success": False,
                "message": "Detection rule not found.",
            }), 404

    source = str(
        data.get("source", "")
    ).strip()

    if not source:

        return jsonify({
            "success": False,
            "message": "Detection source is required.",
        }), 400

    event = create_detection_event(
        rule=rule,
        source=source,
        host=data.get("host"),
        severity=data.get("severity"),
        status=data.get("status", "new"),
        raw_event=data.get("rawEvent"),
    )

    return jsonify({
        "success": True,
        "message": "Detection event created.",
        "data": event.to_dict(),
    }), 201