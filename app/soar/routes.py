"""
CyberDefense XDR
SOAR Automation Routes
"""

from flask import render_template, request, jsonify
from flask_login import login_required, current_user
from app.soar import soar
from app.user_management.decorators import permission_required
from app.soar.services import (
    get_available_playbooks,
    trigger_playbook_execution,
    get_executions,
    get_execution_by_id,
    get_approvals,
    approve_staged_action,
    reject_staged_action,
)


@soar.route("/")
@login_required
@permission_required("soar.view")
def dashboard():
    return render_template("soar/dashboard.html")


@soar.route("/playbooks")
@soar.route("/api/playbooks", methods=["GET"])
@login_required
@permission_required("soar.view")
def api_playbooks():
    playbooks = get_available_playbooks()
    return jsonify({
        "status": "success",
        "playbooks": playbooks,
        "count": len(playbooks),
    })


@soar.route("/api/playbooks/<playbook_id>/execute", methods=["POST"])
@login_required
@permission_required("soar.execute")
def api_execute_playbook(playbook_id):
    payload = request.get_json() or {}
    target_id = (payload.get("target_id") or "").strip()
    target_type = (payload.get("target_type") or "").strip()
    params = payload.get("params") or {}

    if not target_id:
        return jsonify({
            "status": "error",
            "message": "target_id parameter is required",
        }), 400

    try:
        user_id = getattr(current_user, "id", None)
        execution = trigger_playbook_execution(
            playbook_id=playbook_id,
            target_entity_type=target_type,
            target_entity_id=target_id,
            input_params=params,
            user_id=user_id,
        )
        return jsonify({
            "status": "success",
            "execution": execution.to_dict(),
        })
    except ValueError as ve:
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@soar.route("/api/executions", methods=["GET"])
@login_required
@permission_required("soar.view")
def api_executions():
    executions = get_executions(limit=50)
    return jsonify({
        "status": "success",
        "executions": [e.to_dict() for e in executions],
    })


@soar.route("/api/executions/<execution_id>", methods=["GET"])
@login_required
@permission_required("soar.view")
def api_get_execution(execution_id):
    execution = get_execution_by_id(execution_id)
    return jsonify({
        "status": "success",
        "execution": execution.to_dict(),
    })


@soar.route("/api/approvals", methods=["GET"])
@login_required
@permission_required("soar.view")
def api_approvals():
    status_filter = request.args.get("status")
    approvals = get_approvals(status=status_filter)
    return jsonify({
        "status": "success",
        "approvals": [a.to_dict() for a in approvals],
        "count": len(approvals),
    })


@soar.route("/api/approvals/<approval_id>/approve", methods=["POST"])
@login_required
@permission_required("soar.approve")
def api_approve(approval_id):
    payload = request.get_json() or {}
    notes = payload.get("notes")
    user_id = getattr(current_user, "id", None)

    try:
        result = approve_staged_action(approval_id, user_id=user_id, notes=notes)
        return jsonify({
            "status": "success",
            "message": "Action successfully approved and applied.",
            "result": result,
        })
    except ValueError as ve:
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@soar.route("/api/approvals/<approval_id>/reject", methods=["POST"])
@login_required
@permission_required("soar.approve")
def api_reject(approval_id):
    payload = request.get_json() or {}
    notes = payload.get("notes")
    user_id = getattr(current_user, "id", None)

    try:
        approval = reject_staged_action(approval_id, user_id=user_id, notes=notes)
        return jsonify({
            "status": "success",
            "message": "Action rejected.",
            "approval": approval.to_dict(),
        })
    except ValueError as ve:
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

