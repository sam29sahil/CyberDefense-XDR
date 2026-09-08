"""
CyberDefense XDR
SOAR Service Orchestration Layer
Manages playbook triggers, status tracking, approval auditing, and execution history.
"""

from datetime import datetime, timezone
import uuid
import json
from app import db
from app.soar.models import SoarPlaybookExecution, SoarApproval
from app.soar.playbooks import PLAYBOOKS_CATALOG, execute_playbook_logic, execute_approved_action


def get_available_playbooks():
    """Returns the registered non-destructive playbook catalog."""
    return PLAYBOOKS_CATALOG


def trigger_playbook_execution(playbook_id, target_entity_type, target_entity_id, input_params=None, user_id=None):
    """
    Initializes and runs an automated playbook execution workflow.
    """
    catalog_entry = next((p for p in PLAYBOOKS_CATALOG if p["id"] == playbook_id), None)
    if not catalog_entry:
        raise ValueError(f"Playbook '{playbook_id}' is not registered.")

    execution_id = str(uuid.uuid4())
    execution = SoarPlaybookExecution(
        execution_id=execution_id,
        playbook_id=playbook_id,
        playbook_name=catalog_entry["name"],
        target_entity_type=target_entity_type or catalog_entry["target_type"],
        target_entity_id=str(target_entity_id),
        input_params_json=json.dumps(input_params or {}),
        status="running",
        user_id=user_id,
    )
    db.session.add(execution)
    db.session.commit()

    try:
        run_res = execute_playbook_logic(
            execution=execution,
            playbook_id=playbook_id,
            target_type=execution.target_entity_type,
            target_id=execution.target_entity_id,
            params=input_params or {},
        )

        execution.status = run_res.get("status", "completed")
        execution.execution_steps_json = json.dumps(run_res.get("steps", []))
        execution.results_json = json.dumps(run_res.get("results", {}))
        execution.summary = run_res.get("summary", "")
        execution.completed_at = datetime.now(timezone.utc)
        db.session.commit()
    except Exception as e:
        execution.status = "failed"
        execution.error_message = str(e)
        execution.completed_at = datetime.now(timezone.utc)
        db.session.commit()
        raise

    return execution


def get_executions(limit=50):
    """Fetches recent playbook executions."""
    return SoarPlaybookExecution.query.order_by(SoarPlaybookExecution.started_at.desc()).limit(limit).all()


def get_execution_by_id(execution_id):
    """Fetches specific playbook execution by ID."""
    return SoarPlaybookExecution.query.filter_by(execution_id=execution_id).first_or_404()


def get_approvals(status=None):
    """Fetches human-in-the-loop approval requests."""
    query = SoarApproval.query
    if status:
        query = query.filter_by(status=status)
    return query.order_by(SoarApproval.requested_at.desc()).all()


def approve_staged_action(approval_id, user_id=None, notes=None):
    """Executes the staged state change after explicit analyst sign-off."""
    approval = SoarApproval.query.filter_by(approval_id=approval_id).first_or_404()
    return execute_approved_action(approval, decided_by_user_id=user_id, notes=notes)


def reject_staged_action(approval_id, user_id=None, notes=None):
    """Rejects a staged action without altering system security state."""
    approval = SoarApproval.query.filter_by(approval_id=approval_id).first_or_404()
    if approval.status != "pending":
        raise ValueError(f"Approval {approval_id} is not pending (status: {approval.status})")

    approval.status = "rejected"
    approval.decided_by_id = user_id
    approval.decision_notes = notes or "Action rejected by analyst."
    approval.decided_at = datetime.now(timezone.utc)
    db.session.commit()
    return approval

