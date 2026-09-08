"""
CyberDefense XDR
SOAR & Security Automation Database Models
Tracks playbook execution history, audit trails, and human-in-the-loop approvals.
"""

from datetime import datetime
from app.extensions import db


class SoarPlaybookExecution(db.Model):
    """Persists SOAR playbook run records and outputs."""

    __tablename__ = "soar_playbook_executions"

    id = db.Column(db.Integer, primary_key=True)
    execution_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    playbook_id = db.Column(db.String(64), nullable=False, index=True)
    playbook_name = db.Column(db.String(128), nullable=False)
    target_entity_type = db.Column(db.String(64), nullable=False)
    target_entity_id = db.Column(db.String(128), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="running", index=True)
    input_params_json = db.Column(db.Text, nullable=True)
    execution_steps_json = db.Column(db.Text, nullable=True)
    results_json = db.Column(db.Text, nullable=True)
    summary = db.Column(db.Text, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    approvals = db.relationship(
        "SoarApproval",
        backref="execution",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def to_dict(self):
        import json

        def _parse(val, default):
            if not val:
                return default
            try:
                return json.loads(val)
            except (ValueError, TypeError):
                return default

        return {
            "id": self.id,
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "target_entity_type": self.target_entity_type,
            "target_entity_id": self.target_entity_id,
            "status": self.status,
            "input_params": _parse(self.input_params_json, {}),
            "execution_steps": _parse(self.execution_steps_json, []),
            "results": _parse(self.results_json, {}),
            "summary": self.summary,
            "error_message": self.error_message,
            "user_id": self.user_id,
            "started_at": self.started_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.started_at else None,
            "completed_at": self.completed_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.completed_at else None,
            "pending_approvals": [a.to_dict() for a in self.approvals.filter_by(status="pending").all()],
        }


class SoarApproval(db.Model):
    """Enforces analyst sign-off before modifying security state."""

    __tablename__ = "soar_approvals"

    id = db.Column(db.Integer, primary_key=True)
    approval_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    execution_id = db.Column(db.Integer, db.ForeignKey("soar_playbook_executions.id"), nullable=False, index=True)
    action_type = db.Column(db.String(64), nullable=False)
    action_name = db.Column(db.String(128), nullable=False)
    target_entity_type = db.Column(db.String(64), nullable=False)
    target_entity_id = db.Column(db.String(128), nullable=False)
    change_payload_json = db.Column(db.Text, nullable=False)
    expected_impact = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
    decision_notes = db.Column(db.Text, nullable=True)
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    decided_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    requested_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    decided_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        import json

        def _parse(val):
            if not val:
                return {}
            try:
                return json.loads(val)
            except (ValueError, TypeError):
                return {}

        return {
            "id": self.id,
            "approval_id": self.approval_id,
            "execution_id": self.execution_id,
            "action_type": self.action_type,
            "action_name": self.action_name,
            "target_entity_type": self.target_entity_type,
            "target_entity_id": self.target_entity_id,
            "change_payload": _parse(self.change_payload_json),
            "expected_impact": self.expected_impact,
            "status": self.status,
            "decision_notes": self.decision_notes,
            "requested_by_id": self.requested_by_id,
            "decided_by_id": self.decided_by_id,
            "requested_at": self.requested_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.requested_at else None,
            "decided_at": self.decided_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.decided_at else None,
        }

