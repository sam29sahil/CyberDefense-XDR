"""
CyberDefense XDR
Audit Logs & Compliance Blueprint
"""

from flask import Blueprint

audit_logs = Blueprint(
    "audit_logs",
    __name__,
    url_prefix="/audit-logs",
    template_folder="../templates",
)

from app.audit_logs import routes  # noqa: F401, E402

