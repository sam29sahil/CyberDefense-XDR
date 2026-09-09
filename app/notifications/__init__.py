"""
CyberDefense XDR
Notifications & Alerting Blueprint
"""

from flask import Blueprint

notifications = Blueprint(
    "notifications",
    __name__,
    url_prefix="/notifications",
    template_folder="../templates",
)

from app.notifications import routes  # noqa: F401, E402

