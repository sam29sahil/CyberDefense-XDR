"""
CyberDefense XDR
Alert Center Blueprint
"""

from flask import Blueprint


alerts = Blueprint(
    "alerts",
    __name__,
    url_prefix="/alert-center",
)

import app.alerts.routes  # noqa: F401