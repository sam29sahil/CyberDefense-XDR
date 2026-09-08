"""
CyberDefense XDR
Threat Hunting Blueprint
"""

from flask import Blueprint

threat_hunting = Blueprint(
    "threat_hunting",
    __name__,
    url_prefix="/threat-hunting",
    template_folder="../templates",
)

from app.threat_hunting import routes  # noqa: F401, E402

