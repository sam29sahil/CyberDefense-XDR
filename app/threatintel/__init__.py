"""
CyberDefense XDR
Threat Intelligence Blueprint
"""

from flask import Blueprint

threatintel = Blueprint(
    "threatintel",
    __name__,
    url_prefix="/threat-intelligence",
)

from app.threatintel import routes  # noqa: E402,F401