"""
CyberDefense XDR
SIEM & Log Explorer Blueprint
"""

from flask import Blueprint

siem = Blueprint(
    "siem",
    __name__,
    url_prefix="/siem",
)

from app.siem import routes  # noqa: E402,F401

