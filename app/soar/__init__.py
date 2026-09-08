"""
CyberDefense XDR
SOAR & Security Automation Blueprint
"""

from flask import Blueprint

soar = Blueprint(
    "soar",
    __name__,
    url_prefix="/soar",
    template_folder="../templates",
)

from app.soar import routes  # noqa: F401, E402

