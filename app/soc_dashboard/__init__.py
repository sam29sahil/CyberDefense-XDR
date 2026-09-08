"""
CyberDefense XDR
SOC Dashboard Blueprint
"""

from flask import Blueprint

soc_dashboard = Blueprint(
    "soc_dashboard",
    __name__,
    url_prefix="/soc-dashboard",
    template_folder="../templates",
    static_folder="../static",
)

from app.soc_dashboard import routes  # noqa: E402, F401

