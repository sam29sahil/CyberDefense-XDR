"""
CyberDefense XDR
Analytics Module
"""

from flask import Blueprint

analytics = Blueprint(
    "analytics",
    __name__,
    url_prefix="/analytics",
    template_folder="../templates",
)

from app.analytics import routes  # noqa: E402, F401
