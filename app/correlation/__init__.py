"""
CyberDefense XDR
Correlation Engine Blueprint
"""

from flask import Blueprint

correlation = Blueprint(
    "correlation",
    __name__,
    url_prefix="/correlation",
    template_folder="../templates",
)

from app.correlation import routes  # noqa: F401, E402

