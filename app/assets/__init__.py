"""
CyberDefense XDR
Asset Management Blueprint Definition
"""

from flask import Blueprint

assets = Blueprint(
    "assets",
    __name__,
    url_prefix="/assets",
    template_folder="../templates",
    static_folder="../static",
)

from app.assets import routes  # noqa: E402, F401

