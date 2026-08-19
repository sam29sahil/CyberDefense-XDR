"""
CyberDefense XDR
Detection Engine Blueprint
"""

from flask import Blueprint


detection = Blueprint(
    "detection",
    __name__,
    url_prefix="/detection",
)


from app.detection import routes  # noqa: E402,F401