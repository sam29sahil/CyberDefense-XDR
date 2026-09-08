"""
CyberDefense XDR
Network IDS Module Blueprint Definition
"""

from flask import Blueprint

ids = Blueprint("ids", __name__, url_prefix="/network-ids")

from app.ids import routes  # noqa: E402, F401

