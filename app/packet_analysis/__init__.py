"""
CyberDefense XDR
Packet Analysis Module
Provides TShark-based inspection, protocol hierarchy, conversations, and packet dissection.
"""

from flask import Blueprint

packet_analysis = Blueprint(
    "packet_analysis",
    __name__,
    url_prefix="/packet-analysis",
    template_folder="../templates",
    static_folder="../static",
)

from app.packet_analysis import routes  # noqa: F401
