"""
CyberDefense XDR
AI Security Assistant Blueprint
"""

from flask import Blueprint

ai_assistant = Blueprint(
    "ai_assistant",
    __name__,
    url_prefix="/ai-assistant",
    template_folder="../templates",
)

from app.ai_assistant import routes  # noqa: F401, E402

