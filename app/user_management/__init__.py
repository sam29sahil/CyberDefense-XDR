"""
CyberDefense XDR
User Management & Role-Based Access Control (RBAC) Blueprint
"""

from flask import Blueprint

user_management = Blueprint(
    "user_management",
    __name__,
    url_prefix="/user-management",
    template_folder="../templates",
)

from app.user_management import routes  # noqa: F401, E402

