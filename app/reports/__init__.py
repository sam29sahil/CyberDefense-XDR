from flask import Blueprint

reports = Blueprint("reports", __name__, url_prefix="/reports")

from app.reports import routes  # noqa: F401, E402
