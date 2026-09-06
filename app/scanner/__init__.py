"""
CyberDefense XDR
Vulnerability Scanner & Scan History Blueprint
"""

from flask import Blueprint

scanner = Blueprint(
    "scanner",
    __name__,
    url_prefix="/scanner",
)

from app.scanner import routes  # noqa: E402,F401

