"""
CyberDefense XDR
Configuration File
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration."""

    # ======================================================
    # Flask
    # ======================================================
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "change-this-secret-key"
    )

    DEBUG = os.getenv(
        "DEBUG",
        "True"
    ).lower() == "true"

    # ======================================================
    # Database
    # ======================================================
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/cyberdefense_xdr"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ======================================================
    # Security & Session Hardening
    # ======================================================
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = os.getenv("REMEMBER_COOKIE_SECURE", "False").lower() == "true"

    WTF_CSRF_ENABLED = True
    WTF_CSRF_CHECK_DEFAULT = False
    WTF_CSRF_TIME_LIMIT = 3600

    from datetime import timedelta
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # ======================================================
    # Uploads
    # ======================================================
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # ======================================================
    # Application
    # ======================================================
    APP_NAME = "CyberDefense XDR"

    VERSION = "0.1.0"