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
    # Uploads
    # ======================================================
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # ======================================================
    # Application
    # ======================================================
    APP_NAME = "CyberDefense XDR"

    VERSION = "0.1.0"