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
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY must be set")

    DEBUG = os.getenv("DEBUG", "False").lower() == "true"


    # ======================================================
    # Database
    # ======================================================
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    if not SQLALCHEMY_DATABASE_URI:
        raise RuntimeError("DATABASE_URL must be set")

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
    # Network IDS Log Rotation & Retention
    # ======================================================
    IDS_LOG_ROTATION_SIZE_MB = int(os.getenv("IDS_LOG_ROTATION_SIZE_MB", "100"))
    IDS_LOG_RETENTION_FILES = int(os.getenv("IDS_LOG_RETENTION_FILES", "7"))
    IDS_LOG_ROTATION_INTERVAL_SECONDS = int(os.getenv("IDS_LOG_ROTATION_INTERVAL_SECONDS", "60"))

    # ======================================================
    # Central AI Assistant Configuration
    # ======================================================
    AI_PROVIDER = os.getenv("AI_PROVIDER", "mock")
    AI_API_KEY = os.getenv("AI_API_KEY", "")
    AI_API_BASE = os.getenv("AI_API_BASE", "https://generativelanguage.googleapis.com/v1beta/openai/")
    AI_MODEL = os.getenv("AI_MODEL", "gemini-2.5-flash")
    AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "30"))
    AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "1200"))

    # ======================================================
    # Application
    # ======================================================
    APP_NAME = "CyberDefense XDR"

    VERSION = "0.1.0"