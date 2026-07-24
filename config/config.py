import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Base application configuration."""

    # -------------------------
    # Flask Configuration
    # -------------------------
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key")

    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    # -------------------------
    # Database Configuration
    # -------------------------
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "cyberdefense_xdr")

    SQLALCHEMY_DATABASE_URI = (
        f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # -------------------------
    # Security
    # -------------------------
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True

    # Enable this when using HTTPS in production
    SESSION_COOKIE_SECURE = False

    # -------------------------
    # Logging
    # -------------------------
    LOG_LEVEL = "INFO"

    # -------------------------
    # Uploads
    # -------------------------
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # -------------------------
    # Application Info
    # -------------------------
    APP_NAME = "CyberDefense XDR"
    VERSION = "2.0.0-dev"
