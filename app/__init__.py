"""
CyberDefense XDR
Application Factory
"""

from flask import Flask

from config.config import Config

from app.extensions import (
    db,
    migrate,
    login_manager,
)

from app.routes import main
from app.auth import auth
import app.auth.routes
from app.dashboard import dashboard
from app.settings import settings
from app.detection import detection

from app.utils.logger import configure_logger


def create_app():
    """
    Create and configure the Flask application.
    """

    app = Flask(__name__)

    # ==========================================================
    # Configuration
    # ==========================================================

    app.config.from_object(Config)

    # ==========================================================
    # Extensions
    # ==========================================================

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # ==========================================================
    # Logging
    # ==========================================================

    configure_logger()

    # ==========================================================
    # Import models so SQLAlchemy registers them
    # ==========================================================

    from app.users.models import User  # noqa: F401

    from app.settings.models import (
        SecuritySettings,
        NotificationSettings,
        APIKey,
        Integration,
        GeneralSettings,
    )  # noqa: F401
     
    from app.detection.models import (
        DetectionRule,
        DetectionEvent,
    )  # noqa: F401
    # ==========================================================
    # Register Blueprints
    # ==========================================================

    app.register_blueprint(main)

    app.register_blueprint(auth, url_prefix="/auth")

    app.register_blueprint(dashboard)

    app.register_blueprint(settings)

    app.register_blueprint(detection)

    return app
