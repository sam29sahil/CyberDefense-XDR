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
from app.dashboard import dashboard

from app.utils.logger import configure_logger


def create_app():
    """
    Create and configure the Flask application.
    """

    app = Flask(__name__)

    # Configuration
    app.config.from_object(Config)

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Logging
    configure_logger()

    # Import models so SQLAlchemy registers them
    from app.users.models import User  # noqa: F401

    # Register blueprints
    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(dashboard)

    return app