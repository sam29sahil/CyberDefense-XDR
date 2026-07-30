"""
CyberDefense XDR
Application Factory
"""

from flask import Flask

from config.config import Config

from app.extensions import db, migrate
from app.routes import main

from app.utils.logger import configure_logger


def create_app():
    """
    Create and configure the Flask application.
    """

    app = Flask(__name__)

    # Load configuration
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Configure logging
    configure_logger()

    # Register blueprints
    app.register_blueprint(main)

    return app