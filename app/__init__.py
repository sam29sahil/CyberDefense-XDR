from flask import Flask

from config.config import Config

from app.extensions import (
    db,
    migrate,
    login_manager,
)

from app.routes import main


def create_app():

    app = Flask(__name__)

    app.config.from_object(Config)

    db.init_app(app)

    migrate.init_app(app, db)

    login_manager.init_app(app)

    app.register_blueprint(main)

    return app
