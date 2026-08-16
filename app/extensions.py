"""
Application Extensions
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

db = SQLAlchemy()

migrate = Migrate()

login_manager = LoginManager()

login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    """
    Load a user from the database using the session user ID.
    """

    from app.users.models import User

    return db.session.get(User, int(user_id))
