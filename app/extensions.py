"""
Application Extensions
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# Database
db = SQLAlchemy()

# Database Migration
migrate = Migrate()

# Login Manager
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    """
    Temporary user loader.
    Authentication will be implemented later.
    """
    return None