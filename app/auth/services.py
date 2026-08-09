"""
CyberDefense XDR
Authentication Services
"""

from app.extensions import db
from app.users.models import User


def get_user_by_username(username):
    """Find a user by username."""
    return User.query.filter_by(
        username=username
    ).first()


def get_user_by_email(email):
    """Find a user by email."""
    return User.query.filter_by(
        email=email
    ).first()


def create_user(username, email, password, role="analyst"):
    """Create and persist a new user."""

    user = User(
        username=username.strip(),
        email=email.strip().lower(),
        role=role,
    )

    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return user


def authenticate_user(username, password):
    """Authenticate a user using username and password."""

    user = get_user_by_username(
        username.strip()
    )

    if user is None:
        return None

    if not user.is_active:
        return None

    if not user.check_password(password):
        return None

    return user