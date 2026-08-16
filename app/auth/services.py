"""
CyberDefense XDR
Authentication Services
"""

from app.extensions import db
from app.users.models import User


def get_user_by_username(username):
    return User.query.filter_by(username=username).first()


def get_user_by_email(email):
    return User.query.filter_by(email=email.strip().lower()).first()


def create_user(
    first_name,
    last_name,
    email,
    company,
    password,
    role="analyst",
):
    email = email.strip().lower()

    # Generate an internal username from email.
    base_username = email.split("@")[0]

    username = base_username
    counter = 1

    while get_user_by_username(username):

        username = f"{base_username}{counter}"
        counter += 1

    user = User(
        username=username,
        email=email,
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        company=company.strip() if company else None,
        role=role,
    )

    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return user


def authenticate_user(email, password):

    user = get_user_by_email(email)

    if user is None:
        return None

    if not user.is_active:
        return None

    if not user.check_password(password):
        return None

    return user
