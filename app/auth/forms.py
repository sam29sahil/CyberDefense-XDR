"""
CyberDefense XDR
Authentication Forms
"""

from flask_wtf import FlaskForm

from wtforms import (
    StringField,
    PasswordField,
    BooleanField,
    SubmitField,
)

from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
)


class LoginForm(FlaskForm):

    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=80),
        ],
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
        ],
    )

    remember = BooleanField("Remember me")

    submit = SubmitField("Login")


class RegisterForm(FlaskForm):

    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=80),
        ],
    )

    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Email(),
            Length(max=255),
        ],
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8),
        ],
    )

    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo(
                "password",
                message="Passwords must match.",
            ),
        ],
    )

    submit = SubmitField("Register")
