"""
CyberDefense XDR
Authentication Routes
"""

from flask import (
    render_template,
    redirect,
    url_for,
    flash,
)

from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user,
)

from app.auth import auth

from app.auth.forms import (
    LoginForm,
    RegisterForm,
)

from app.auth.services import (
    get_user_by_username,
    get_user_by_email,
    create_user,
    authenticate_user,
)


@auth.route("/login", methods=["GET", "POST"])
def login():
    """User login."""

    if current_user.is_authenticated:
        return redirect(
            url_for("main.home")
        )

    form = LoginForm()

    if form.validate_on_submit():

        user = authenticate_user(
            form.username.data,
            form.password.data,
        )

        if user is None:
            flash(
                "Invalid username or password.",
                "danger",
            )

            return render_template(
                "auth/login.html",
                form=form,
            )

        login_user(
            user,
            remember=form.remember.data,
        )

        flash(
            "Login successful.",
            "success",
        )

        return redirect(
            url_for("main.home")
        )

    return render_template(
        "auth/login.html",
        form=form,
    )


@auth.route("/register", methods=["GET", "POST"])
def register():
    """User registration."""

    if current_user.is_authenticated:
        return redirect(
            url_for("main.home")
        )

    form = RegisterForm()

    if form.validate_on_submit():

        username = form.username.data.strip()
        email = form.email.data.strip().lower()

        if get_user_by_username(username):
            flash(
                "Username already exists.",
                "danger",
            )

            return render_template(
                "auth/register.html",
                form=form,
            )

        if get_user_by_email(email):
            flash(
                "Email already registered.",
                "danger",
            )

            return render_template(
                "auth/register.html",
                form=form,
            )

        create_user(
            username=username,
            email=email,
            password=form.password.data,
        )

        flash(
            "Registration successful. You can now log in.",
            "success",
        )

        return redirect(
            url_for("auth.login")
        )

    return render_template(
        "auth/register.html",
        form=form,
    )


@auth.route("/logout")
@login_required
def logout():
    """Log out the current user."""

    logout_user()

    flash(
        "You have been logged out.",
        "success",
    )

    return redirect(
        url_for("auth.login")
    )