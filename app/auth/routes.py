"""
CyberDefense XDR
Authentication Routes
"""

from flask import (
    render_template,
    redirect,
    url_for,
    request,
    jsonify,
)

from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user,
)

from app.auth import auth

from app.auth.services import (
    get_user_by_email,
    create_user,
    authenticate_user,
)


@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":

        if current_user.is_authenticated:
            return redirect(url_for("main.home"))

        return render_template("auth/login.html")

    data = request.get_json(silent=True) or {}

    email = str(
        data.get("email", "")
    ).strip().lower()

    password = data.get("password", "")

    remember = bool(
        data.get("remember", False)
    )

    if not email or not password:

        return jsonify({
            "success": False,
            "message": "Email and password are required.",
        }), 400

    user = authenticate_user(
        email,
        password,
    )

    if user is None:

        return jsonify({
            "success": False,
            "message": "Invalid email or password.",
        }), 401

    login_user(
        user,
        remember=remember,
    )

    return jsonify({
        "success": True,
        "message": "Login successful.",
        "redirect": url_for("main.home"),
    }), 200


@auth.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":

        if current_user.is_authenticated:
            return redirect(url_for("main.home"))

        return render_template("auth/register.html")

    data = request.get_json(silent=True) or {}

    first_name = str(
        data.get("first_name", "")
    ).strip()

    last_name = str(
        data.get("last_name", "")
    ).strip()

    email = str(
        data.get("email", "")
    ).strip().lower()

    company = str(
        data.get("company", "")
    ).strip()

    password = data.get("password", "")

    terms = data.get("terms", False)

    if not first_name:
        return jsonify({
            "success": False,
            "message": "First name is required.",
        }), 400

    if not last_name:
        return jsonify({
            "success": False,
            "message": "Last name is required.",
        }), 400

    if not email:
        return jsonify({
            "success": False,
            "message": "Work email is required.",
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "message": "Password is required.",
        }), 400

    if not terms:
        return jsonify({
            "success": False,
            "message": "You must accept the Terms of Service and Security Policy.",
        }), 400

    if len(password) < 12:
        return jsonify({
            "success": False,
            "message": "Password must contain at least 12 characters.",
        }), 400

    if get_user_by_email(email):

        return jsonify({
            "success": False,
            "message": "An account with this email already exists.",
        }), 409

    create_user(
        first_name=first_name,
        last_name=last_name,
        email=email,
        company=company,
        password=password,
    )

    return jsonify({
        "success": True,
        "message": "Your account has been created successfully.",
        "redirect": url_for("auth.login"),
    }), 201


@auth.route("/logout", methods=["GET", "POST"])
@login_required
def logout():

    logout_user()

    return jsonify({
        "success": True,
        "message": "Logged out successfully.",
        "redirect": url_for("auth.login"),
    })