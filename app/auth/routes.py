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
    current_app,
)

from flask_login import (
    login_user,
    logout_user,
    login_required,
)

from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired,
)

from app.extensions import db

from app.auth import auth

from app.auth.services import (
    get_user_by_email,
    create_user,
    authenticate_user,
)


# ============================================================
# LOGIN
# ============================================================

@auth.route("/login", methods=["GET", "POST"])
def login():

    # GET → show login page
    if request.method == "GET":
        return render_template("auth/login.html")

    # POST → process login
    data = request.get_json(silent=True) or {}

    email = str(
        data.get("email", "")
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    remember = bool(
        data.get("remember", False)
    )

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password are required."
        }), 400

    user = authenticate_user(
        email=email,
        password=password
    )

    if user is None:
        return jsonify({
            "success": False,
            "message": "Invalid email or password."
        }), 401

    login_user(
        user,
        remember=remember
    )

    return jsonify({
        "success": True,
        "message": "Login successful.",
        "redirect": url_for("dashboard.index")
    }), 200


# ============================================================
# REGISTER
# ============================================================

@auth.route("/register", methods=["GET", "POST"])
def register():

    # GET → show registration page
    if request.method == "GET":
        return render_template("auth/register.html")

    # POST → create account
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

    password = data.get(
        "password",
        ""
    )

    terms = bool(
        data.get("terms", False)
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not first_name:
        return jsonify({
            "success": False,
            "message": "First name is required."
        }), 400

    if not last_name:
        return jsonify({
            "success": False,
            "message": "Last name is required."
        }), 400

    if not email:
        return jsonify({
            "success": False,
            "message": "Work email is required."
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "message": "Password is required."
        }), 400

    if len(password) < 12:
        return jsonify({
            "success": False,
            "message": "Password must contain at least 12 characters."
        }), 400

    if not terms:
        return jsonify({
            "success": False,
            "message": (
                "You must accept the Terms of Service "
                "and Security Policy."
            )
        }), 400

    # --------------------------------------------------------
    # Existing account
    # --------------------------------------------------------

    if get_user_by_email(email):
        return jsonify({
            "success": False,
            "message": "An account with this email already exists."
        }), 409

    # --------------------------------------------------------
    # Create account
    # --------------------------------------------------------

    create_user(
        first_name=first_name,
        last_name=last_name,
        email=email,
        company=company,
        password=password
    )

    # Registration → login page
    return jsonify({
        "success": True,
        "message": "Account created successfully. Please sign in.",
        "redirect": url_for("auth.login")
    }), 201


# ============================================================
# PASSWORD RESET TOKEN
# ============================================================

def generate_reset_token(email):

    serializer = URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )

    return serializer.dumps(
        email,
        salt="password-reset"
    )


def verify_reset_token(
    token,
    max_age=3600
):

    serializer = URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"]
    )

    try:

        return serializer.loads(
            token,
            salt="password-reset",
            max_age=max_age
        )

    except (
        BadSignature,
        SignatureExpired
    ):

        return None


# ============================================================
# FORGOT PASSWORD
# ============================================================

@auth.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():

    # GET → show forgot password page
    if request.method == "GET":
        return render_template(
            "auth/forgot-password.html"
        )

    # POST → generate reset token
    data = request.get_json(
        silent=True
    )

    if data is not None:

        email = str(
            data.get("email", "")
        ).strip().lower()

    else:

        email = str(
            request.form.get("email", "")
        ).strip().lower()

    if not email:

        return jsonify({
            "success": False,
            "message": "Email address is required."
        }), 400

    user = get_user_by_email(email)

    if user is None:

        return jsonify({
            "success": False,
            "message": "No account was found with that email address."
        }), 404

    token = generate_reset_token(email)

    reset_url = url_for(
        "auth.reset_password",
        token=token,
        _external=True
    )

    return jsonify({
        "success": True,
        "message": "Password reset link generated.",
        "reset_url": reset_url
    }), 200


# ============================================================
# RESET PASSWORD
# ============================================================

@auth.route(
    "/reset-password/<token>",
    methods=["GET", "POST"]
)
def reset_password(token):

    email = verify_reset_token(token)

    # Invalid/expired token
    if email is None:

        return render_template(
            "auth/reset-password.html",
            valid=False,
            message=(
                "This password reset link "
                "is invalid or has expired."
            )
        )

    # GET → show reset form
    if request.method == "GET":

        return render_template(
            "auth/reset-password.html",
            valid=True,
            token=token
        )

    # POST → update password
    data = request.get_json(
        silent=True
    )

    if data is not None:

        password = data.get(
            "password",
            ""
        )

        confirm_password = data.get(
            "confirm_password",
            ""
        )

    else:

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

    if not password:

        return jsonify({
            "success": False,
            "message": "Password is required."
        }), 400

    if len(password) < 12:

        return jsonify({
            "success": False,
            "message": (
                "Password must contain at least 12 characters."
            )
        }), 400

    if password != confirm_password:

        return jsonify({
            "success": False,
            "message": "Passwords do not match."
        }), 400

    user = get_user_by_email(email)

    if user is None:

        return jsonify({
            "success": False,
            "message": "User account no longer exists."
        }), 404

    user.set_password(password)

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Password has been reset successfully.",
        "redirect": url_for("auth.login")
    }), 200


# ============================================================
# LOGOUT
# ============================================================

@auth.route(
    "/logout",
    methods=["GET", "POST"]
)
@login_required
def logout():

    logout_user()

    return redirect(
        url_for("auth.login")
    )