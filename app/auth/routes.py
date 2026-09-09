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

import time
from collections import defaultdict
import threading

# Brute-force protection: in-memory failed attempt tracker
_failed_logins = defaultdict(list)
_rate_lock = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes


def is_login_locked(identifier: str) -> bool:
    now = time.time()
    with _rate_lock:
        attempts = _failed_logins[identifier]
        _failed_logins[identifier] = [t for t in attempts if now - t < LOCKOUT_DURATION]
        return len(_failed_logins[identifier]) >= MAX_LOGIN_ATTEMPTS


def record_failed_login(identifier: str):
    now = time.time()
    with _rate_lock:
        _failed_logins[identifier].append(now)


def clear_failed_logins(identifier: str):
    with _rate_lock:
        if identifier in _failed_logins:
            del _failed_logins[identifier]


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

    email = str(data.get("email", "")).strip().lower()

    password = data.get("password", "")

    remember = bool(data.get("remember", False))

    if not email or not password:
        return (
            jsonify({"success": False, "message": "Email and password are required."}),
            400,
        )

    # Brute-force rate limiting check
    ip = request.remote_addr or "127.0.0.1"
    rate_key = f"{ip}:{email}"
    if is_login_locked(rate_key):
        try:
            from app.audit_logs.services import record_audit_event
            record_audit_event(
                action="AUTH_LOCKOUT",
                category="Authentication",
                message=f"Rate limit exceeded: Account/IP temporarily locked ({email})",
                actor=email or "Anonymous",
                result="DENIED",
                severity="high",
                details={"rate_key": rate_key, "email": email},
            )
        except Exception:
            pass

        return (
            jsonify(
                {
                    "success": False,
                    "message": "Too many failed login attempts. Account temporarily locked for 15 minutes.",
                }
            ),
            429,
        )

    user = authenticate_user(email=email, password=password)

    if user is None:
        # Increment failed login count on the database user if account exists
        db_user = get_user_by_email(email)
        if db_user:
            from datetime import datetime, timedelta
            db_user.failed_login_count = (db_user.failed_login_count or 0) + 1
            if db_user.failed_login_count >= 5:
                db_user.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
                db_user.status = "locked"
            db.session.commit()

        record_failed_login(rate_key)

        try:
            from app.audit_logs.services import record_audit_event
            record_audit_event(
                action="LOGIN_FAILED",
                category="Authentication",
                message=f"Failed authentication attempt for email '{email}'",
                actor=email or "Anonymous",
                result="FAILURE",
                severity="medium",
                details={"email": email},
            )
        except Exception:
            pass

        return jsonify({"success": False, "message": "Invalid email or password."}), 401

    if user.is_locked:
        try:
            from app.audit_logs.services import record_audit_event
            record_audit_event(
                action="LOGIN_LOCKED",
                category="Authentication",
                message=f"Authentication blocked: Account '{user.username}' is locked",
                actor=user.username,
                actor_id=user.id,
                result="DENIED",
                severity="medium",
                details={"email": user.email, "user_id": user.id},
            )
        except Exception:
            pass

        return jsonify({
            "success": False,
            "message": "Account is temporarily locked. Please contact an administrator or try again later."
        }), 423

    if user.status in ("disabled", "inactive") or not user.is_active:
        try:
            from app.audit_logs.services import record_audit_event
            record_audit_event(
                action="LOGIN_DEACTIVATED",
                category="Authentication",
                message=f"Authentication blocked: Account '{user.username}' is deactivated or inactive",
                actor=user.username,
                actor_id=user.id,
                result="DENIED",
                severity="medium",
                details={"email": user.email, "user_id": user.id},
            )
        except Exception:
            pass

        return jsonify({
            "success": False,
            "message": "Account has been deactivated. Please contact an administrator."
        }), 403

    from datetime import datetime
    user.last_login = datetime.utcnow()
    user.failed_login_count = 0
    if user.status == "locked":
        user.status = "active"
    db.session.commit()

    clear_failed_logins(rate_key)
    login_user(user, remember=remember)

    try:
        from app.audit_logs.services import record_audit_event
        record_audit_event(
            action="LOGIN_SUCCESS",
            category="Authentication",
            message=f"User '{user.username}' authenticated successfully",
            actor=user.username,
            actor_id=user.id,
            result="SUCCESS",
            severity="info",
            details={"email": user.email, "role": user.role},
        )
    except Exception:
        pass

    return (
        jsonify(
            {
                "success": True,
                "message": "Login successful.",
                "redirect": url_for("dashboard.index"),
            }
        ),
        200,
    )


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

    first_name = str(data.get("first_name", "")).strip()

    last_name = str(data.get("last_name", "")).strip()

    email = str(data.get("email", "")).strip().lower()

    company = str(data.get("company", "")).strip()

    password = data.get("password", "")

    terms = bool(data.get("terms", False))

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not first_name:
        return jsonify({"success": False, "message": "First name is required."}), 400

    if not last_name:
        return jsonify({"success": False, "message": "Last name is required."}), 400

    if not email:
        return jsonify({"success": False, "message": "Work email is required."}), 400

    if not password:
        return jsonify({"success": False, "message": "Password is required."}), 400

    if len(password) < 12:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Password must contain at least 12 characters.",
                }
            ),
            400,
        )

    if not terms:
        return (
            jsonify(
                {
                    "success": False,
                    "message": (
                        "You must accept the Terms of Service " "and Security Policy."
                    ),
                }
            ),
            400,
        )

    # --------------------------------------------------------
    # Existing account
    # --------------------------------------------------------

    if get_user_by_email(email):
        return (
            jsonify(
                {
                    "success": False,
                    "message": "An account with this email already exists.",
                }
            ),
            409,
        )

    # --------------------------------------------------------
    # Create account
    # --------------------------------------------------------

    create_user(
        first_name=first_name,
        last_name=last_name,
        email=email,
        company=company,
        password=password,
    )

    # Registration → login page
    return (
        jsonify(
            {
                "success": True,
                "message": "Account created successfully. Please sign in.",
                "redirect": url_for("auth.login"),
            }
        ),
        201,
    )


# ============================================================
# PASSWORD RESET TOKEN
# ============================================================


def generate_reset_token(email):

    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

    return serializer.dumps(email, salt="password-reset")


def verify_reset_token(token, max_age=3600):

    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

    try:

        return serializer.loads(token, salt="password-reset", max_age=max_age)

    except (BadSignature, SignatureExpired):

        return None


# ============================================================
# FORGOT PASSWORD
# ============================================================


@auth.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    # GET → show forgot password page
    if request.method == "GET":
        return render_template("auth/forgot-password.html")

    # POST → generate reset token
    data = request.get_json(silent=True)

    if data is not None:

        email = str(data.get("email", "")).strip().lower()

    else:

        email = str(request.form.get("email", "")).strip().lower()

    if not email:

        return jsonify({"success": False, "message": "Email address is required."}), 400

    user = get_user_by_email(email)

    # OWASP Defense against User Enumeration: return generic message
    if user is None:
        return (
            jsonify(
                {
                    "success": True,
                    "message": "If an account exists with that email address, password reset instructions have been generated.",
                }
            ),
            200,
        )

    token = generate_reset_token(email)

    reset_url = url_for("auth.reset_password", token=token, _external=True)

    response_payload = {
        "success": True,
        "message": "If an account exists with that email address, password reset instructions have been generated.",
    }
    # Expose reset_url only in DEBUG or TESTING environments
    if current_app.config.get("DEBUG") or current_app.config.get("TESTING"):
        response_payload["reset_url"] = reset_url

    return (
        jsonify(response_payload),
        200,
    )


# ============================================================
# RESET PASSWORD
# ============================================================


@auth.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    email = verify_reset_token(token)

    # Invalid/expired token
    if email is None:

        return render_template(
            "auth/reset-password.html",
            valid=False,
            message=("This password reset link " "is invalid or has expired."),
        )

    # GET → show reset form
    if request.method == "GET":

        return render_template("auth/reset-password.html", valid=True, token=token)

    # POST → update password
    data = request.get_json(silent=True)

    if data is not None:

        password = data.get("password", "")

        confirm_password = data.get("confirm_password", "")

    else:

        password = request.form.get("password", "")

        confirm_password = request.form.get("confirm_password", "")

    if not password:

        return jsonify({"success": False, "message": "Password is required."}), 400

    if len(password) < 12:

        return (
            jsonify(
                {
                    "success": False,
                    "message": ("Password must contain at least 12 characters."),
                }
            ),
            400,
        )

    if password != confirm_password:

        return jsonify({"success": False, "message": "Passwords do not match."}), 400

    user = get_user_by_email(email)

    if user is None:

        return (
            jsonify({"success": False, "message": "User account no longer exists."}),
            404,
        )

    user.set_password(password)

    db.session.commit()

    return (
        jsonify(
            {
                "success": True,
                "message": "Password has been reset successfully.",
                "redirect": url_for("auth.login"),
            }
        ),
        200,
    )


# ============================================================
# LOGOUT
# ============================================================


@auth.route("/logout", methods=["GET", "POST"])
@login_required
def logout():

    actor_name = getattr(current_user, "username", "User")
    actor_id = getattr(current_user, "id", None)
    logout_user()

    try:
        from app.audit_logs.services import record_audit_event
        record_audit_event(
            action="LOGOUT",
            category="Authentication",
            message=f"User '{actor_name}' logged out successfully",
            actor=actor_name,
            actor_id=actor_id,
            result="SUCCESS",
            severity="info",
        )
    except Exception:
        pass

    return redirect(url_for("auth.login"))
