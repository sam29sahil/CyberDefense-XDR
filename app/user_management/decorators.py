"""
CyberDefense XDR
Authorization Decorators for Role-Based Access Control (RBAC)
Provides reusable, non-intrusive view and API route protection.
"""

from functools import wraps
from flask import request, jsonify, abort, redirect, url_for, flash
from flask_login import current_user


def permission_required(permission: str):
    """
    Enforces that the current authenticated user has the specified permission.
    Returns JSON 403 for API requests or aborts 403 for browser views.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
                    return jsonify({
                        "success": False,
                        "error": "Unauthorized",
                        "message": "Authentication is required to access this resource."
                    }), 401
                return redirect(url_for("auth.login"))

            # Check account active / locked state
            if getattr(current_user, "is_locked", False):
                if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
                    return jsonify({
                        "success": False,
                        "error": "Account Locked",
                        "message": "Your account is temporarily locked. Contact an administrator."
                    }), 423
                abort(403)

            # Check permission
            has_perm = False
            if hasattr(current_user, "has_permission"):
                has_perm = current_user.has_permission(permission)
            else:
                # Fallback role check
                role = str(getattr(current_user, "role", "")).lower()
                has_perm = (role in ("admin", "administrator"))

            if not has_perm:
                try:
                    from app.audit_logs.services import record_audit_event
                    u_name = getattr(current_user, "username", "Unknown")
                    u_id = getattr(current_user, "id", None)
                    record_audit_event(
                        action="AUTHORIZATION_DENIED",
                        category="Authorization",
                        message=f"Access denied: User '{u_name}' missing permission '{permission}' for {request.path}",
                        actor=u_name,
                        actor_id=u_id,
                        result="DENIED",
                        severity="medium",
                        details={"permission": permission, "path": request.path, "method": request.method},
                        sync_to_siem=False,
                    )
                except Exception:
                    pass

                if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
                    return jsonify({
                        "success": False,
                        "error": "Forbidden",
                        "message": f"Access denied: You do not possess the required permission ({permission})."
                    }), 403
                abort(403)

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def role_required(*allowed_roles: str):
    """
    Enforces that the current authenticated user belongs to at least one of the specified roles.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
                    return jsonify({
                        "success": False,
                        "error": "Unauthorized",
                        "message": "Authentication is required to access this resource."
                    }), 401
                return redirect(url_for("auth.login"))

            has_matched_role = False
            if hasattr(current_user, "has_role"):
                has_matched_role = current_user.has_role(*allowed_roles)
            else:
                user_role = str(getattr(current_user, "role", "")).upper()
                has_matched_role = any(user_role == r.upper() for r in allowed_roles)

            if not has_matched_role:
                try:
                    from app.audit_logs.services import record_audit_event
                    u_name = getattr(current_user, "username", "Unknown")
                    u_id = getattr(current_user, "id", None)
                    record_audit_event(
                        action="AUTHORIZATION_DENIED",
                        category="Authorization",
                        message=f"Access denied: User '{u_name}' missing role in {list(allowed_roles)} for {request.path}",
                        actor=u_name,
                        actor_id=u_id,
                        result="DENIED",
                        severity="medium",
                        details={"required_roles": list(allowed_roles), "path": request.path, "method": request.method},
                        sync_to_siem=False,
                    )
                except Exception:
                    pass

                if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
                    return jsonify({
                        "success": False,
                        "error": "Forbidden",
                        "message": f"Access denied: Role in {list(allowed_roles)} required."
                    }), 403
                abort(403)

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(fn):
    """Convenience decorator requiring the ADMIN role."""
    return role_required("ADMIN")(fn)
