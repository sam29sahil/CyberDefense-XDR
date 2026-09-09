"""
CyberDefense XDR
User Management & RBAC Blueprint Routes & APIs
Provides Web page views and RESTful APIs for identity administration,
role assignment, access control policy introspection, and audit trails.
"""

from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app.user_management import user_management
from app.user_management.permissions import (
    ALL_PERMISSIONS,
    ROLE_PERMISSIONS,
    ROLE_METADATA,
    normalize_role,
    get_permissions_for_role,
)
from app.user_management.decorators import permission_required, role_required, admin_required
from app.user_management.services import (
    list_users,
    get_user_by_id,
    create_managed_user,
    update_managed_user,
    delete_managed_user,
    get_role_summary,
    count_active_admins,
)
from app.users.models import User


# ==============================================================================
# HTML Page Views
# ==============================================================================

@user_management.route("/", methods=["GET"])
@user_management.route("/users", methods=["GET"])
@login_required
@permission_required("users.view")
def users_view():
    """Renders the primary User Management inventory and administration interface."""
    roles = get_role_summary()
    return render_template(
        "user_management/users.html",
        roles=roles,
        all_permissions=ALL_PERMISSIONS,
    )


@user_management.route("/users/<int:user_id>", methods=["GET"])
@login_required
@permission_required("users.view")
def user_detail_view(user_id):
    """Renders the detailed user profile, permissions inspection, and activity view."""
    user_data = get_user_by_id(user_id, include_permissions=True)
    if not user_data:
        flash("User not found.", "warning")
        return redirect(url_for("user_management.users_view"))

    roles = get_role_summary()
    return render_template(
        "user_management/user_details.html",
        user=user_data,
        roles=roles,
        all_permissions=ALL_PERMISSIONS,
    )


@user_management.route("/roles", methods=["GET"])
@login_required
@permission_required("users.view")
def roles_view():
    """Renders the RBAC roles and permissions matrix view."""
    roles = get_role_summary()
    return render_template(
        "user_management/roles.html",
        roles=roles,
        all_permissions=ALL_PERMISSIONS,
    )


# ==============================================================================
# REST APIs
# ==============================================================================

@user_management.route("/api/users", methods=["GET"])
@login_required
@permission_required("users.view")
def api_users():
    """Returns paginated user accounts with role and status filters."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    search_query = request.args.get("search", type=str)
    role_filter = request.args.get("role", type=str)
    status_filter = request.args.get("status", type=str)

    result = list_users(
        page=page,
        per_page=per_page,
        search_query=search_query,
        role_filter=role_filter,
        status_filter=status_filter,
    )

    # Compute high-level system summary counts
    all_users = User.query.all()
    stats = {
        "total": len(all_users),
        "active": sum(1 for u in all_users if u.status == "active"),
        "disabled": sum(1 for u in all_users if u.status == "disabled"),
        "locked": sum(1 for u in all_users if u.is_locked),
        "admins": sum(1 for u in all_users if u.get_canonical_role() == "ADMIN"),
        "analysts": sum(1 for u in all_users if "ANALYST" in u.get_canonical_role()),
        "viewers": sum(1 for u in all_users if u.get_canonical_role() == "VIEWER"),
    }

    return jsonify({
        "success": True,
        "users": result["users"],
        "total": result["total"],
        "page": result["page"],
        "per_page": result["per_page"],
        "pages": result["pages"],
        "stats": stats,
    })


@user_management.route("/api/users/<int:user_id>", methods=["GET"])
@login_required
@permission_required("users.view")
def api_user_detail(user_id):
    """Retrieves full profile, permissions, and security metrics for a single user."""
    user_data = get_user_by_id(user_id, include_permissions=True)
    if not user_data:
        return jsonify({"success": False, "error": f"User ID {user_id} not found."}), 404

    return jsonify({
        "success": True,
        "user": user_data,
    })


@user_management.route("/api/users", methods=["POST"])
@login_required
@permission_required("users.create")
def api_create_user():
    """Provisions a new user account with assigned role, credentials, and profile."""
    data = request.get_json(silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"success": False, "error": "No JSON or form data received."}), 400

    try:
        new_user = create_managed_user(data, creator_user=current_user)
        return jsonify({
            "success": True,
            "message": f"User '{new_user.username}' created successfully.",
            "user": new_user.to_dict(include_permissions=True),
        }), 201
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal server error: {e}"}), 500


@user_management.route("/api/users/<int:user_id>", methods=["PATCH", "PUT"])
@login_required
@permission_required("users.modify")
def api_update_user(user_id):
    """Modifies user profile details, updates role/status, or resets credentials."""
    data = request.get_json(silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"success": False, "error": "No JSON or form data received."}), 400

    try:
        updated_user = update_managed_user(user_id, data, current_user=current_user)
        return jsonify({
            "success": True,
            "message": f"User '{updated_user.username}' updated successfully.",
            "user": updated_user.to_dict(include_permissions=True),
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal server error: {e}"}), 500


@user_management.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
@permission_required("users.delete")
def api_delete_user(user_id):
    """
    Safely deletes or deactivates a user.
    Enforces last-admin safety, self-protection, and referential integrity.
    """
    try:
        res = delete_managed_user(user_id, current_user=current_user)
        return jsonify(res)
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal server error: {e}"}), 500


@user_management.route("/api/roles", methods=["GET"])
@login_required
@permission_required("users.view")
def api_roles():
    """Returns canonical roles, permission counts, and descriptions."""
    roles = get_role_summary()
    return jsonify({
        "success": True,
        "roles": roles,
        "all_permissions": ALL_PERMISSIONS,
    })


@user_management.route("/api/permissions", methods=["GET"])
@login_required
@permission_required("users.view")
def api_permissions():
    """Returns all available system permissions categorized by module."""
    categorized = {}
    for perm_key, perm_desc in ALL_PERMISSIONS.items():
        module = perm_key.split(".")[0]
        if module not in categorized:
            categorized[module] = []
        categorized[module].append({
            "permission": perm_key,
            "description": perm_desc,
        })

    return jsonify({
        "success": True,
        "permissions": ALL_PERMISSIONS,
        "categorized": categorized,
    })

