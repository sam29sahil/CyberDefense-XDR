"""
CyberDefense XDR
Notifications Blueprint Routes & APIs
Provides Web page views, RESTful management endpoints, read tracking,
inbox dismissals, live count metrics, and user preference configuration.
"""

from flask import (
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
    abort,
)
from flask_login import login_required, current_user

from app.notifications import notifications
from app.user_management.decorators import permission_required
from app.notifications.services import (
    get_user_notifications,
    get_notification_by_id,
    mark_as_read,
    mark_all_as_read,
    dismiss_notification,
    get_unread_count,
    get_notification_statistics,
    get_user_preferences,
    update_user_preferences,
)


# ==============================================================================
# HTML Page Views
# ==============================================================================


@notifications.route("/", methods=["GET"])
@login_required
@permission_required("notifications.view")
def index():
    """Renders the main Notification Center inbox interface."""
    stats = get_notification_statistics(current_user.id)
    return render_template(
        "notifications/notifications.html",
        stats=stats,
        title="Notification Center",
        page="notifications",
        active="notifications",
    )


@notifications.route("/details/<notification_id>", methods=["GET"])
@login_required
@permission_required("notifications.view")
def detail_view(notification_id):
    """Renders single notification inspector and marks it as read."""
    is_admin = current_user.has_permission("*")
    notif = get_notification_by_id(
        notification_id=notification_id,
        user_id=current_user.id,
        is_admin=is_admin,
    )
    if not notif:
        flash("Notification not found or access denied.", "warning")
        return redirect(url_for("notifications.index"))

    # Auto mark as read on view
    if not notif.is_read:
        mark_as_read(notification_id, user_id=current_user.id, is_admin=is_admin)

    return render_template(
        "notifications/notification_details.html",
        notification=notif,
        title=f"Notification - {notif.notification_id}",
        page="notifications",
        active="notifications",
    )


# ==============================================================================
# RESTful Query & Metric APIs
# ==============================================================================


@notifications.route("/api", methods=["GET"])
@login_required
@permission_required("notifications.view")
def api_list_notifications():
    """Returns paginated, filtered notifications for the current authenticated user."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    category = request.args.get("category", None)
    severity = request.args.get("severity", None)
    is_read_raw = request.args.get("is_read", None)
    search = request.args.get("search", None)

    is_read = None
    if is_read_raw is not None:
        if str(is_read_raw).lower() in ("true", "1", "yes"):
            is_read = True
        elif str(is_read_raw).lower() in ("false", "0", "no"):
            is_read = False

    items, total, pages = get_user_notifications(
        user_id=current_user.id,
        category=category,
        severity=severity,
        is_read=is_read,
        is_dismissed=False,
        search=search,
        page=page,
        per_page=per_page,
    )

    unread_count = get_unread_count(current_user.id)

    return jsonify({
        "success": True,
        "notifications": [item.to_dict() for item in items],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
        "unread_count": unread_count,
    })


@notifications.route("/api/<notification_id>", methods=["GET"])
@login_required
@permission_required("notifications.view")
def api_get_notification(notification_id):
    """Retrieves a single notification by notification_id (with IDOR protection)."""
    is_admin = current_user.has_permission("*")
    notif = get_notification_by_id(
        notification_id=notification_id,
        user_id=current_user.id,
        is_admin=is_admin,
    )
    if not notif:
        return jsonify({"success": False, "error": "Notification not found or access denied."}), 404

    return jsonify({
        "success": True,
        "notification": notif.to_dict(),
    })


@notifications.route("/api/unread", methods=["GET"])
@login_required
@permission_required("notifications.view")
def api_unread_notifications():
    """Returns top unread notifications for quick navbar preview."""
    limit = request.args.get("limit", 5, type=int)
    items, total, _ = get_user_notifications(
        user_id=current_user.id,
        is_read=False,
        is_dismissed=False,
        per_page=limit,
    )
    return jsonify({
        "success": True,
        "unread": [item.to_dict() for item in items],
        "count": total,
    })


@notifications.route("/api/count", methods=["GET"])
@login_required
@permission_required("notifications.view")
def api_unread_count():
    """Returns total unread notification count for global navbar badge indicator."""
    count = get_unread_count(current_user.id)
    return jsonify({
        "success": True,
        "unread_count": count,
    })


@notifications.route("/api/stats", methods=["GET"])
@login_required
@permission_required("notifications.view")
def api_notification_stats():
    """Returns summary statistics for the current user's notifications."""
    stats = get_notification_statistics(current_user.id)
    return jsonify({
        "success": True,
        "stats": stats,
    })


# ==============================================================================
# RESTful Action APIs (Read / Dismiss / Preferences)
# ==============================================================================


@notifications.route("/api/<notification_id>/read", methods=["POST"])
@login_required
@permission_required("notifications.modify")
def api_mark_read(notification_id):
    """Marks a single notification as read."""
    is_admin = current_user.has_permission("*")
    success = mark_as_read(
        notification_id=notification_id,
        user_id=current_user.id,
        is_admin=is_admin,
    )
    if not success:
        return jsonify({"success": False, "error": "Notification not found or access denied."}), 404

    unread_count = get_unread_count(current_user.id)
    return jsonify({
        "success": True,
        "message": "Notification marked as read.",
        "unread_count": unread_count,
    })


@notifications.route("/api/read-all", methods=["POST"])
@login_required
@permission_required("notifications.modify")
def api_mark_all_read():
    """Marks all unread notifications as read for current user."""
    marked = mark_all_as_read(current_user.id)
    return jsonify({
        "success": True,
        "message": f"Marked {marked} notifications as read.",
        "marked_count": marked,
        "unread_count": 0,
    })


@notifications.route("/api/<notification_id>/dismiss", methods=["POST"])
@login_required
@permission_required("notifications.modify")
def api_dismiss(notification_id):
    """Soft-dismisses a notification for current user."""
    is_admin = current_user.has_permission("*")
    success = dismiss_notification(
        notification_id=notification_id,
        user_id=current_user.id,
        is_admin=is_admin,
    )
    if not success:
        return jsonify({"success": False, "error": "Notification not found or access denied."}), 404

    unread_count = get_unread_count(current_user.id)
    return jsonify({
        "success": True,
        "message": "Notification dismissed.",
        "unread_count": unread_count,
    })


@notifications.route("/api/preferences", methods=["GET"])
@login_required
@permission_required("notifications.view")
def api_get_preferences():
    """Fetches user notification channel and threshold preferences."""
    prefs = get_user_preferences(current_user.id)
    return jsonify({
        "success": True,
        "preferences": prefs,
    })


@notifications.route("/api/preferences", methods=["POST", "PATCH"])
@login_required
@permission_required("notifications.modify")
def api_update_preferences():
    """Updates user notification channel and threshold preferences."""
    data = request.get_json(silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"success": False, "error": "No preference data provided."}), 400

    updated = update_user_preferences(
        user_id=current_user.id,
        data=data,
        actor_username=current_user.username,
    )
    return jsonify({
        "success": True,
        "message": "Notification preferences updated successfully.",
        "preferences": updated,
    })

