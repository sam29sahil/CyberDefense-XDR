"""
CyberDefense XDR
Notifications Service Layer
Orchestrates notification dispatch, deduplication, recipient resolution, RBAC filtering, and user inbox management.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from flask import current_app
from sqlalchemy import or_

from app.extensions import db
from app.notifications.models import Notification
from app.notifications.providers import InAppProvider, EmailProvider, WebhookProvider
from app.settings.models import NotificationSettings, Integration
from app.users.models import User
from app.user_management.permissions import get_permissions_for_role, normalize_role

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

in_app_provider = InAppProvider()
email_provider = EmailProvider()
webhook_provider = WebhookProvider()


def _is_within_quiet_hours(quiet_from: str, quiet_to: str) -> bool:
    """Checks if current UTC time is inside quiet hours window (HH:MM format)."""
    try:
        now_time = datetime.utcnow().time()
        from_parts = [int(p) for p in quiet_from.split(":")]
        to_parts = [int(p) for p in quiet_to.split(":")]
        from_time = datetime.utcnow().replace(hour=from_parts[0], minute=from_parts[1]).time()
        to_time = datetime.utcnow().replace(hour=to_parts[0], minute=to_parts[1]).time()

        if from_time <= to_time:
            return from_time <= now_time <= to_time
        else:
            # Over midnight window (e.g. 22:00 to 07:00)
            return now_time >= from_time or now_time <= to_time
    except Exception:
        return False


def resolve_recipients(
    recipient_user_id: Optional[int] = None,
    recipient_role: Optional[str] = None,
    recipient_permission: Optional[str] = None,
) -> List[User]:
    """
    Resolves recipient users based on specific user ID, role, or explicit RBAC permission.
    Only active, non-locked accounts are returned.
    """
    if recipient_user_id:
        user = User.query.filter_by(id=recipient_user_id, is_active=True).first()
        return [user] if user else []

    if recipient_permission:
        all_active_users = User.query.filter_by(is_active=True).all()
        matching = []
        for u in all_active_users:
            if u.has_permission(recipient_permission):
                matching.append(u)
        if matching:
            return matching

    if recipient_role:
        target_role = normalize_role(recipient_role)
        all_active_users = User.query.filter_by(is_active=True).all()
        matching = [u for u in all_active_users if u.get_canonical_role() == target_role]
        if matching:
            return matching

    # Default fallback: All active administrators
    all_active_users = User.query.filter_by(is_active=True).all()
    admins = [u for u in all_active_users if u.has_permission("*") or u.get_canonical_role() == "ADMIN"]
    return admins if admins else all_active_users[:1]


def dispatch_notification(
    title: str,
    message: str,
    category: str = "SYSTEM",
    severity: str = "info",
    recipient_user_id: Optional[int] = None,
    recipient_role: Optional[str] = None,
    recipient_permission: Optional[str] = None,
    source: str = "System",
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    action_url: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    channels: Optional[List[str]] = None,
    dedup_window_minutes: int = 5,
) -> List[Dict[str, Any]]:
    """
    Primary platform entrypoint for dispatching notifications.
    Fans out across resolved recipients, enforces recipient quiet hours and severity thresholds,
    guarantees in-app persistence, and safely delivers to external channels.
    """
    recipients = resolve_recipients(
        recipient_user_id=recipient_user_id,
        recipient_role=recipient_role,
        recipient_permission=recipient_permission,
    )

    if not recipients:
        logger.warning(
            f"dispatch_notification: No active recipients found for role={recipient_role}, "
            f"perm={recipient_permission}, user_id={recipient_user_id}"
        )
        return []

    norm_severity = (severity or "info").lower()
    sev_rank = SEVERITY_LEVELS.get(norm_severity, 1)
    notif_data = {
        "title": title,
        "message": message,
        "category": category,
        "severity": norm_severity,
        "source": source,
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "action_url": action_url,
        "metadata": metadata or {},
    }

    dispatched = []

    for user in recipients:
        try:
            settings = NotificationSettings.query.filter_by(user_id=user.id).first()
            user_min_sev = (settings.min_severity if settings else "info").lower()
            user_min_rank = SEVERITY_LEVELS.get(user_min_sev, 1)

            # In-App notification is always recorded
            in_app_ok = in_app_provider.send(
                notification=notif_data,
                recipient=user,
                dedup_window_minutes=dedup_window_minutes,
            )

            # External channels check settings threshold and quiet hours
            can_send_external = sev_rank >= user_min_rank
            if settings and settings.quiet_hours_enabled:
                if _is_within_quiet_hours(settings.quiet_hours_from, settings.quiet_hours_to):
                    # Suppress external channels during quiet hours unless critical
                    if norm_severity != "critical":
                        can_send_external = False

            # Email Delivery
            should_email = False
            if channels and "email" in channels:
                should_email = True
            elif settings and settings.email_enabled and can_send_external:
                should_email = True

            if should_email:
                email_provider.send(notification=notif_data, recipient=user)

            # Webhook Delivery
            should_webhook = False
            if channels and "webhook" in channels:
                should_webhook = True
            elif settings and settings.webhook_enabled and can_send_external:
                should_webhook = True

            if should_webhook:
                # Retrieve webhook URL from user integrations or settings
                integration = Integration.query.filter_by(
                    name="Webhook", connected=True
                ).first()
                if integration and integration.webhook_url:
                    webhook_provider.send(
                        notification=notif_data,
                        recipient=user,
                        webhook_url=integration.webhook_url,
                    )

            dispatched.append({"user_id": user.id, "success": in_app_ok})

        except Exception as e:
            logger.error(f"Error dispatching notification to user {user.id}: {str(e)}", exc_info=True)

    return dispatched


def get_user_notifications(
    user_id: int,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    is_read: Optional[bool] = None,
    is_dismissed: bool = False,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
) -> Tuple[List[Notification], int, int]:
    """
    Fetches paginated, filtered notifications for a specific user.
    Enforces user isolation (IDOR protection).
    Returns (items, total_count, total_pages).
    """
    page = max(1, int(page))
    per_page = max(1, min(100, int(per_page)))

    query = Notification.query.filter(Notification.recipient_user_id == user_id)

    if is_dismissed is not None:
        query = query.filter(Notification.is_dismissed == is_dismissed)

    if category:
        query = query.filter(Notification.category.ilike(f"%{category.strip()}%"))

    if severity:
        query = query.filter(Notification.severity == severity.strip().lower())

    if is_read is not None:
        query = query.filter(Notification.is_read == is_read)

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Notification.title.ilike(s),
                Notification.message.ilike(s),
                Notification.source.ilike(s),
                Notification.resource_id.ilike(s),
            )
        )

    query = query.order_by(Notification.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return pagination.items, pagination.total, pagination.pages


def get_notification_by_id(
    notification_id: str,
    user_id: Optional[int] = None,
    is_admin: bool = False,
) -> Optional[Notification]:
    """
    Retrieves a single notification by notification_id.
    Strictly verifies ownership unless requester is an administrator.
    """
    query = Notification.query.filter(Notification.notification_id == notification_id)
    notif = query.first()
    if not notif:
        return None

    if not is_admin and user_id is not None:
        if notif.recipient_user_id != user_id:
            logger.warning(
                f"IDOR violation attempt: User {user_id} tried to access notification {notification_id} owned by {notif.recipient_user_id}"
            )
            return None

    return notif


def mark_as_read(
    notification_id: str,
    user_id: int,
    is_admin: bool = False,
) -> bool:
    """Marks a single notification as read."""
    notif = get_notification_by_id(notification_id, user_id=user_id, is_admin=is_admin)
    if not notif:
        return False

    if not notif.is_read:
        notif.is_read = True
        notif.read_at = datetime.utcnow()
        db.session.commit()
    return True


def mark_all_as_read(user_id: int) -> int:
    """Marks all unread non-dismissed notifications as read for a given user."""
    unread_notifs = Notification.query.filter(
        Notification.recipient_user_id == user_id,
        Notification.is_read.is_(False),
        Notification.is_dismissed.is_(False),
    ).all()

    now = datetime.utcnow()
    count = 0
    for notif in unread_notifs:
        notif.is_read = True
        notif.read_at = now
        count += 1

    if count > 0:
        db.session.commit()
    return count


def dismiss_notification(
    notification_id: str,
    user_id: int,
    is_admin: bool = False,
) -> bool:
    """Soft-dismisses a notification for a user."""
    notif = get_notification_by_id(notification_id, user_id=user_id, is_admin=is_admin)
    if not notif:
        return False

    if not notif.is_dismissed:
        notif.is_dismissed = True
        notif.dismissed_at = datetime.utcnow()
        db.session.commit()
    return True


def get_unread_count(user_id: int) -> int:
    """Returns total unread, non-dismissed notifications count for a user."""
    return Notification.query.filter(
        Notification.recipient_user_id == user_id,
        Notification.is_read.is_(False),
        Notification.is_dismissed.is_(False),
    ).count()


def get_notification_statistics(user_id: int) -> Dict[str, Any]:
    """Computes summary metrics for user's notification center."""
    base_query = Notification.query.filter(
        Notification.recipient_user_id == user_id,
        Notification.is_dismissed.is_(False),
    )

    total_active = base_query.count()
    unread_count = base_query.filter(Notification.is_read.is_(False)).count()
    critical_high_count = base_query.filter(
        Notification.severity.in_(["critical", "high"])
    ).count()
    system_count = base_query.filter(
        Notification.category.in_(["SYSTEM", "SECURITY", "SCANNER"])
    ).count()

    return {
        "total_active": total_active,
        "unread_count": unread_count,
        "critical_high_count": critical_high_count,
        "system_count": system_count,
    }


def get_user_preferences(user_id: int) -> Dict[str, Any]:
    """Retrieves user notification preferences from NotificationSettings."""
    settings = NotificationSettings.query.filter_by(user_id=user_id).first()
    if not settings:
        return {
            "email_enabled": True,
            "slack_enabled": False,
            "sms_enabled": False,
            "webhook_enabled": False,
            "min_severity": "medium",
            "quiet_hours_enabled": False,
            "quiet_hours_from": "20:00",
            "quiet_hours_to": "07:00",
            "notification_matrix": {},
        }

    try:
        matrix = json.loads(settings.notification_matrix) if settings.notification_matrix else {}
    except Exception:
        matrix = {}

    return {
        "email_enabled": bool(settings.email_enabled),
        "slack_enabled": bool(settings.slack_enabled),
        "sms_enabled": bool(settings.sms_enabled),
        "webhook_enabled": bool(settings.webhook_enabled),
        "min_severity": settings.min_severity or "medium",
        "quiet_hours_enabled": bool(settings.quiet_hours_enabled),
        "quiet_hours_from": settings.quiet_hours_from or "20:00",
        "quiet_hours_to": settings.quiet_hours_to or "07:00",
        "notification_matrix": matrix,
    }


def update_user_preferences(
    user_id: int, data: Dict[str, Any], actor_username: str = "User"
) -> Dict[str, Any]:
    """Updates user notification preferences and records audit trail."""
    settings = NotificationSettings.query.filter_by(user_id=user_id).first()
    if not settings:
        settings = NotificationSettings(user_id=user_id)
        db.session.add(settings)

    if "email_enabled" in data:
        settings.email_enabled = bool(data["email_enabled"])
    if "slack_enabled" in data:
        settings.slack_enabled = bool(data["slack_enabled"])
    if "sms_enabled" in data:
        settings.sms_enabled = bool(data["sms_enabled"])
    if "webhook_enabled" in data:
        settings.webhook_enabled = bool(data["webhook_enabled"])
    if "min_severity" in data:
        sev = str(data["min_severity"]).lower()
        if sev in SEVERITY_LEVELS:
            settings.min_severity = sev
    if "quiet_hours_enabled" in data:
        settings.quiet_hours_enabled = bool(data["quiet_hours_enabled"])
    if "quiet_hours_from" in data:
        settings.quiet_hours_from = str(data["quiet_hours_from"])[:5]
    if "quiet_hours_to" in data:
        settings.quiet_hours_to = str(data["quiet_hours_to"])[:5]
    if "notification_matrix" in data:
        val = data["notification_matrix"]
        settings.notification_matrix = json.dumps(val) if isinstance(val, dict) else str(val)

    db.session.commit()

    # Attempt audit logging
    try:
        from app.audit_logs.services import record_audit_event
        record_audit_event(
            actor=actor_username,
            action="UPDATE_NOTIFICATION_PREFERENCES",
            category="Settings",
            resource_type="User",
            resource_id=str(user_id),
            message=f"User {actor_username} updated notification channel preferences",
            details={
                "min_severity": settings.min_severity,
                "email_enabled": settings.email_enabled,
                "webhook_enabled": settings.webhook_enabled,
            },
        )
    except Exception as e:
        logger.debug(f"Audit log recording skipped: {str(e)}")

    return get_user_preferences(user_id)

