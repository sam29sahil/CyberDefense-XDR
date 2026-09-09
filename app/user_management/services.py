"""
CyberDefense XDR
User Management & RBAC Service Layer
Encapsulates CRUD operations, password complexity validation, last-admin protection,
self-modification safety, and SIEM audit logging.
"""

import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from app.extensions import db
from app.users.models import User
from app.user_management.permissions import (
    ALL_PERMISSIONS,
    ROLE_PERMISSIONS,
    ROLE_METADATA,
    normalize_role,
    get_permissions_for_role,
)

logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r"^[\w\.\+\-]+@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{3,50}$")


def validate_password_complexity(password: str) -> Tuple[bool, Optional[str]]:
    """
    Enforces enterprise password complexity:
    - Minimum 8 characters
    - At least one uppercase character
    - At least one lowercase character
    - At least one digit
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    return True, None


def validate_username(username: str, current_user_id: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """Validates format and uniqueness of username."""
    if not username or not USERNAME_REGEX.match(username.strip()):
        return False, "Username must be between 3 and 50 characters and contain only letters, numbers, hyphens, dots, or underscores."
    
    query = User.query.filter(db.func.lower(User.username) == username.strip().lower())
    if current_user_id:
        query = query.filter(User.id != current_user_id)
    
    if query.first():
        return False, f"Username '{username.strip()}' is already taken."
    return True, None


def validate_email(email: str, current_user_id: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """Validates format and uniqueness of email."""
    if not email or not EMAIL_REGEX.match(email.strip()):
        return False, "A valid email address is required."
    
    query = User.query.filter(db.func.lower(User.email) == email.strip().lower())
    if current_user_id:
        query = query.filter(User.id != current_user_id)
        
    if query.first():
        return False, f"Email '{email.strip()}' is already registered."
    return True, None


def count_active_admins() -> int:
    """
    Counts the number of active, non-locked administrators in the system.
    Recognizes canonical role 'ADMIN' as well as alias strings.
    """
    active_users = User.query.filter(
        User.status == "active",
        User.is_active.is_(True)
    ).all()
    admin_count = 0
    for u in active_users:
        if u.get_canonical_role() == "ADMIN" and not u.is_locked:
            admin_count += 1
    return admin_count


def list_users(
    page: int = 1,
    per_page: int = 20,
    search_query: Optional[str] = None,
    role_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Queries users with search, role/status filtering, and pagination.
    """
    query = User.query

    if search_query:
        sq = f"%{search_query.strip().lower()}%"
        query = query.filter(
            db.or_(
                db.func.lower(User.username).like(sq),
                db.func.lower(User.email).like(sq),
                db.func.lower(User.first_name).like(sq),
                db.func.lower(User.last_name).like(sq),
                db.func.lower(User.company).like(sq),
            )
        )

    if status_filter and status_filter.lower() != "all":
        query = query.filter(User.status == status_filter.lower())

    # Fetch ordered by id desc
    query = query.order_by(User.id.desc())

    # Filter roles if specified
    all_matched = query.all()
    if role_filter and role_filter.upper() != "ALL":
        target_role = normalize_role(role_filter)
        filtered_users = [u for u in all_matched if u.get_canonical_role() == target_role]
    else:
        filtered_users = all_matched

    total_count = len(filtered_users)
    start = (page - 1) * per_page
    end = start + per_page
    page_users = filtered_users[start:end]

    return {
        "users": [u.to_dict(include_permissions=False) for u in page_users],
        "total": total_count,
        "page": page,
        "per_page": per_page,
        "pages": (total_count + per_page - 1) // per_page if per_page > 0 else 1,
    }


def get_user_by_id(user_id: int, include_permissions: bool = True) -> Optional[Dict[str, Any]]:
    """Retrieves detailed user data including assigned permissions and system activity."""
    user = User.query.get(user_id)
    if not user:
        return None

    data = user.to_dict(include_permissions=include_permissions)
    
    # Calculate operational metrics
    try:
        from app.incidents.models import Incident
        from app.alerts.models import Alert
        assigned_incidents = Incident.query.filter(
            (Incident.assigned_to == user.id) | (Incident.created_by == user.id)
        ).count()
        assigned_alerts = Alert.query.filter(Alert.assigned_to == user.id).count()
    except Exception:
        assigned_incidents = 0
        assigned_alerts = 0

    data["metrics"] = {
        "assigned_incidents": assigned_incidents,
        "assigned_alerts": assigned_alerts,
    }
    return data


def create_managed_user(data: Dict[str, Any], creator_user: Optional[User] = None) -> User:
    """
    Validates and creates a new user account with assigned role and status.
    """
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    company = (data.get("company") or "").strip()
    role_input = (data.get("role") or "SOC_ANALYST").strip()
    status_input = (data.get("status") or "active").strip().lower()
    password = data.get("password") or ""

    # Validations
    if not first_name or not last_name:
        raise ValueError("First name and last name are required.")

    valid_user, err_user = validate_username(username)
    if not valid_user:
        raise ValueError(err_user)

    valid_email, err_email = validate_email(email)
    if not valid_email:
        raise ValueError(err_email)

    valid_pw, err_pw = validate_password_complexity(password)
    if not valid_pw:
        raise ValueError(err_pw)

    canonical_role = normalize_role(role_input)
    if canonical_role not in ROLE_METADATA:
        raise ValueError(f"Invalid role '{role_input}'. Allowed roles: {list(ROLE_METADATA.keys())}")

    if status_input not in ("active", "inactive", "disabled", "locked"):
        raise ValueError("Status must be one of: active, inactive, disabled, locked")

    user = User(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        company=company,
        role=canonical_role,
        status=status_input,
        is_active=(status_input == "active"),
        failed_login_count=0,
        account_locked_until=None,
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    log_user_audit_event(
        action="User Created",
        message=f"User {user.username} ({user.email}) created with role {canonical_role} and status {status_input}.",
        target_user=user,
        actor_user=creator_user,
    )

    return user


def update_managed_user(user_id: int, data: Dict[str, Any], current_user: Optional[User] = None) -> User:
    """
    Updates user details with safety checks:
    - Last-admin protection: cannot demote or deactivate the last active admin
    - Self-protection: cannot disable, lock, or demote own account
    """
    user = User.query.get(user_id)
    if not user:
        raise ValueError(f"User with ID {user_id} does not exist.")

    is_self = (current_user and current_user.id == user.id)

    # 1. Check self-protection against deactivation
    new_status = data.get("status")
    if new_status:
        new_status = new_status.strip().lower()
        if new_status not in ("active", "inactive", "disabled", "locked"):
            raise ValueError("Status must be one of: active, inactive, disabled, locked")

        if is_self and new_status != "active":
            raise ValueError("Security restriction: You cannot deactivate or lock your own account.")

    # 2. Check role mutation and last-admin safety
    new_role = data.get("role")
    canonical_role = user.get_canonical_role()
    if new_role:
        canonical_role = normalize_role(new_role)
        if canonical_role not in ROLE_METADATA:
            raise ValueError(f"Invalid role '{new_role}'. Allowed roles: {list(ROLE_METADATA.keys())}")

        if is_self and user.get_canonical_role() == "ADMIN" and canonical_role != "ADMIN":
            raise ValueError("Security restriction: You cannot demote your own Administrator account.")

    # Check last-admin protection whenever modifying an active administrator
    if user.get_canonical_role() == "ADMIN" and user.status == "active":
        will_lose_admin = (canonical_role != "ADMIN") or (new_status and new_status != "active")
        if will_lose_admin and count_active_admins() <= 1:
            raise ValueError("Cannot demote or deactivate the last remaining active Administrator.")

    if new_role:
        user.role = canonical_role

    # 3. Status updates and lock clearance
    if new_status:
        user.status = new_status
        if new_status == "active":
            user.is_active = True
            user.failed_login_count = 0
            user.account_locked_until = None
        elif new_status in ("inactive", "disabled"):
            user.is_active = False
        elif new_status == "locked":
            user.is_active = False

    # 4. Username / Email updates
    if "username" in data and data["username"]:
        un = data["username"].strip()
        if un != user.username:
            valid_un, err_un = validate_username(un, current_user_id=user.id)
            if not valid_un:
                raise ValueError(err_un)
            user.username = un

    if "email" in data and data["email"]:
        em = data["email"].strip()
        if em != user.email:
            valid_em, err_em = validate_email(em, current_user_id=user.id)
            if not valid_em:
                raise ValueError(err_em)
            user.email = em

    if "first_name" in data and data["first_name"]:
        user.first_name = data["first_name"].strip()

    if "last_name" in data and data["last_name"]:
        user.last_name = data["last_name"].strip()

    if "company" in data:
        user.company = data["company"].strip() if data["company"] else None

    # 5. Password update
    if "password" in data and data["password"]:
        pw = data["password"]
        valid_pw, err_pw = validate_password_complexity(pw)
        if not valid_pw:
            raise ValueError(err_pw)
        user.set_password(pw)

    user.updated_at = datetime.utcnow()
    db.session.commit()

    log_user_audit_event(
        action="User Updated",
        message=f"User {user.username} (ID {user.id}) updated. Role: {user.role}, Status: {user.status}.",
        target_user=user,
        actor_user=current_user,
    )

    return user


def delete_managed_user(user_id: int, current_user: Optional[User] = None) -> Dict[str, Any]:
    """
    Safely deletes or deactivates a user.
    - Prevents self-deletion.
    - Prevents deleting the last remaining active Administrator.
    - Checks referential dependencies (Incidents, Alerts, SOAR, Threat Hunt).
      If linked records exist, soft-deactivates the user to protect audit integrity.
      If no dependencies exist, hard deletes the user.
    """
    user = User.query.get(user_id)
    if not user:
        raise ValueError(f"User with ID {user_id} does not exist.")

    if current_user and current_user.id == user.id:
        raise ValueError("Security restriction: You cannot delete your own account.")

    if user.get_canonical_role() == "ADMIN" and user.status == "active":
        if count_active_admins() <= 1:
            raise ValueError("Cannot delete the last remaining active Administrator.")

    # Check referential integrity across XDR modules
    has_linked_records = False
    reasons = []

    try:
        from app.incidents.models import Incident
        incident_count = Incident.query.filter(
            (Incident.created_by == user.id) | (Incident.assigned_to == user.id)
        ).count()
        if incident_count > 0:
            has_linked_records = True
            reasons.append(f"{incident_count} incidents")
    except Exception as e:
        logger.debug(f"Incident check error: {e}")

    try:
        from app.alerts.models import Alert
        alert_count = Alert.query.filter(Alert.assigned_to == user.id).count()
        if alert_count > 0:
            has_linked_records = True
            reasons.append(f"{alert_count} alerts")
    except Exception as e:
        logger.debug(f"Alert check error: {e}")

    try:
        from app.soar.models import SOARPlaybookExecution, SOARApproval
        playbook_count = SOARPlaybookExecution.query.filter_by(user_id=user.id).count()
        approval_count = SOARApproval.query.filter(
            (SOARApproval.requested_by_id == user.id) | (SOARApproval.decided_by_id == user.id)
        ).count()
        if playbook_count > 0 or approval_count > 0:
            has_linked_records = True
            reasons.append(f"{playbook_count + approval_count} SOAR actions")
    except Exception as e:
        logger.debug(f"SOAR check error: {e}")

    try:
        from app.threat_hunting.models import ThreatHuntQuery
        hunt_count = ThreatHuntQuery.query.filter_by(user_id=user.id).count()
        if hunt_count > 0:
            has_linked_records = True
            reasons.append(f"{hunt_count} threat hunting queries")
    except Exception as e:
        logger.debug(f"Threat hunting check error: {e}")

    if has_linked_records:
        # Soft deactivate to maintain forensic and referential integrity
        user.status = "disabled"
        user.is_active = False
        user.updated_at = datetime.utcnow()
        db.session.commit()

        reason_str = ", ".join(reasons)
        log_user_audit_event(
            action="User Deactivated",
            message=f"User {user.username} (ID {user.id}) deactivated rather than deleted due to linked security history ({reason_str}).",
            target_user=user,
            actor_user=current_user,
        )

        return {
            "success": True,
            "deleted": False,
            "soft_deleted": True,
            "message": f"User '{user.username}' has linked security records ({reason_str}). Account has been safely disabled to maintain forensic audit trails.",
            "user": user.to_dict(),
        }

    # Clean up non-critical user-specific settings if any
    try:
        from app.settings.models import (
            ProfileSettings,
            NotificationSettings,
            SecuritySettings,
            AppearanceSettings,
            IntegrationSettings,
        )
        ProfileSettings.query.filter_by(user_id=user.id).delete()
        NotificationSettings.query.filter_by(user_id=user.id).delete()
        SecuritySettings.query.filter_by(user_id=user.id).delete()
        AppearanceSettings.query.filter_by(user_id=user.id).delete()
        IntegrationSettings.query.filter_by(user_id=user.id).delete()
    except Exception as e:
        logger.debug(f"Settings clean error: {e}")

    username_cached = user.username
    email_cached = user.email
    db.session.delete(user)
    db.session.commit()

    log_user_audit_event(
        action="User Deleted",
        message=f"User {username_cached} ({email_cached}) permanently deleted from system.",
        target_user=None,
        actor_user=current_user,
    )

    return {
        "success": True,
        "deleted": True,
        "soft_deleted": False,
        "message": f"User '{username_cached}' was permanently deleted.",
    }


def get_role_summary() -> List[Dict[str, Any]]:
    """
    Returns high-level metadata and user counts for all canonical roles.
    """
    users = User.query.all()
    counts: Dict[str, int] = {}
    for u in users:
        canon = u.get_canonical_role()
        counts[canon] = counts.get(canon, 0) + 1

    summary = []
    for role_id, meta in ROLE_METADATA.items():
        perms = get_permissions_for_role(role_id)
        summary.append({
            "id": role_id,
            "name": meta["name"],
            "badge_color": meta["badge_color"],
            "badge_class": meta["badge_class"],
            "description": meta["description"],
            "user_count": counts.get(role_id, 0),
            "permission_count": len(perms) if "*" not in perms else len(ALL_PERMISSIONS),
            "permissions": sorted(list(perms)),
        })
    return summary


def log_user_audit_event(
    action: str,
    message: str,
    target_user: Optional[User] = None,
    actor_user: Optional[User] = None,
) -> None:
    """
    Dispatches a structured security audit event into the XDR SIEM pipeline.
    Records an administrative IAM event into AuditLog and dispatches to SIEM.
    """
    actor_str = actor_user.username if (actor_user and hasattr(actor_user, "username")) else "System/Admin"
    logger.info(f"[RBAC Audit] [{action}] by {actor_str}: {message}")

    try:
        from app.audit_logs.services import record_audit_event
        norm_action = f"USER_{action.upper().replace(' ', '_')}"
        record_audit_event(
            action=norm_action,
            category="User Management",
            message=message,
            actor=actor_str,
            actor_id=getattr(actor_user, "id", None),
            resource_type="User",
            resource_id=str(target_user.id) if target_user else None,
            result="SUCCESS",
            severity="medium" if "Delete" in action or "Deactivate" in action else "info",
            details={
                "action": action,
                "actor": actor_str,
                "target_username": target_user.username if target_user else None,
                "target_id": target_user.id if target_user else None,
            },
            sync_to_siem=True,
        )
    except Exception as e:
        logger.warning(f"Failed to record IAM audit log: {e}")
