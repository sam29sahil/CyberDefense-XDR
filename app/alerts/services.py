"""
CyberDefense XDR
Alert Center Services
"""

import json
import secrets
from datetime import datetime
from sqlalchemy import or_, and_, func

from app.extensions import db
from app.alerts.models import Alert
from app.detection.models import DetectionEvent
from app.users.models import User
from app.incidents.models import Incident
from app.incidents.services import create_incident


# ============================================================
# CONSTANTS & LIFECYCLE
# ============================================================

ALLOWED_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
}

ALLOWED_STATUSES = {
    "new",
    "acknowledged",
    "investigating",
    "escalated",
    "resolved",
    "false_positive",
    "suppressed",
}

VALID_TRANSITIONS = {
    "new": {"acknowledged", "investigating", "resolved", "false_positive", "suppressed"},
    "acknowledged": {"investigating", "escalated", "resolved", "false_positive", "suppressed"},
    "investigating": {"escalated", "resolved", "false_positive", "suppressed", "acknowledged"},
    "escalated": {"investigating", "resolved", "false_positive", "suppressed"},
    "false_positive": {"new", "investigating"},
    "suppressed": {"new", "investigating"},
    "resolved": {"new", "investigating"},
}


# ============================================================
# ID GENERATION & VALIDATION
# ============================================================

def generate_alert_id():
    """
    Generate a unique public alert ID.
    Example: ALT-483921
    """
    while True:
        alert_id = f"ALT-{secrets.randbelow(900000) + 100000}"
        if not Alert.query.filter_by(alert_id=alert_id).first():
            return alert_id


def validate_severity(severity):
    sev = str(severity or "medium").strip().lower()
    if sev not in ALLOWED_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(ALLOWED_SEVERITIES))}")
    return sev


def validate_status(status):
    st = str(status or "new").strip().lower()
    if st not in ALLOWED_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(sorted(ALLOWED_STATUSES))}")
    return st


# ============================================================
# ALERT RETRIEVAL
# ============================================================

def get_alert_by_id(pk_id):
    """Get Alert by database primary key."""
    return db.session.get(Alert, pk_id)


def get_alert(alert_id):
    """Get Alert by public string identifier (e.g. ALT-123456)."""
    if not alert_id:
        return None
    return Alert.query.filter_by(alert_id=str(alert_id).strip()).first()


def get_alerts(filters=None, page=1, per_page=20):
    """
    Retrieve paginated alerts supporting SOC-style filtering.
    """
    filters = filters or {}
    query = Alert.query

    # Severity filter
    severity = filters.get("severity")
    if severity:
        if isinstance(severity, list):
            query = query.filter(Alert.severity.in_([s.lower() for s in severity]))
        elif isinstance(severity, str) and severity.strip().lower() != "all":
            query = query.filter(Alert.severity == severity.strip().lower())

    # Status filter
    status = filters.get("status")
    if status:
        if isinstance(status, list):
            query = query.filter(Alert.status.in_([s.lower() for s in status]))
        elif isinstance(status, str) and status.strip().lower() != "all":
            query = query.filter(Alert.status == status.strip().lower())

    # Category filter
    category = filters.get("category")
    if category and category.strip().lower() != "all":
        query = query.filter(Alert.category.ilike(f"%{category.strip()}%"))

    # Source filter
    source = filters.get("source")
    if source and source.strip().lower() != "all":
        query = query.filter(Alert.source.ilike(f"%{source.strip()}%"))

    # Assignee filter (by user id or 'unassigned')
    assigned_to = filters.get("assigned_to")
    if assigned_to:
        if str(assigned_to).lower() == "unassigned":
            query = query.filter(Alert.assigned_to.is_(None))
        else:
            try:
                query = query.filter(Alert.assigned_to == int(assigned_to))
            except (ValueError, TypeError):
                pass

    # Free text search across title, description, host, asset, alert_id, mitre_id
    search = filters.get("search")
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Alert.alert_id.ilike(search_term),
                Alert.title.ilike(search_term),
                Alert.description.ilike(search_term),
                Alert.affected_host.ilike(search_term),
                Alert.affected_asset.ilike(search_term),
                Alert.mitre_id.ilike(search_term),
                Alert.mitre_name.ilike(search_term),
            )
        )

    # Date range filters
    start_date = filters.get("start_date")
    if start_date:
        if isinstance(start_date, str):
            try:
                start_date = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
            except ValueError:
                start_date = None
        if start_date:
            query = query.filter(Alert.created_at >= start_date)

    end_date = filters.get("end_date")
    if end_date:
        if isinstance(end_date, str):
            try:
                end_date = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
            except ValueError:
                end_date = None
        if end_date:
            query = query.filter(Alert.created_at <= end_date)

    # Ordering
    query = query.order_by(Alert.created_at.desc())

    # Pagination
    total = query.count()
    if page and per_page:
        items = query.paginate(page=page, per_page=per_page, error_out=False).items
    else:
        items = query.all()

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def get_alert_statistics():
    """
    Calculate high-level dashboard metrics for Alert Center KPI cards.
    """
    total = Alert.query.count()

    # Severity counts
    critical = Alert.query.filter_by(severity="critical").count()
    high = Alert.query.filter_by(severity="high").count()
    medium = Alert.query.filter_by(severity="medium").count()
    low = Alert.query.filter_by(severity="low").count()

    # Status counts
    new_count = Alert.query.filter_by(status="new").count()
    acknowledged = Alert.query.filter_by(status="acknowledged").count()
    investigating = Alert.query.filter_by(status="investigating").count()
    escalated = Alert.query.filter_by(status="escalated").count()
    resolved = Alert.query.filter_by(status="resolved").count()
    false_positive = Alert.query.filter_by(status="false_positive").count()
    suppressed = Alert.query.filter_by(status="suppressed").count()

    # Unassigned count
    unassigned = Alert.query.filter(Alert.assigned_to.is_(None)).count()

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "new": new_count,
        "acknowledged": acknowledged,
        "investigating": investigating,
        "escalated": escalated,
        "resolved": resolved,
        "false_positive": false_positive,
        "suppressed": suppressed,
        "unassigned": unassigned,
    }


# ============================================================
# ALERT LIFECYCLE & MUTATIONS
# ============================================================

def create_alert(data, user=None):
    """
    Create a new security Alert.
    """
    title = str(data.get("title", "")).strip()
    if not title:
        raise ValueError("Alert title is required.")

    severity = validate_severity(data.get("severity", "medium"))
    status = validate_status(data.get("status", "new"))

    # Foreign key validations
    detection_event_id = data.get("detection_event_id")
    if detection_event_id:
        event = db.session.get(DetectionEvent, detection_event_id)
        if not event:
            raise ValueError(f"Detection event with id {detection_event_id} does not exist.")

    assigned_to = data.get("assigned_to")
    if assigned_to:
        assignee = db.session.get(User, assigned_to)
        if not assignee:
            raise ValueError(f"User with id {assigned_to} does not exist.")

    # Parse metadata_json
    metadata = data.get("metadata_json") or data.get("metadata")
    if isinstance(metadata, dict):
        metadata_str = json.dumps(metadata)
    elif isinstance(metadata, str):
        metadata_str = metadata
    else:
        metadata_str = "{}"

    now = datetime.utcnow()

    alert = Alert(
        alert_id=generate_alert_id(),
        title=title,
        description=str(data.get("description", "")).strip() or None,
        severity=severity,
        status=status,
        category=str(data.get("category", "")).strip() or "Security",
        source=str(data.get("source", "")).strip() or "Manual",
        rule_id=str(data.get("rule_id", "")).strip() or None,
        detection_event_id=detection_event_id,
        affected_host=str(data.get("affected_host", "")).strip() or None,
        affected_asset=str(data.get("affected_asset", "")).strip() or None,
        mitre_id=str(data.get("mitre_id", "")).strip() or None,
        mitre_name=str(data.get("mitre_name", "")).strip() or None,
        assigned_to=assigned_to,
        incident_id=str(data.get("incident_id", "")).strip() or None,
        investigation_notes=str(data.get("investigation_notes", "")).strip() or None,
        resolution_notes=str(data.get("resolution_notes", "")).strip() or None,
        metadata_json=metadata_str,
        created_at=now,
        updated_at=now,
        acknowledged_at=now if status == "acknowledged" else None,
        resolved_at=now if status == "resolved" else None,
    )

    db.session.add(alert)
    db.session.commit()
    return alert


def acknowledge_alert(alert, user=None):
    """
    Acknowledge an alert. Valid from 'new'.
    """
    if not alert:
        raise ValueError("Alert is required.")

    if alert.status not in ("new", "acknowledged"):
        raise ValueError(f"Cannot acknowledge alert in '{alert.status}' status.")

    now = datetime.utcnow()
    alert.status = "acknowledged"
    if not alert.acknowledged_at:
        alert.acknowledged_at = now
    alert.updated_at = now

    # Optionally auto-assign if unassigned and user provided
    if not alert.assigned_to and user and hasattr(user, "id"):
        alert.assigned_to = user.id

    db.session.commit()
    return alert


def change_alert_status(alert, new_status, notes=None, user=None):
    """
    Change alert status respecting lifecycle state machine.
    """
    if not alert:
        raise ValueError("Alert is required.")

    target_status = validate_status(new_status)
    current_status = alert.status

    if target_status == current_status:
        # If notes were provided, append them
        if notes:
            now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            user_label = user.email if user and hasattr(user, "email") else "System"
            append_note = f"[{now_str}] ({user_label}) Status kept as {target_status}: {notes.strip()}"
            alert.investigation_notes = (
                f"{alert.investigation_notes}\n{append_note}"
                if alert.investigation_notes
                else append_note
            )
            db.session.commit()
        return alert

    # Check allowed transitions
    allowed = VALID_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise ValueError(
            f"Invalid status transition from '{current_status}' to '{target_status}'. "
            f"Allowed transitions: {', '.join(sorted(allowed)) if allowed else 'None'}"
        )

    now = datetime.utcnow()
    alert.status = target_status
    alert.updated_at = now

    # Set lifecycle timestamps
    if target_status in ("acknowledged", "investigating") and not alert.acknowledged_at:
        alert.acknowledged_at = now

    if target_status == "resolved":
        alert.resolved_at = now
        if notes:
            alert.resolution_notes = (
                f"{alert.resolution_notes}\n{notes.strip()}"
                if alert.resolution_notes
                else notes.strip()
            )
    elif current_status == "resolved" and target_status in ("new", "investigating"):
        # Reopening alert
        alert.resolved_at = None

    if notes and target_status != "resolved":
        now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
        user_label = user.email if user and hasattr(user, "email") else "Analyst"
        append_note = f"[{now_str}] ({user_label}) Status changed to {target_status}: {notes.strip()}"
        alert.investigation_notes = (
            f"{alert.investigation_notes}\n{append_note}"
            if alert.investigation_notes
            else append_note
        )

    db.session.commit()
    return alert


def assign_alert(alert, user_id=None, notes=None, current_user=None):
    """
    Assign or unassign an alert to an analyst.
    """
    if not alert:
        raise ValueError("Alert is required.")

    if user_id is not None and user_id != "":
        user = db.session.get(User, int(user_id))
        if not user:
            raise ValueError(f"User with ID {user_id} does not exist.")
        alert.assigned_to = user.id
        assigned_label = user.email
    else:
        alert.assigned_to = None
        assigned_label = "Unassigned"

    now = datetime.utcnow()
    alert.updated_at = now

    # If assigning from 'new', optionally move to 'acknowledged' if not already
    if alert.status == "new" and alert.assigned_to:
        alert.status = "acknowledged"
        if not alert.acknowledged_at:
            alert.acknowledged_at = now

    if notes or alert.assigned_to:
        now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
        actor_label = current_user.email if current_user and hasattr(current_user, "email") else "System"
        extra = f": {notes.strip()}" if notes else ""
        append_note = f"[{now_str}] ({actor_label}) Assigned to {assigned_label}{extra}"
        alert.investigation_notes = (
            f"{alert.investigation_notes}\n{append_note}"
            if alert.investigation_notes
            else append_note
        )

    db.session.commit()
    return alert


def resolve_alert(alert, resolution_notes, user=None):
    """
    Resolve an alert with closing resolution notes.
    """
    if not alert:
        raise ValueError("Alert is required.")

    notes = str(resolution_notes or "").strip()
    if not notes:
        raise ValueError("Resolution notes are required when resolving an alert.")

    return change_alert_status(alert, "resolved", notes=notes, user=user)


# ============================================================
# INTEGRATION: DETECTION EVENT -> ALERT
# ============================================================

def create_alert_from_detection_event(detection_event):
    """
    Generate an Alert from a DetectionEvent.
    Implements deduplication by checking detection_event_id.
    """
    if not detection_event:
        raise ValueError("Detection event is required.")

    # Deduplication check
    existing = Alert.query.filter_by(detection_event_id=detection_event.id).first()
    if existing:
        return existing

    rule = detection_event.rule

    title = (
        f"{rule.name} on {detection_event.host}"
        if (rule and detection_event.host)
        else (rule.name if rule else f"Detection Event {detection_event.event_id}")
    )

    description = (
        rule.description
        if (rule and rule.description)
        else f"Security detection triggered from source {detection_event.source}"
    )

    severity = (
        detection_event.severity
        or (rule.severity if rule else "medium")
    ).lower()

    category = (rule.category if rule else "Security Event")
    source = detection_event.source or (rule.source if rule else "Detection Engine")

    mitre_id = detection_event.mitre_id or (rule.mitre_id if rule else None)
    mitre_name = rule.mitre_name if rule else None

    # Construct metadata
    meta = {
        "event_id": detection_event.event_id,
        "rule_id": rule.rule_id if rule else None,
        "event_timestamp": detection_event.timestamp.isoformat() if detection_event.timestamp else None,
        "raw_event": detection_event.raw_event,
    }

    alert_data = {
        "title": title,
        "description": description,
        "severity": severity,
        "status": "new",
        "category": category,
        "source": source,
        "rule_id": rule.rule_id if rule else None,
        "detection_event_id": detection_event.id,
        "affected_host": detection_event.host,
        "affected_asset": detection_event.host,
        "mitre_id": mitre_id,
        "mitre_name": mitre_name,
        "metadata_json": json.dumps(meta),
    }

    return create_alert(alert_data)


# ============================================================
# INTEGRATION: ALERT -> INCIDENT
# ============================================================

def link_alert_to_incident(alert, incident_id):
    """
    Link an existing incident identifier to an alert.
    """
    if not alert:
        raise ValueError("Alert is required.")

    inc_id = str(incident_id or "").strip()
    if not inc_id:
        raise ValueError("Incident ID is required.")

    incident = Incident.query.filter_by(incident_id=inc_id).first()
    if not incident:
        raise ValueError(f"Incident '{inc_id}' not found.")

    alert.incident_id = incident.incident_id
    alert.updated_at = datetime.utcnow()
    db.session.commit()
    return alert


def create_incident_from_alert(alert, current_user=None, extra_data=None):
    """
    Create a new Incident from an Alert using the existing Incident Response module.
    Preserves detection_event association and links incident_id to Alert.
    """
    if not alert:
        raise ValueError("Alert is required.")

    # Check if incident already linked
    if alert.incident_id:
        existing = Incident.query.filter_by(incident_id=alert.incident_id).first()
        if existing:
            return existing

    extra_data = extra_data or {}

    title = extra_data.get("title") or f"Incident: {alert.title}"
    description = (
        extra_data.get("description")
        or (
            f"Escalated from Alert {alert.alert_id}.\n\n"
            f"{alert.description or 'No description provided.'}\n\n"
            f"Investigation Notes:\n{alert.investigation_notes or 'None'}"
        )
    )

    incident_payload = {
        "title": title,
        "description": description,
        "category": extra_data.get("category") or alert.category or "Security",
        "severity": extra_data.get("severity") or alert.severity or "medium",
        "priority": extra_data.get("priority") or alert.severity or "medium",
        "status": "new",
        "source": f"Alert Center ({alert.alert_id})",
        "affectedHost": alert.affected_host,
        "affectedAsset": alert.affected_asset,
        "mitreId": alert.mitre_id,
        "mitreName": alert.mitre_name,
        "investigationNotes": alert.investigation_notes,
        "assignedTo": alert.assigned_to,
    }

    # Fetch associated detection event if present
    detection_event = None
    if alert.detection_event_id:
        detection_event = db.session.get(DetectionEvent, alert.detection_event_id)

    incident = create_incident(
        incident_payload,
        created_by=current_user,
        detection_event=detection_event,
    )

    # Link incident_id to alert and advance status
    alert.incident_id = incident.incident_id
    if alert.status in ("new", "acknowledged"):
        alert.status = "investigating"
    alert.updated_at = datetime.utcnow()

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    actor_label = current_user.email if current_user and hasattr(current_user, "email") else "Analyst"
    append_note = f"[{now_str}] ({actor_label}) Escalated to Incident {incident.incident_id}"
    alert.investigation_notes = (
        f"{alert.investigation_notes}\n{append_note}"
        if alert.investigation_notes
        else append_note
    )

    db.session.commit()
    return incident
