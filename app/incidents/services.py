"""
CyberDefense XDR
Incident Response Services
"""

import secrets
from datetime import datetime

from app.extensions import db

from app.incidents.models import Incident


# ============================================================
# CONSTANTS
# ============================================================

ALLOWED_SEVERITIES = {
    "critical",
    "high",
    "medium",
    "low",
}

ALLOWED_PRIORITIES = {
    "critical",
    "high",
    "medium",
    "low",
}

ALLOWED_STATUSES = {
    "new",
    "investigating",
    "contained",
    "resolved",
    "closed",
}


# ============================================================
# ID GENERATOR
# ============================================================

def generate_incident_id():
    """
    Generate a unique incident ID.

    Example:
        INC-483921
    """

    while True:

        incident_id = (
            f"INC-{secrets.randbelow(900000) + 100000}"
        )

        existing = Incident.query.filter_by(
            incident_id=incident_id
        ).first()

        if not existing:
            return incident_id


# ============================================================
# VALIDATION HELPERS
# ============================================================

def validate_severity(severity):
    severity = str(
        severity or "medium"
    ).strip().lower()

    if severity not in ALLOWED_SEVERITIES:
        raise ValueError("Invalid incident severity.")

    return severity


def validate_priority(priority):
    priority = str(
        priority or "medium"
    ).strip().lower()

    if priority not in ALLOWED_PRIORITIES:
        raise ValueError("Invalid incident priority.")

    return priority


def validate_status(status):
    status = str(
        status or "new"
    ).strip().lower()

    if status not in ALLOWED_STATUSES:
        raise ValueError("Invalid incident status.")

    return status


# ============================================================
# CREATE INCIDENT
# ============================================================

def create_incident(
    data,
    created_by=None,
    detection_event=None,
):
    """
    Create a new security incident.

    The incident may optionally be linked to a
    DetectionEvent.
    """

    title = str(
        data.get("title", "")
    ).strip()

    if not title:
        raise ValueError(
            "Incident title is required."
        )

    severity = validate_severity(
        data.get("severity", "medium")
    )

    priority = validate_priority(
        data.get("priority", severity)
    )

    status = validate_status(
        data.get("status", "new")
    )

    category = str(
        data.get(
            "category",
            "Security"
        )
    ).strip()

    if not category:
        category = "Security"

    incident = Incident(
        incident_id=generate_incident_id(),

        title=title,

        description=str(
            data.get("description", "")
        ).strip() or None,

        category=category,

        severity=severity,

        priority=priority,

        status=status,

        created_by=(
            created_by.id
            if created_by
            else None
        ),

        source=str(
            data.get("source", "")
        ).strip() or None,

        affected_host=str(
            data.get("affectedHost", "")
        ).strip() or None,

        affected_asset=str(
            data.get("affectedAsset", "")
        ).strip() or None,

        mitre_id=str(
            data.get("mitreId", "")
        ).strip() or None,

        mitre_name=str(
            data.get("mitreName", "")
        ).strip() or None,

        investigation_notes=str(
            data.get("investigationNotes", "")
        ).strip() or None,

        containment_notes=str(
            data.get("containmentNotes", "")
        ).strip() or None,

        resolution_notes=str(
            data.get("resolutionNotes", "")
        ).strip() or None,

        assigned_to=data.get("assignedTo"),

        detection_event_id=(
            detection_event.id
            if detection_event
            else None
        ),

        detected_at=(
            detection_event.timestamp
            if detection_event
            else datetime.utcnow()
        ),
    )

    db.session.add(incident)
    db.session.commit()

    return incident


# ============================================================
# UPDATE INCIDENT
# ============================================================

def update_incident(
    incident,
    data,
):
    """
    Update an existing incident.
    """

    if "title" in data:

        title = str(
            data["title"]
        ).strip()

        if not title:
            raise ValueError(
                "Incident title is required."
            )

        incident.title = title

    if "description" in data:

        incident.description = (
            str(data["description"]).strip()
            or None
        )

    if "category" in data:

        incident.category = (
            str(data["category"]).strip()
            or "Security"
        )

    if "severity" in data:

        incident.severity = validate_severity(
            data["severity"]
        )

    if "priority" in data:

        incident.priority = validate_priority(
            data["priority"]
        )

    if "status" in data:

        new_status = validate_status(
            data["status"]
        )

        incident.status = new_status

        if new_status in {
            "resolved",
            "closed",
        }:

            if not incident.resolved_at:
                incident.resolved_at = (
                    datetime.utcnow()
                )

        else:

            incident.resolved_at = None

    if "assignedTo" in data:

        incident.assigned_to = (
            data["assignedTo"]
        )

    if "source" in data:

        incident.source = (
            str(data["source"]).strip()
            or None
        )

    if "affectedHost" in data:

        incident.affected_host = (
            str(data["affectedHost"]).strip()
            or None
        )

    if "affectedAsset" in data:

        incident.affected_asset = (
            str(data["affectedAsset"]).strip()
            or None
        )

    if "mitreId" in data:

        incident.mitre_id = (
            str(data["mitreId"]).strip()
            or None
        )

    if "mitreName" in data:

        incident.mitre_name = (
            str(data["mitreName"]).strip()
            or None
        )

    if "investigationNotes" in data:

        incident.investigation_notes = (
            str(
                data["investigationNotes"]
            ).strip()
            or None
        )

    if "containmentNotes" in data:

        incident.containment_notes = (
            str(
                data["containmentNotes"]
            ).strip()
            or None
        )

    if "resolutionNotes" in data:

        incident.resolution_notes = (
            str(
                data["resolutionNotes"]
            ).strip()
            or None
        )

    db.session.commit()

    return incident


# ============================================================
# ASSIGN INCIDENT
# ============================================================

def assign_incident(
    incident,
    user_id,
):
    """
    Assign an incident to a user.
    """

    if not user_id:
        raise ValueError(
            "User ID is required."
        )

    incident.assigned_to = user_id

    db.session.commit()

    return incident


# ============================================================
# CHANGE STATUS
# ============================================================

def change_status(
    incident,
    status,
):
    """
    Change incident lifecycle status.
    """

    status = validate_status(status)

    incident.status = status

    if status in {
        "resolved",
        "closed",
    }:

        if not incident.resolved_at:
            incident.resolved_at = (
                datetime.utcnow()
            )

    else:

        incident.resolved_at = None

    db.session.commit()

    return incident


# ============================================================
# RESOLVE INCIDENT
# ============================================================

def resolve_incident(
    incident,
    resolution_notes=None,
):
    """
    Resolve an incident.
    """

    incident.status = "resolved"

    incident.resolved_at = (
        datetime.utcnow()
    )

    if resolution_notes is not None:

        incident.resolution_notes = (
            str(
                resolution_notes
            ).strip()
            or None
        )

    db.session.commit()

    return incident


# ============================================================
# CLOSE INCIDENT
# ============================================================

def close_incident(incident):
    """
    Close an already resolved incident.
    """

    incident.status = "closed"

    if not incident.resolved_at:
        incident.resolved_at = (
            datetime.utcnow()
        )

    db.session.commit()

    return incident


# ============================================================
# DELETE INCIDENT
# ============================================================

def delete_incident(incident):
    """
    Permanently delete an incident.
    """

    db.session.delete(incident)

    db.session.commit()


# ============================================================
# CREATE FROM DETECTION EVENT
# ============================================================

def create_incident_from_detection(
    detection_event,
    created_by=None,
):
    """
    Convert a DetectionEvent into an Incident.

    This is the main bridge between the
    Detection Engine and Incident Response.
    """

    if not detection_event:
        raise ValueError(
            "Detection event is required."
        )

    # Prevent duplicate incidents for
    # the same detection event.
    existing = Incident.query.filter_by(
        detection_event_id=detection_event.id
    ).first()

    if existing:
        return existing

    rule = detection_event.rule

    title = (
        rule.name
        if rule
        else "Security Detection Event"
    )

    data = {
        "title": title,

        "description": (
            f"Incident created from "
            f"detection event "
            f"{detection_event.event_id}."
        ),

        "category": (
            rule.category
            if rule
            else "Security"
        ),

        "severity": (
            detection_event.severity
            or (
                rule.severity
                if rule
                else "medium"
            )
        ),

        "priority": (
            detection_event.severity
            or (
                rule.severity
                if rule
                else "medium"
            )
        ),

        "source": detection_event.source,

        "affectedHost": (
            detection_event.host
        ),

        "mitreId": (
            detection_event.mitre_id
            or (
                rule.mitre_id
                if rule
                else None
            )
        ),

        "mitreName": (
            rule.mitre_name
            if rule
            else None
        ),
    }

    return create_incident(
        data,
        created_by=created_by,
        detection_event=detection_event,
    )