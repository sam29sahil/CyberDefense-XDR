"""
CyberDefense XDR
Audit Logs Service Layer
Provides centralized event recording, complex multi-parameter querying,
real-time database-backed analytics, and CSV export generation.
"""

import csv
import io
import logging
from datetime import datetime, time
from typing import Any, Dict, List, Optional, Union

from flask import has_request_context, request
from flask_login import current_user

from app.extensions import db
from app.audit_logs.models import AuditLog
from app.audit_logs.utils import (
    generate_audit_id,
    sanitize_audit_details,
    get_client_ip,
    get_user_agent,
    sanitize_csv_cell,
)

logger = logging.getLogger(__name__)


def record_audit_event(
    action: str,
    category: str,
    message: Optional[str] = None,
    actor: Optional[str] = None,
    actor_id: Optional[int] = None,
    actor_role: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    result: str = "SUCCESS",
    severity: str = "info",
    details: Optional[Dict[str, Any]] = None,
    source_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_obj: Optional[Any] = None,
    sync_to_siem: bool = True,
) -> AuditLog:
    """
    Primary API to record an immutable administrative or security audit event.
    Automatically enriches actor, IP, and user-agent from request context if omitted.
    Sanitizes credentials/tokens before persistence.
    """
    # 1. Resolve Actor
    resolved_actor = actor
    resolved_actor_id = actor_id

    if not resolved_actor and has_request_context():
        if current_user and getattr(current_user, "is_authenticated", False):
            resolved_actor = getattr(current_user, "username", "Authenticated User")
            if not resolved_actor_id:
                resolved_actor_id = getattr(current_user, "id", None)
            if not actor_role:
                actor_role = getattr(current_user, "role", None)
        else:
            resolved_actor = "Anonymous/System"

    if not resolved_actor:
        resolved_actor = "System"

    # 2. Resolve Client IP & User Agent
    resolved_ip = source_ip or get_client_ip(request_obj)
    resolved_ua = user_agent or get_user_agent(request_obj)

    # 3. Sanitize details
    clean_details = sanitize_audit_details(details or {})
    if actor_role and "actor_role" not in clean_details:
        clean_details["actor_role"] = actor_role

    # 4. Normalize Result & Severity
    norm_result = (result or "SUCCESS").strip().upper()
    norm_severity = (severity or "info").strip().lower()
    if norm_severity not in ("info", "low", "medium", "high", "critical"):
        norm_severity = "info"

    if not message:
        message = f"{action} on {resource_type or 'system'}" + (f" #{resource_id}" if resource_id else "") + f" - {norm_result}"

    audit_entry = AuditLog(
        audit_id=generate_audit_id(),
        timestamp=datetime.utcnow(),
        actor=str(resolved_actor)[:120],
        actor_id=resolved_actor_id,
        action=str(action).strip()[:100],
        category=str(category).strip()[:60],
        resource_type=str(resource_type).strip()[:60] if resource_type else None,
        resource_id=str(resource_id).strip()[:100] if resource_id else None,
        result=norm_result[:20],
        severity=norm_severity[:20],
        source_ip=str(resolved_ip)[:64] if resolved_ip else None,
        user_agent=str(resolved_ua)[:255] if resolved_ua else None,
        message=str(message).strip(),
    )
    audit_entry.details = clean_details

    try:
        db.session.add(audit_entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to persist AuditLog: {exc}", exc_info=True)
        raise exc

    # 5. Optional SIEM dispatch for unified telemetry
    if sync_to_siem:
        try:
            from app.siem.services import ingest_event
            ingest_event({
                "source": "Audit System",
                "severity": norm_severity,
                "category": f"Audit: {category}",
                "host": resolved_ip or "localhost",
                "message": f"[AUDIT] [{action}] ({norm_result}) {message}",
                "fields": {
                    "audit_id": audit_entry.audit_id,
                    "actor": resolved_actor,
                    "action": action,
                    "category": category,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "result": norm_result,
                },
            })
        except Exception as e:
            logger.debug(f"SIEM audit dispatch omitted/failed: {e}")

    return audit_entry


def list_audit_logs(
    page: int = 1,
    per_page: int = 20,
    filters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Retrieves a paginated list of audit records matching the specified filters.
    Enforces maximum page bounds to prevent denial of service.
    """
    safe_per_page = min(max(1, per_page), 100)
    safe_page = max(1, page)
    filters = filters or {}

    query = AuditLog.query

    # 1. Search Query across multiple fields
    search = filters.get("search")
    if search:
        sq = f"%{str(search).strip().lower()}%"
        query = query.filter(
            db.or_(
                db.func.lower(AuditLog.message).like(sq),
                db.func.lower(AuditLog.action).like(sq),
                db.func.lower(AuditLog.actor).like(sq),
                db.func.lower(AuditLog.resource_id).like(sq),
                db.func.lower(AuditLog.source_ip).like(sq),
                db.func.lower(AuditLog.audit_id).like(sq),
            )
        )

    # 2. Specific field filters
    if filters.get("actor"):
        act = str(filters["actor"]).strip().lower()
        query = query.filter(db.func.lower(AuditLog.actor) == act)

    if filters.get("action"):
        actn = str(filters["action"]).strip().lower()
        query = query.filter(db.func.lower(AuditLog.action) == actn)

    if filters.get("category") and filters["category"].upper() != "ALL":
        cat = str(filters["category"]).strip().lower()
        query = query.filter(db.func.lower(AuditLog.category) == cat)

    if filters.get("resource_type") and filters["resource_type"].upper() != "ALL":
        rt = str(filters["resource_type"]).strip().lower()
        query = query.filter(db.func.lower(AuditLog.resource_type) == rt)

    if filters.get("resource_id"):
        rid = str(filters["resource_id"]).strip().lower()
        query = query.filter(db.func.lower(AuditLog.resource_id) == rid)

    if filters.get("result") and filters["result"].upper() != "ALL":
        res = str(filters["result"]).strip().upper()
        query = query.filter(AuditLog.result == res)

    if filters.get("severity") and filters["severity"].upper() != "ALL":
        sev = str(filters["severity"]).strip().lower()
        query = query.filter(AuditLog.severity == sev)

    if filters.get("source_ip"):
        sip = str(filters["source_ip"]).strip().lower()
        query = query.filter(db.func.lower(AuditLog.source_ip) == sip)

    # 3. Date / Time range filters
    if filters.get("start_time"):
        try:
            st = _parse_datetime(filters["start_time"])
            if st:
                query = query.filter(AuditLog.timestamp >= st)
        except Exception:
            pass

    if filters.get("end_time"):
        try:
            et = _parse_datetime(filters["end_time"])
            if et:
                query = query.filter(AuditLog.timestamp <= et)
        except Exception:
            pass

    # Order newest first
    query = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())

    total_count = query.count()
    total_pages = (total_count + safe_per_page - 1) // safe_per_page if safe_per_page > 0 else 1

    records = query.offset((safe_page - 1) * safe_per_page).limit(safe_per_page).all()

    return {
        "items": [r.to_dict() for r in records],
        "total": total_count,
        "page": safe_page,
        "per_page": safe_per_page,
        "pages": total_pages,
    }


def get_audit_log_by_id(audit_identifier: Union[str, int]) -> Optional[Dict[str, Any]]:
    """Fetches a single audit log record by string audit_id or integer id."""
    if not audit_identifier:
        return None

    query = AuditLog.query
    if isinstance(audit_identifier, int) or (isinstance(audit_identifier, str) and audit_identifier.isdigit()):
        record = query.filter(db.or_(AuditLog.id == int(audit_identifier), AuditLog.audit_id == str(audit_identifier))).first()
    else:
        record = query.filter_by(audit_id=str(audit_identifier).strip()).first()

    return record.to_dict() if record else None


def get_audit_statistics() -> Dict[str, Any]:
    """
    Computes real database-backed metrics across all audit logs.
    Returns 0/empty counts when database is fresh.
    """
    now = datetime.utcnow()
    midnight_today = datetime.combine(now.date(), time.min)

    # 1. Scalar Counts
    total_events = db.session.query(db.func.count(AuditLog.id)).scalar() or 0
    events_today = db.session.query(db.func.count(AuditLog.id)).filter(AuditLog.timestamp >= midnight_today).scalar() or 0
    auth_failures = db.session.query(db.func.count(AuditLog.id)).filter(
        AuditLog.category == "Authentication",
        AuditLog.result == "FAILURE",
    ).scalar() or 0
    auth_denials = db.session.query(db.func.count(AuditLog.id)).filter(
        db.or_(
            AuditLog.category == "Authorization",
            AuditLog.result == "DENIED",
        )
    ).scalar() or 0
    admin_actions = db.session.query(db.func.count(AuditLog.id)).filter(
        AuditLog.category.in_(["User Management", "Settings", "Detection Engine", "Network IDS"])
    ).scalar() or 0
    soar_actions = db.session.query(db.func.count(AuditLog.id)).filter(
        AuditLog.category == "SOAR"
    ).scalar() or 0
    critical_events = db.session.query(db.func.count(AuditLog.id)).filter(
        AuditLog.severity == "critical"
    ).scalar() or 0

    # 2. Aggregations by Category
    category_rows = db.session.query(
        AuditLog.category,
        db.func.count(AuditLog.id)
    ).group_by(AuditLog.category).all()
    by_category = {cat: count for cat, count in category_rows}

    # 3. Aggregations by Result
    result_rows = db.session.query(
        AuditLog.result,
        db.func.count(AuditLog.id)
    ).group_by(AuditLog.result).all()
    by_result = {res: count for res, count in result_rows}

    # 4. Aggregations by Severity
    severity_rows = db.session.query(
        AuditLog.severity,
        db.func.count(AuditLog.id)
    ).group_by(AuditLog.severity).all()
    by_severity = {sev: count for sev, count in severity_rows}

    return {
        "total_events": total_events,
        "events_today": events_today,
        "authentication_failures": auth_failures,
        "authorization_denials": auth_denials,
        "admin_actions": admin_actions,
        "soar_actions": soar_actions,
        "critical_audit_events": critical_events,
        "events_by_category": by_category,
        "events_by_result": by_result,
        "events_by_severity": by_severity,
        "by_category": by_category,
        "by_result": by_result,
        "by_severity": by_severity,
    }


def export_audit_logs_csv(filters: Optional[Dict[str, Any]] = None, max_rows: int = 5000) -> str:
    """
    Generates RFC 4180 compliant CSV stream with formula injection mitigation.
    """
    res = list_audit_logs(page=1, per_page=max_rows, filters=filters)
    logs = res.get("items", [])

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header Row
    writer.writerow([
        "Audit ID",
        "Timestamp (UTC)",
        "Actor",
        "Category",
        "Action",
        "Resource Type",
        "Resource ID",
        "Result",
        "Severity",
        "Source IP",
        "User Agent",
        "Message",
    ])

    for log in logs:
        writer.writerow([
            sanitize_csv_cell(log.get("audit_id")),
            sanitize_csv_cell(log.get("timestamp")),
            sanitize_csv_cell(log.get("actor")),
            sanitize_csv_cell(log.get("category")),
            sanitize_csv_cell(log.get("action")),
            sanitize_csv_cell(log.get("resource_type")),
            sanitize_csv_cell(log.get("resource_id")),
            sanitize_csv_cell(log.get("result")),
            sanitize_csv_cell(log.get("severity")),
            sanitize_csv_cell(log.get("source_ip")),
            sanitize_csv_cell(log.get("user_agent")),
            sanitize_csv_cell(log.get("message")),
        ])

    return output.getvalue()


def _parse_datetime(val: Any) -> Optional[datetime]:
    """Helper to parse varied ISO / datetime strings."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    val_str = str(val).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(val_str, fmt)
        except ValueError:
            continue
    return None
