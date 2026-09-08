"""
CyberDefense XDR
Analytics Aggregation Services
Provides real-time SQL-based analytical aggregation, metrics evaluation,
cross-module correlation, and trend generation across all security domains.
"""

from datetime import datetime, timedelta
import logging
from sqlalchemy import desc, func, and_, or_, not_, case

from app.extensions import db
from app.assets.models import Asset
from app.alerts.models import Alert
from app.incidents.models import Incident
from app.scanner.models import VulnerabilityFinding, Scan
from app.ids.models import NetworkIDSEvent
from app.ids.services import get_security_alert_sql_filter
from app.siem.models import SiemEvent
from app.detection.models import DetectionRule, DetectionEvent
from app.threatintel.models import IOC, ThreatCampaign, ThreatActor, ThreatFeed

logger = logging.getLogger("cyberdefense.analytics")


# ============================================================================
# 1. Time Range Parsing & Validation
# ============================================================================

def parse_time_range(range_param=None, start_param=None, end_param=None):
    """
    Parses and strictly validates time range filters.
    Returns (start_dt, end_dt, effective_range_key, interval_type).
    Raises ValueError on invalid dates or bounds.
    """
    now = datetime.utcnow()
    range_key = (range_param or "7d").strip().lower()

    if start_param or end_param or range_key == "custom":
        if not start_param or not end_param:
            raise ValueError("Both start date and end date must be provided for custom ranges.")

        start_dt = _parse_date_string(start_param, is_end=False)
        end_dt = _parse_date_string(end_param, is_end=True)

        if start_dt > end_dt:
            raise ValueError("Start date cannot be after end date.")

        if (end_dt - start_dt).days > 366:
            raise ValueError("Date range cannot exceed 365 days.")

        effective_range = "custom"
        diff_seconds = (end_dt - start_dt).total_seconds()
        interval = "hour" if diff_seconds <= 86400 * 2 else "day"
        return start_dt, end_dt, effective_range, interval

    if range_key == "24h":
        start_dt = now - timedelta(hours=24)
        end_dt = now
        return start_dt, end_dt, "24h", "hour"
    elif range_key == "7d":
        start_dt = now - timedelta(days=7)
        end_dt = now
        return start_dt, end_dt, "7d", "day"
    elif range_key == "30d":
        start_dt = now - timedelta(days=30)
        end_dt = now
        return start_dt, end_dt, "30d", "day"
    elif range_key == "90d":
        start_dt = now - timedelta(days=90)
        end_dt = now
        return start_dt, end_dt, "90d", "day"
    else:
        raise ValueError(f"Invalid range preset '{range_param}'. Allowed: 24h, 7d, 30d, 90d, custom.")


def _parse_date_string(date_str, is_end=False):
    """Parses date string supporting ISO formats or YYYY-MM-DD."""
    cleaned = date_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1]

    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(cleaned, fmt)
            if fmt == "%Y-%m-%d" and is_end:
                # Set end of day
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            return dt
        except ValueError:
            continue

    raise ValueError(f"Invalid date format for '{date_str}'. Expected YYYY-MM-DD or ISO format.")


# ============================================================================
# 2. Master Analytics Dashboard Aggregator
# ============================================================================

def get_analytics_dashboard_data(range_param=None, start_param=None, end_param=None):
    """
    Main aggregator returning the comprehensive analytics payload across all domains.
    """
    start_dt, end_dt, effective_range, interval = parse_time_range(
        range_param, start_param, end_param
    )

    overview = get_analytics_overview(start_dt, end_dt)
    trends = get_trend_analytics(start_dt, end_dt, interval)
    alert_data = get_alert_analytics(start_dt, end_dt)
    incident_data = get_incident_analytics(start_dt, end_dt)
    vuln_data = get_vulnerability_analytics(start_dt, end_dt)
    ids_data = get_ids_analytics(start_dt, end_dt)
    siem_data = get_siem_analytics(start_dt, end_dt)
    detection_data = get_detection_analytics(start_dt, end_dt)
    threat_intel_data = get_threat_intel_analytics()
    asset_data = get_asset_analytics()
    correlations = get_correlation_analytics(start_dt, end_dt)

    return {
        "success": True,
        "filters": {
            "range": effective_range,
            "start": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "interval": interval,
        },
        "overview": overview,
        "trends": trends,
        "alerts": alert_data,
        "incidents": incident_data,
        "vulnerabilities": vuln_data,
        "ids": ids_data,
        "siem": siem_data,
        "detection": detection_data,
        "threat_intel": threat_intel_data,
        "assets": asset_data,
        "correlations": correlations,
    }


# ============================================================================
# 3. Overview / KPI Metrics
# ============================================================================

def get_analytics_overview(start_dt, end_dt):
    """High-level summary KPIs across all security domains."""
    # Assets (inventory is cumulative)
    total_assets = Asset.query.count()
    online_assets = Asset.query.filter_by(status="online").count()
    critical_assets = Asset.query.filter(
        or_(Asset.risk_severity == "critical", Asset.criticality == "critical")
    ).count()

    # Alerts (in evaluated time window)
    total_alerts = Alert.query.filter(
        Alert.created_at >= start_dt, Alert.created_at <= end_dt
    ).count()
    critical_alerts = Alert.query.filter(
        Alert.created_at >= start_dt,
        Alert.created_at <= end_dt,
        Alert.severity == "critical",
    ).count()
    open_alert_statuses = ["new", "acknowledged", "investigating", "escalated"]
    open_alerts = Alert.query.filter(
        Alert.created_at >= start_dt,
        Alert.created_at <= end_dt,
        Alert.status.in_(open_alert_statuses),
    ).count()

    # Incidents (in evaluated time window)
    total_incidents = Incident.query.filter(
        Incident.created_at >= start_dt, Incident.created_at <= end_dt
    ).count()
    active_inc_statuses = ["new", "assigned", "investigating", "containment", "open"]
    active_incidents = Incident.query.filter(
        Incident.created_at >= start_dt,
        Incident.created_at <= end_dt,
        Incident.status.in_(active_inc_statuses),
    ).count()

    # Vulnerability findings (in evaluated time window)
    total_vulns = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.discovered_at >= start_dt,
        VulnerabilityFinding.discovered_at <= end_dt,
    ).count()
    critical_vulns = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.discovered_at >= start_dt,
        VulnerabilityFinding.discovered_at <= end_dt,
        VulnerabilityFinding.severity == "critical",
    ).count()

    # Detection Events
    detection_events = DetectionEvent.query.filter(
        DetectionEvent.timestamp >= start_dt,
        DetectionEvent.timestamp <= end_dt,
    ).count()

    # IDS Security Alerts (excluding diagnostic checksum noise)
    sec_filter = get_security_alert_sql_filter()
    ids_security_alerts = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= start_dt,
        NetworkIDSEvent.timestamp <= end_dt,
        sec_filter,
    ).count()
    ids_total_events = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= start_dt,
        NetworkIDSEvent.timestamp <= end_dt,
    ).count()

    # SIEM Events
    siem_events = SiemEvent.query.filter(
        SiemEvent.timestamp >= start_dt,
        SiemEvent.timestamp <= end_dt,
    ).count()

    # Threat Intelligence IOCs
    total_iocs = IOC.query.count()

    return {
        "total_assets": total_assets,
        "online_assets": online_assets,
        "critical_assets": critical_assets,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "open_alerts": open_alerts,
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "total_vulnerabilities": total_vulns,
        "critical_vulnerabilities": critical_vulns,
        "detection_events": detection_events,
        "ids_security_alerts": ids_security_alerts,
        "ids_total_events": ids_total_events,
        "siem_events": siem_events,
        "total_iocs": total_iocs,
    }


# ============================================================================
# 4. Security Alert Analytics
# ============================================================================

def get_alert_analytics(start_dt, end_dt):
    """Detailed analytics on Alert Center records."""
    base_q = Alert.query.filter(Alert.created_at >= start_dt, Alert.created_at <= end_dt)

    total_alerts = base_q.count()

    # Severity distribution
    sev_rows = (
        db.session.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.created_at >= start_dt, Alert.created_at <= end_dt)
        .group_by(Alert.severity)
        .all()
    )
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev, count in sev_rows:
        s = (sev or "low").lower()
        if s in severity_dist:
            severity_dist[s] = count
        else:
            severity_dist[s] = count

    # Status distribution
    status_rows = (
        db.session.query(Alert.status, func.count(Alert.id))
        .filter(Alert.created_at >= start_dt, Alert.created_at <= end_dt)
        .group_by(Alert.status)
        .all()
    )
    status_dist = {status: count for status, count in status_rows if status}

    # Category distribution
    cat_rows = (
        db.session.query(Alert.category, func.count(Alert.id))
        .filter(Alert.created_at >= start_dt, Alert.created_at <= end_dt)
        .group_by(Alert.category)
        .order_by(desc(func.count(Alert.id)))
        .limit(8)
        .all()
    )
    category_dist = [
        {"category": cat or "General", "count": count} for cat, count in cat_rows
    ]

    # Source distribution
    src_rows = (
        db.session.query(Alert.source, func.count(Alert.id))
        .filter(Alert.created_at >= start_dt, Alert.created_at <= end_dt)
        .group_by(Alert.source)
        .order_by(desc(func.count(Alert.id)))
        .limit(8)
        .all()
    )
    source_dist = [{"source": src or "Unknown", "count": count} for src, count in src_rows]

    # Top affected assets/hosts
    host_rows = (
        db.session.query(
            func.coalesce(Alert.affected_host, Alert.affected_asset, "Unknown Host"),
            func.count(Alert.id),
        )
        .filter(Alert.created_at >= start_dt, Alert.created_at <= end_dt)
        .group_by(func.coalesce(Alert.affected_host, Alert.affected_asset, "Unknown Host"))
        .order_by(desc(func.count(Alert.id)))
        .limit(8)
        .all()
    )
    top_affected_hosts = [{"host": h, "count": cnt} for h, cnt in host_rows if h]

    return {
        "total": total_alerts,
        "by_severity": severity_dist,
        "by_status": status_dist,
        "top_categories": category_dist,
        "top_sources": source_dist,
        "top_affected_hosts": top_affected_hosts,
    }


# ============================================================================
# 5. Incident Analytics & MTTR
# ============================================================================

def get_incident_analytics(start_dt, end_dt):
    """Detailed analytics on Incident Response lifecycles and MTTR."""
    base_q = Incident.query.filter(
        Incident.created_at >= start_dt, Incident.created_at <= end_dt
    )

    total_incidents = base_q.count()

    # Severity distribution
    sev_rows = (
        db.session.query(Incident.severity, func.count(Incident.id))
        .filter(Incident.created_at >= start_dt, Incident.created_at <= end_dt)
        .group_by(Incident.severity)
        .all()
    )
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev, count in sev_rows:
        s = (sev or "low").lower()
        if s in severity_dist:
            severity_dist[s] = count
        else:
            severity_dist[s] = count

    # Status distribution
    status_rows = (
        db.session.query(Incident.status, func.count(Incident.id))
        .filter(Incident.created_at >= start_dt, Incident.created_at <= end_dt)
        .group_by(Incident.status)
        .all()
    )
    status_dist = {status: count for status, count in status_rows if status}

    active_statuses = ["new", "assigned", "investigating", "containment", "open"]
    active_count = sum(cnt for status, cnt in status_dist.items() if status.lower() in active_statuses)
    resolved_count = sum(cnt for status, cnt in status_dist.items() if status.lower() in ["resolved", "closed"])

    # Mean Time to Resolution (MTTR) calculation
    # Only calculate for incidents that have both resolved_at and created_at
    resolved_incidents = (
        Incident.query.filter(
            Incident.created_at >= start_dt,
            Incident.created_at <= end_dt,
            Incident.resolved_at.isnot(None),
        )
        .all()
    )

    mttr_hours = None
    if resolved_incidents:
        durations = [
            (inc.resolved_at - inc.created_at).total_seconds() / 3600.0
            for inc in resolved_incidents
            if inc.resolved_at >= inc.created_at
        ]
        if durations:
            mttr_hours = round(sum(durations) / len(durations), 1)

    # Top categories
    cat_rows = (
        db.session.query(Incident.category, func.count(Incident.id))
        .filter(Incident.created_at >= start_dt, Incident.created_at <= end_dt)
        .group_by(Incident.category)
        .order_by(desc(func.count(Incident.id)))
        .limit(8)
        .all()
    )
    top_categories = [{"category": cat, "count": count} for cat, count in cat_rows if cat]

    return {
        "total": total_incidents,
        "active": active_count,
        "resolved": resolved_count,
        "mttr_hours": mttr_hours,
        "by_severity": severity_dist,
        "by_status": status_dist,
        "top_categories": top_categories,
    }


# ============================================================================
# 6. Vulnerability Analytics
# ============================================================================

def get_vulnerability_analytics(start_dt, end_dt):
    """Detailed analytics on Vulnerability Scanner findings."""
    base_q = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.discovered_at >= start_dt,
        VulnerabilityFinding.discovered_at <= end_dt,
    )

    total_findings = base_q.count()

    # Severity distribution
    sev_rows = (
        db.session.query(VulnerabilityFinding.severity, func.count(VulnerabilityFinding.id))
        .filter(
            VulnerabilityFinding.discovered_at >= start_dt,
            VulnerabilityFinding.discovered_at <= end_dt,
        )
        .group_by(VulnerabilityFinding.severity)
        .all()
    )
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev, count in sev_rows:
        s = (sev or "low").lower()
        if s in severity_dist:
            severity_dist[s] = count
        else:
            severity_dist[s] = count

    # Status breakdown
    status_rows = (
        db.session.query(VulnerabilityFinding.status, func.count(VulnerabilityFinding.id))
        .filter(
            VulnerabilityFinding.discovered_at >= start_dt,
            VulnerabilityFinding.discovered_at <= end_dt,
        )
        .group_by(VulnerabilityFinding.status)
        .all()
    )
    status_dist = {st: cnt for st, cnt in status_rows if st}

    # CVSS Score distribution tiers (0-3.9 Low, 4.0-6.9 Med, 7.0-8.9 High, 9.0-10.0 Crit)
    cvss_rows = (
        db.session.query(
            case(
                (VulnerabilityFinding.cvss_score >= 9.0, "Critical (9.0-10.0)"),
                (VulnerabilityFinding.cvss_score >= 7.0, "High (7.0-8.9)"),
                (VulnerabilityFinding.cvss_score >= 4.0, "Medium (4.0-6.9)"),
                else_="Low (0.0-3.9)",
            ).label("tier"),
            func.count(VulnerabilityFinding.id),
        )
        .filter(
            VulnerabilityFinding.discovered_at >= start_dt,
            VulnerabilityFinding.discovered_at <= end_dt,
        )
        .group_by("tier")
        .all()
    )
    cvss_dist = {tier: cnt for tier, cnt in cvss_rows}

    # Scanner Tool distribution
    tool_rows = (
        db.session.query(VulnerabilityFinding.tool, func.count(VulnerabilityFinding.id))
        .filter(
            VulnerabilityFinding.discovered_at >= start_dt,
            VulnerabilityFinding.discovered_at <= end_dt,
        )
        .group_by(VulnerabilityFinding.tool)
        .order_by(desc(func.count(VulnerabilityFinding.id)))
        .all()
    )
    tool_dist = [{"tool": t, "count": cnt} for t, cnt in tool_rows if t]

    # Top CVEs (non-empty)
    cve_rows = (
        db.session.query(VulnerabilityFinding.cve, func.count(VulnerabilityFinding.id))
        .filter(
            VulnerabilityFinding.discovered_at >= start_dt,
            VulnerabilityFinding.discovered_at <= end_dt,
            VulnerabilityFinding.cve != "",
            VulnerabilityFinding.cve.isnot(None),
        )
        .group_by(VulnerabilityFinding.cve)
        .order_by(desc(func.count(VulnerabilityFinding.id)))
        .limit(8)
        .all()
    )
    top_cves = [{"cve": cve, "cve_id": cve, "count": cnt} for cve, cnt in cve_rows]

    # Top vulnerable hosts
    host_rows = (
        db.session.query(VulnerabilityFinding.host, func.count(VulnerabilityFinding.id))
        .filter(
            VulnerabilityFinding.discovered_at >= start_dt,
            VulnerabilityFinding.discovered_at <= end_dt,
        )
        .group_by(VulnerabilityFinding.host)
        .order_by(desc(func.count(VulnerabilityFinding.id)))
        .limit(8)
        .all()
    )
    top_hosts = [{"host": h, "count": cnt} for h, cnt in host_rows if h]

    return {
        "total": total_findings,
        "by_severity": severity_dist,
        "by_status": status_dist,
        "cvss_distribution": cvss_dist,
        "tool_distribution": tool_dist,
        "top_cves": top_cves,
        "top_vulnerable_hosts": top_hosts,
    }


# ============================================================================
# 7. Network IDS Analytics (with Strict Diagnostic Isolation)
# ============================================================================

def get_ids_analytics(start_dt, end_dt):
    """Detailed analytics on Network IDS events, separating security alerts from diagnostic noise."""
    sec_filter = get_security_alert_sql_filter()

    total_events = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= start_dt, NetworkIDSEvent.timestamp <= end_dt
    ).count()

    security_alerts_count = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= start_dt,
        NetworkIDSEvent.timestamp <= end_dt,
        sec_filter,
    ).count()

    diagnostic_events_count = total_events - security_alerts_count

    # Security alerts severity breakdown
    sev_rows = (
        db.session.query(NetworkIDSEvent.severity, func.count(NetworkIDSEvent.id))
        .filter(
            NetworkIDSEvent.timestamp >= start_dt,
            NetworkIDSEvent.timestamp <= end_dt,
            sec_filter,
        )
        .group_by(NetworkIDSEvent.severity)
        .all()
    )
    severity_dist = {s: cnt for s, cnt in sev_rows if s}

    # Top security signatures (excluding diagnostic noise)
    sig_rows = (
        db.session.query(NetworkIDSEvent.signature, func.count(NetworkIDSEvent.id))
        .filter(
            NetworkIDSEvent.timestamp >= start_dt,
            NetworkIDSEvent.timestamp <= end_dt,
            sec_filter,
        )
        .group_by(NetworkIDSEvent.signature)
        .order_by(desc(func.count(NetworkIDSEvent.id)))
        .limit(8)
        .all()
    )
    top_signatures = [{"signature": sig, "count": cnt} for sig, cnt in sig_rows if sig]

    # Protocol breakdown
    proto_rows = (
        db.session.query(NetworkIDSEvent.protocol, func.count(NetworkIDSEvent.id))
        .filter(NetworkIDSEvent.timestamp >= start_dt, NetworkIDSEvent.timestamp <= end_dt)
        .group_by(NetworkIDSEvent.protocol)
        .order_by(desc(func.count(NetworkIDSEvent.id)))
        .all()
    )
    protocol_dist = [{"protocol": p or "Other", "count": cnt} for p, cnt in proto_rows]

    return {
        "total_events": total_events,
        "security_alerts": security_alerts_count,
        "diagnostic_events": diagnostic_events_count,
        "by_severity": severity_dist,
        "top_signatures": top_signatures,
        "protocol_distribution": protocol_dist,
    }


# ============================================================================
# 8. SIEM Analytics
# ============================================================================

def get_siem_analytics(start_dt, end_dt):
    """Detailed analytics on SIEM log ingestion."""
    base_q = SiemEvent.query.filter(
        SiemEvent.timestamp >= start_dt, SiemEvent.timestamp <= end_dt
    )

    total_events = base_q.count()

    # Severity distribution
    sev_rows = (
        db.session.query(SiemEvent.severity, func.count(SiemEvent.id))
        .filter(SiemEvent.timestamp >= start_dt, SiemEvent.timestamp <= end_dt)
        .group_by(SiemEvent.severity)
        .all()
    )
    severity_dist = {s: cnt for s, cnt in sev_rows if s}

    # Top log sources
    src_rows = (
        db.session.query(SiemEvent.source, func.count(SiemEvent.id))
        .filter(SiemEvent.timestamp >= start_dt, SiemEvent.timestamp <= end_dt)
        .group_by(SiemEvent.source)
        .order_by(desc(func.count(SiemEvent.id)))
        .limit(8)
        .all()
    )
    top_sources = [{"source": src, "count": cnt} for src, cnt in src_rows if src]

    # Top categories
    cat_rows = (
        db.session.query(SiemEvent.category, func.count(SiemEvent.id))
        .filter(SiemEvent.timestamp >= start_dt, SiemEvent.timestamp <= end_dt)
        .group_by(SiemEvent.category)
        .order_by(desc(func.count(SiemEvent.id)))
        .limit(8)
        .all()
    )
    top_categories = [{"category": cat, "count": cnt} for cat, cnt in cat_rows if cat]

    return {
        "total": total_events,
        "total_events": total_events,
        "by_severity": severity_dist,
        "by_source": top_sources,
        "top_sources": top_sources,
        "top_categories": top_categories,
    }


# ============================================================================
# 9. Detection Engine Analytics
# ============================================================================

def get_detection_analytics(start_dt, end_dt):
    """Detailed analytics on Detection Engine rules and triggered events."""
    base_q = DetectionEvent.query.filter(
        DetectionEvent.timestamp >= start_dt, DetectionEvent.timestamp <= end_dt
    )

    total_events = base_q.count()

    # Severity distribution
    sev_rows = (
        db.session.query(DetectionEvent.severity, func.count(DetectionEvent.id))
        .filter(DetectionEvent.timestamp >= start_dt, DetectionEvent.timestamp <= end_dt)
        .group_by(DetectionEvent.severity)
        .all()
    )
    severity_dist = {s: cnt for s, cnt in sev_rows if s}

    # Top firing rules (joining DetectionRule)
    rule_rows = (
        db.session.query(
            DetectionRule.rule_id,
            DetectionRule.name,
            func.count(DetectionEvent.id).label("cnt"),
        )
        .join(DetectionRule, DetectionEvent.rule_id == DetectionRule.id)
        .filter(DetectionEvent.timestamp >= start_dt, DetectionEvent.timestamp <= end_dt)
        .group_by(DetectionRule.rule_id, DetectionRule.name)
        .order_by(desc("cnt"))
        .limit(8)
        .all()
    )
    top_rules = [
        {"rule_id": r_id, "name": r_name, "triggers": cnt}
        for r_id, r_name, cnt in rule_rows
    ]

    active_rules_count = DetectionRule.query.filter_by(status="active").count()

    return {
        "total": total_events,
        "total_events": total_events,
        "active_rules_count": active_rules_count,
        "by_severity": severity_dist,
        "top_rules": top_rules,
    }


# ============================================================================
# 10. Threat Intelligence Analytics
# ============================================================================

def get_threat_intel_analytics():
    """Detailed analytics on Threat Intelligence database records."""
    total_iocs = IOC.query.count()

    # IOC by type
    type_rows = (
        db.session.query(IOC.type, func.count(IOC.id))
        .group_by(IOC.type)
        .order_by(desc(func.count(IOC.id)))
        .all()
    )
    by_type_list = [{"type": t, "count": cnt} for t, cnt in type_rows if t]
    by_type_map = {t: cnt for t, cnt in type_rows if t}

    # IOC by threat level
    level_rows = (
        db.session.query(IOC.threat_level, func.count(IOC.id))
        .group_by(IOC.threat_level)
        .all()
    )
    by_level_list = [{"severity": lvl, "count": cnt} for lvl, cnt in level_rows if lvl]
    by_level_map = {lvl: cnt for lvl, cnt in level_rows if lvl}

    # IOC by confidence
    conf_rows = (
        db.session.query(IOC.confidence, func.count(IOC.id))
        .group_by(IOC.confidence)
        .all()
    )
    by_confidence = {c: cnt for c, cnt in conf_rows if c}

    campaigns_count = ThreatCampaign.query.count()
    feeds_count = ThreatFeed.query.count()
    actors_count = ThreatActor.query.count()

    return {
        "total": total_iocs,
        "total_iocs": total_iocs,
        "by_type": by_type_list,
        "by_type_map": by_type_map,
        "by_threat_level": by_level_map,
        "by_severity": by_level_list,
        "by_confidence": by_confidence,
        "threat_actors": actors_count,
        "threat_actors_count": actors_count,
        "active_campaigns": campaigns_count,
        "campaigns_count": campaigns_count,
        "active_feeds": feeds_count,
        "feeds_count": feeds_count,
    }


# ============================================================================
# 11. Asset Analytics & Top Risk Ranking
# ============================================================================

def get_asset_analytics():
    """Detailed inventory analytics and top risk assets ranking."""
    total_assets = Asset.query.count()

    # By environment
    env_rows = (
        db.session.query(Asset.environment, func.count(Asset.id))
        .group_by(Asset.environment)
        .all()
    )
    by_environment_list = [{"environment": e or "Unassigned", "count": cnt} for e, cnt in env_rows if e]
    by_environment_map = {e: cnt for e, cnt in env_rows if e}

    # By asset type
    type_rows = (
        db.session.query(Asset.asset_type, func.count(Asset.id))
        .group_by(Asset.asset_type)
        .order_by(desc(func.count(Asset.id)))
        .all()
    )
    by_type = {t: cnt for t, cnt in type_rows if t}

    # By criticality
    crit_rows = (
        db.session.query(Asset.criticality, func.count(Asset.id))
        .group_by(Asset.criticality)
        .all()
    )
    by_criticality_list = [{"criticality": c, "count": cnt} for c, cnt in crit_rows if c]
    by_criticality_map = {c: cnt for c, cnt in crit_rows if c}

    # By status
    status_rows = (
        db.session.query(Asset.status, func.count(Asset.id))
        .group_by(Asset.status)
        .all()
    )
    by_status = {s: cnt for s, cnt in status_rows if s}

    # Risk tiers (<35, 35-59, 60-79, >=80)
    crit_count = Asset.query.filter(Asset.risk_score >= 80).count()
    high_count = Asset.query.filter(Asset.risk_score >= 60, Asset.risk_score < 80).count()
    med_count = Asset.query.filter(Asset.risk_score >= 35, Asset.risk_score < 60).count()
    low_count = Asset.query.filter(Asset.risk_score < 35).count()
    risk_distribution = {
        "critical": crit_count,
        "high": high_count,
        "medium": med_count,
        "low": low_count,
        "Critical (80-100)": crit_count,
        "High (60-79)": high_count,
        "Medium (35-59)": med_count,
        "Low (0-34)": low_count,
    }

    # Top risk assets list
    top_assets_records = (
        Asset.query.order_by(desc(Asset.risk_score), desc(Asset.open_vulnerabilities_count))
        .limit(10)
        .all()
    )
    top_risk_assets = [
        {
            "asset_id": a.asset_id,
            "name": a.name,
            "ip_address": a.ip_address or "-",
            "asset_type": a.asset_type,
            "environment": a.environment,
            "criticality": a.criticality,
            "status": a.status,
            "risk_score": a.risk_score,
            "risk_severity": a.risk_severity,
            "open_vulnerabilities_count": a.open_vulnerabilities_count,
            "open_alerts_count": a.open_alerts_count,
        }
        for a in top_assets_records
    ]

    return {
        "total": total_assets,
        "total_assets": total_assets,
        "online": by_status.get("online", 0),
        "offline": by_status.get("offline", 0),
        "by_environment": by_environment_list,
        "by_environment_map": by_environment_map,
        "by_type": by_type,
        "by_criticality": by_criticality_list,
        "by_criticality_map": by_criticality_map,
        "by_status": by_status,
        "risk_distribution": risk_distribution,
        "risk_score_tiers": risk_distribution,
        "top_risk_assets": top_risk_assets,
    }


# ============================================================================
# 12. Security Trend Analytics (Time-Series Buckets)
# ============================================================================

def get_trend_analytics(start_dt, end_dt, interval="day"):
    """
    Generates multi-series chronological telemetry trends across domains.
    Builds aligned intervals (hourly or daily) with zero-filling for absent buckets.
    """
    labels = []
    bucket_map = {}

    if interval == "hour":
        current = start_dt.replace(minute=0, second=0, microsecond=0)
        step = timedelta(hours=1)
        fmt = "%H:00"
    else:
        current = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        step = timedelta(days=1)
        fmt = "%b %d"

    while current <= end_dt:
        key = current.strftime(fmt)
        labels.append(key)
        bucket_map[key] = current
        current += step

    def _bucket_query(model, date_col, extra_filter=None):
        series = [0] * len(labels)
        q = db.session.query(date_col).filter(date_col >= start_dt, date_col <= end_dt)
        if extra_filter is not None:
            q = q.filter(extra_filter)

        dates = q.all()
        counts = {}
        for (d,) in dates:
            if d:
                k = d.strftime(fmt)
                counts[k] = counts.get(k, 0) + 1

        for i, lbl in enumerate(labels):
            series[i] = counts.get(lbl, 0)
        return series

    sec_filter = get_security_alert_sql_filter()

    alerts_series = _bucket_query(Alert, Alert.created_at)
    ids_series = _bucket_query(NetworkIDSEvent, NetworkIDSEvent.timestamp, sec_filter)
    siem_series = _bucket_query(SiemEvent, SiemEvent.timestamp)
    detections_series = _bucket_query(DetectionEvent, DetectionEvent.timestamp)
    incidents_series = _bucket_query(Incident, Incident.created_at)
    vulns_series = _bucket_query(VulnerabilityFinding, VulnerabilityFinding.discovered_at)

    return {
        "labels": labels,
        "alerts": alerts_series,
        "ids_alerts": ids_series,
        "siem_events": siem_series,
        "detections": detections_series,
        "incidents": incidents_series,
        "vulnerabilities": vulns_series,
    }


# ============================================================================
# 13. Cross-Module Correlations
# ============================================================================

def get_correlation_analytics(start_dt, end_dt):
    """
    Computes cross-module security relationships and correlations.
    """
    # 1. Assets with BOTH active alerts and open vulnerabilities
    dual_risk_assets = (
        Asset.query.filter(
            Asset.open_alerts_count > 0,
            Asset.open_vulnerabilities_count > 0,
        )
        .order_by(desc(Asset.risk_score))
        .limit(6)
        .all()
    )
    dual_risk_data = [
        {
            "asset_id": a.asset_id,
            "name": a.name,
            "ip": a.ip_address or "-",
            "risk_score": a.risk_score,
            "alerts_count": a.open_alerts_count,
            "vulns_count": a.open_vulnerabilities_count,
        }
        for a in dual_risk_assets
    ]

    # 2. Criticality vs Alert Severity Matrix
    matrix_rows = (
        db.session.query(
            Asset.criticality,
            Alert.severity,
            func.count(Alert.id),
        )
        .join(
            Alert,
            or_(
                Alert.affected_host == Asset.ip_address,
                Alert.affected_host == Asset.name,
                Alert.affected_asset == Asset.name,
                Alert.affected_asset == Asset.asset_id,
            ),
        )
        .filter(Alert.created_at >= start_dt, Alert.created_at <= end_dt)
        .group_by(Asset.criticality, Alert.severity)
        .all()
    )
    criticality_severity_matrix = [
        {"asset_criticality": crit, "alert_severity": sev, "count": cnt}
        for crit, sev, cnt in matrix_rows
    ]

    # 3. Incidents originating from Detection Events
    incident_detection_count = (
        Incident.query.filter(
            Incident.created_at >= start_dt,
            Incident.created_at <= end_dt,
            Incident.detection_event_id.isnot(None),
        ).count()
    )

    # 4. Detection events correlated with SIEM Events
    detection_siem_count = (
        SiemEvent.query.filter(
            SiemEvent.timestamp >= start_dt,
            SiemEvent.timestamp <= end_dt,
            SiemEvent.detection_event_id.isnot(None),
        ).count()
    )

    return {
        "dual_risk_assets": dual_risk_data,
        "dual_risk_count": len(dual_risk_assets),
        "criticality_severity_matrix": criticality_severity_matrix,
        "incidents_from_detections": incident_detection_count,
        "siem_correlated_detections": detection_siem_count,
    }
