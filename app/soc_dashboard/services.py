"""
CyberDefense XDR
SOC Dashboard Aggregation Services
Queries real database records across Assets, Alerts, Incidents,
Vulnerabilities, Network IDS, SIEM, Detection, and Threat Intelligence.
"""

from datetime import datetime, timedelta
import logging
from sqlalchemy import desc, func, and_, or_, not_

from app.extensions import db
from app.assets.models import Asset
from app.alerts.models import Alert
from app.incidents.models import Incident
from app.scanner.models import VulnerabilityFinding, Scan
from app.ids.models import NetworkIDSEvent
from app.ids.services import get_security_alert_sql_filter, get_sensor_status
from app.siem.models import SiemEvent
from app.detection.models import DetectionRule, DetectionEvent
from app.threatintel.models import IOC, ThreatCampaign, ThreatActor, ThreatFeed

logger = logging.getLogger("cyberdefense.soc_dashboard")


def get_soc_dashboard_data():
    """
    Main aggregator for the SOC Dashboard.
    Returns complete real telemetry payload across all completed security modules.
    """
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_24h = now - timedelta(hours=24)

    # 1. High-level Summary / KPIs
    summary = _build_summary(today_start)

    # 2. Alert Overview
    alert_overview = _build_alert_overview(last_24h)

    # 3. Incident Overview
    incident_overview = _build_incident_overview()

    # 4. Asset Risk Overview
    asset_overview = _build_asset_risk_overview()

    # 5. Vulnerability Overview
    vuln_overview = _build_vulnerability_overview()

    # 6. Network IDS Overview
    ids_overview = _build_ids_overview(today_start)

    # 7. SIEM Overview
    siem_overview = _build_siem_overview(today_start, last_24h)

    # 8. Detection Engine Overview
    detection_overview = _build_detection_overview(today_start)

    # 9. Threat Intelligence Overview
    threat_intel_overview = _build_threat_intel_overview()

    # 10. Unified Activity Feed (Newest first)
    activity_feed = _build_activity_feed(limit=15)

    # 11. Security Event Trend Timeline (Last 24h)
    trend_timeline = _build_trend_timeline(now)

    return {
        "success": True,
        "generatedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": summary,
        "alertOverview": alert_overview,
        "incidentOverview": incident_overview,
        "assetRiskOverview": asset_overview,
        "vulnerabilityOverview": vuln_overview,
        "idsOverview": ids_overview,
        "siemOverview": siem_overview,
        "detectionOverview": detection_overview,
        "threatIntelOverview": threat_intel_overview,
        "activityFeed": activity_feed,
        "trendTimeline": trend_timeline,
    }


def _build_summary(today_start):
    """Calculates top-level operational SOC KPIs."""
    # Assets
    total_assets = Asset.query.count()
    online_assets = Asset.query.filter_by(status="online").count()
    offline_assets = Asset.query.filter_by(status="offline").count()
    critical_assets = Asset.query.filter(
        or_(Asset.risk_severity == "critical", Asset.criticality == "critical")
    ).count()

    # Alerts
    open_alert_statuses = ["new", "acknowledged", "investigating", "escalated"]
    open_alerts = Alert.query.filter(Alert.status.in_(open_alert_statuses)).count()
    critical_alerts = Alert.query.filter(
        Alert.status.in_(open_alert_statuses),
        Alert.severity == "critical",
    ).count()
    high_alerts = Alert.query.filter(
        Alert.status.in_(open_alert_statuses),
        Alert.severity == "high",
    ).count()

    # Incidents
    active_inc_statuses = ["new", "assigned", "investigating", "containment", "open"]
    active_incidents = Incident.query.filter(Incident.status.in_(active_inc_statuses)).count()
    critical_incidents = Incident.query.filter(
        Incident.status.in_(active_inc_statuses),
        Incident.severity == "critical",
    ).count()

    # Vulnerabilities
    open_vulns = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.status != "patched"
    ).count()
    critical_vulns = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.status != "patched",
        VulnerabilityFinding.severity == "critical",
    ).count()

    # IDS Alerts Today (Excluding diagnostic checksum noise)
    sec_filter = get_security_alert_sql_filter()
    ids_alerts_today = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= today_start,
        sec_filter,
    ).count()

    # SIEM Events Today
    siem_events_today = SiemEvent.query.filter(
        SiemEvent.timestamp >= today_start
    ).count()

    return {
        "totalAssets": total_assets,
        "onlineAssets": online_assets,
        "offlineAssets": offline_assets,
        "criticalAssets": critical_assets,
        "openAlerts": open_alerts,
        "criticalAlerts": critical_alerts,
        "highAlerts": high_alerts,
        "activeIncidents": active_incidents,
        "criticalIncidents": critical_incidents,
        "openVulnerabilities": open_vulns,
        "criticalVulnerabilities": critical_vulns,
        "idsAlertsToday": ids_alerts_today,
        "siemEventsToday": siem_events_today,
    }


def _build_alert_overview(last_24h):
    """Severity and status breakdown for Alert Center."""
    open_statuses = ["new", "acknowledged", "investigating", "escalated"]

    # Severity counts across all open alerts
    sev_counts = {
        "critical": Alert.query.filter(Alert.status.in_(open_statuses), Alert.severity == "critical").count(),
        "high": Alert.query.filter(Alert.status.in_(open_statuses), Alert.severity == "high").count(),
        "medium": Alert.query.filter(Alert.status.in_(open_statuses), Alert.severity == "medium").count(),
        "low": Alert.query.filter(Alert.status.in_(open_statuses), Alert.severity == "low").count(),
    }

    # Status counts
    status_counts = {
        "new": Alert.query.filter_by(status="new").count(),
        "acknowledged": Alert.query.filter_by(status="acknowledged").count(),
        "investigating": Alert.query.filter_by(status="investigating").count(),
        "escalated": Alert.query.filter_by(status="escalated").count(),
        "resolved": Alert.query.filter_by(status="resolved").count(),
    }

    # Recent 6 alerts
    recent_query = Alert.query.order_by(Alert.id.desc()).limit(6).all()
    recent = []
    for a in recent_query:
        recent.append({
            "id": a.id,
            "alertId": a.alert_id,
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "source": a.source,
            "host": a.affected_host or a.affected_asset or "-",
            "createdAt": a.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if a.created_at else "-",
        })

    return {
        "bySeverity": sev_counts,
        "byStatus": status_counts,
        "recentAlerts": recent,
    }


def _build_incident_overview():
    """Active incidents, severity breakdown, and recent records."""
    active_statuses = ["new", "assigned", "investigating", "containment", "open"]
    active_count = Incident.query.filter(Incident.status.in_(active_statuses)).count()
    crit_high = Incident.query.filter(
        Incident.status.in_(active_statuses),
        Incident.severity.in_(["critical", "high"]),
    ).count()

    by_status = {
        "new": Incident.query.filter_by(status="new").count(),
        "investigating": Incident.query.filter_by(status="investigating").count(),
        "containment": Incident.query.filter_by(status="containment").count(),
        "resolved": Incident.query.filter(Incident.status.in_(["resolved", "closed"])).count(),
    }

    recent_query = Incident.query.order_by(Incident.id.desc()).limit(6).all()
    recent = []
    for inc in recent_query:
        assignee_name = "Unassigned"
        if getattr(inc, "assigned_user", None):
            assignee_name = inc.assigned_user.username
        elif inc.assigned_to:
            assignee_name = f"User #{inc.assigned_to}"

        recent.append({
            "id": inc.id,
            "incidentId": inc.incident_id,
            "title": inc.title,
            "severity": inc.severity,
            "priority": inc.priority,
            "status": inc.status,
            "source": inc.source or "Manual",
            "assignedTo": assignee_name,
            "createdAt": inc.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if inc.created_at else "-",
        })

    return {
        "activeCount": active_count,
        "criticalHighCount": crit_high,
        "byStatus": by_status,
        "recentIncidents": recent,
    }


def _build_asset_risk_overview():
    """Asset risk distribution and top-risk hosts."""
    risk_distribution = {
        "critical": Asset.query.filter(or_(Asset.risk_severity == "critical", Asset.risk_score >= 80)).count(),
        "high": Asset.query.filter(and_(Asset.risk_severity == "high", Asset.risk_score < 80)).count(),
        "medium": Asset.query.filter(Asset.risk_severity == "medium").count(),
        "low": Asset.query.filter(Asset.risk_severity == "low").count(),
    }

    online_count = Asset.query.filter_by(status="online").count()
    offline_count = Asset.query.filter_by(status="offline").count()

    top_assets_query = Asset.query.order_by(Asset.risk_score.desc(), Asset.id.desc()).limit(5).all()
    top_risk_assets = []
    for a in top_assets_query:
        top_risk_assets.append({
            "id": a.id,
            "assetId": a.asset_id,
            "name": a.name,
            "ip": a.ip_address or "-",
            "type": a.asset_type,
            "environment": a.environment,
            "riskScore": a.risk_score,
            "severity": a.risk_severity,
            "openVulns": a.open_vulnerabilities_count,
            "openAlerts": a.open_alerts_count,
            "status": a.status,
        })

    return {
        "riskDistribution": risk_distribution,
        "onlineCount": online_count,
        "offlineCount": offline_count,
        "topRiskAssets": top_risk_assets,
    }


def _build_vulnerability_overview():
    """Severity breakdown and top findings from Vulnerability Scanner."""
    open_filter = VulnerabilityFinding.status != "patched"
    by_severity = {
        "critical": VulnerabilityFinding.query.filter(open_filter, VulnerabilityFinding.severity == "critical").count(),
        "high": VulnerabilityFinding.query.filter(open_filter, VulnerabilityFinding.severity == "high").count(),
        "medium": VulnerabilityFinding.query.filter(open_filter, VulnerabilityFinding.severity == "medium").count(),
        "low": VulnerabilityFinding.query.filter(open_filter, VulnerabilityFinding.severity == "low").count(),
    }

    top_vulns_query = (
        VulnerabilityFinding.query.filter(open_filter)
        .order_by(VulnerabilityFinding.cvss_score.desc(), VulnerabilityFinding.id.desc())
        .limit(5)
        .all()
    )
    recent_findings = []
    for v in top_vulns_query:
        recent_findings.append({
            "id": v.id,
            "findingId": v.finding_id,
            "cve": v.cve or "-",
            "title": v.title,
            "severity": v.severity,
            "cvss": v.cvss_score,
            "host": v.host,
            "port": v.port,
            "status": v.status,
        })

    return {
        "bySeverity": by_severity,
        "recentFindings": recent_findings,
    }


def _build_ids_overview(today_start):
    """Network IDS sensor health, event counts, and genuine alert signatures."""
    sensor_status = get_sensor_status()
    sec_filter = get_security_alert_sql_filter()

    events_today = NetworkIDSEvent.query.filter(NetworkIDSEvent.timestamp >= today_start).count()
    alerts_today = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= today_start,
        sec_filter,
    ).count()

    by_severity = {
        "critical": NetworkIDSEvent.query.filter(NetworkIDSEvent.timestamp >= today_start, sec_filter, NetworkIDSEvent.severity == "critical").count(),
        "high": NetworkIDSEvent.query.filter(NetworkIDSEvent.timestamp >= today_start, sec_filter, NetworkIDSEvent.severity == "high").count(),
        "medium": NetworkIDSEvent.query.filter(NetworkIDSEvent.timestamp >= today_start, sec_filter, NetworkIDSEvent.severity == "medium").count(),
        "low": NetworkIDSEvent.query.filter(NetworkIDSEvent.timestamp >= today_start, sec_filter, NetworkIDSEvent.severity == "low").count(),
    }

    # Top Signatures (genuine security alerts only)
    top_sigs_query = (
        db.session.query(
            NetworkIDSEvent.signature,
            NetworkIDSEvent.severity,
            func.count(NetworkIDSEvent.id).label("count"),
        )
        .filter(sec_filter, NetworkIDSEvent.signature.isnot(None))
        .group_by(NetworkIDSEvent.signature, NetworkIDSEvent.severity)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    top_signatures = [
        {"signature": s[0], "severity": s[1], "count": s[2]}
        for s in top_sigs_query
    ]

    return {
        "sensorStatus": sensor_status,
        "eventsToday": events_today,
        "alertsToday": alerts_today,
        "bySeverity": by_severity,
        "topSignatures": top_signatures,
    }


def _build_siem_overview(today_start, last_24h):
    """SIEM ingestion telemetry, source breakdowns, and severity counts."""
    events_today = SiemEvent.query.filter(SiemEvent.timestamp >= today_start).count()

    by_severity = {
        "critical": SiemEvent.query.filter_by(severity="critical").count(),
        "high": SiemEvent.query.filter_by(severity="high").count(),
        "medium": SiemEvent.query.filter_by(severity="medium").count(),
        "low": SiemEvent.query.filter_by(severity="low").count(),
        "info": SiemEvent.query.filter_by(severity="info").count(),
    }

    top_sources_query = (
        db.session.query(SiemEvent.source, func.count(SiemEvent.id).label("count"))
        .group_by(SiemEvent.source)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    top_sources = [{"source": r[0], "count": r[1]} for r in top_sources_query]

    recent_events_query = SiemEvent.query.order_by(SiemEvent.id.desc()).limit(5).all()
    recent_events = []
    for s in recent_events_query:
        recent_events.append({
            "id": s.id,
            "source": s.source,
            "severity": s.severity,
            "message": s.message,
            "host": s.host or "-",
            "timestamp": s.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if s.timestamp else "-",
        })

    return {
        "eventsToday": events_today,
        "bySeverity": by_severity,
        "topSources": top_sources,
        "recentEvents": recent_events,
    }


def _build_detection_overview(today_start):
    """Detection rules status and today's triggered detection events."""
    active_rules = DetectionRule.query.filter_by(status="active").count()
    events_today = DetectionEvent.query.filter(DetectionEvent.timestamp >= today_start).count()
    crit_high_events = DetectionEvent.query.filter(
        DetectionEvent.timestamp >= today_start,
        DetectionEvent.severity.in_(["critical", "high"]),
    ).count()

    recent_query = DetectionEvent.query.order_by(DetectionEvent.id.desc()).limit(5).all()
    recent = []
    for d in recent_query:
        recent.append({
            "id": d.id,
            "eventId": d.event_id,
            "ruleId": d.rule_id,
            "source": d.source,
            "host": d.host or "-",
            "severity": d.severity,
            "timestamp": d.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if d.timestamp else "-",
        })

    return {
        "activeRules": active_rules,
        "eventsToday": events_today,
        "criticalHighEvents": crit_high_events,
        "recentDetections": recent,
    }


def _build_threat_intel_overview():
    """Threat intelligence snapshot based on existing IOC/Campaign tables."""
    return {
        "totalIocs": IOC.query.count(),
        "activeCampaigns": ThreatCampaign.query.filter_by(status="active").count(),
        "threatActors": ThreatActor.query.count(),
        "activeFeeds": ThreatFeed.query.filter_by(status="active").count(),
    }


def _build_activity_feed(limit=15):
    """
    Constructs a unified, chronological security activity feed by merging
    real recent records from Alerts, Incidents, IDS, Detection, and SIEM.
    """
    items = []

    # 1. Recent Alerts
    alerts = Alert.query.order_by(Alert.id.desc()).limit(limit).all()
    for a in alerts:
        items.append({
            "timestamp": a.created_at,
            "timeStr": a.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if a.created_at else "-",
            "source": "Alert Center",
            "severity": a.severity,
            "title": a.title,
            "description": a.description or f"Alert on {a.affected_host or 'system'}",
            "entityId": a.alert_id,
            "url": f"/alert-center/",
        })

    # 2. Recent Incidents
    incidents = Incident.query.order_by(Incident.id.desc()).limit(limit).all()
    for inc in incidents:
        items.append({
            "timestamp": inc.created_at,
            "timeStr": inc.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if inc.created_at else "-",
            "source": "Incident Response",
            "severity": inc.severity,
            "title": f"Incident: {inc.title}",
            "description": inc.description or f"Status: {inc.status}",
            "entityId": inc.incident_id,
            "url": f"/incidents/{inc.incident_id}",
        })

    # 3. Recent Genuine Network IDS Events
    sec_filter = get_security_alert_sql_filter()
    ids_events = NetworkIDSEvent.query.filter(sec_filter).order_by(NetworkIDSEvent.id.desc()).limit(limit).all()
    for e in ids_events:
        items.append({
            "timestamp": e.timestamp,
            "timeStr": e.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if e.timestamp else "-",
            "source": "Network IDS",
            "severity": e.severity,
            "title": e.signature or "IDS Security Alert",
            "description": f"{e.src_ip} -> {e.dest_ip}:{e.dest_port or ''}",
            "entityId": f"IDS-{e.id}",
            "url": "/network-ids/",
        })

    # 4. Recent Detection Events
    detections = DetectionEvent.query.order_by(DetectionEvent.id.desc()).limit(limit).all()
    for d in detections:
        items.append({
            "timestamp": d.timestamp,
            "timeStr": d.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if d.timestamp else "-",
            "source": "Detection Engine",
            "severity": d.severity,
            "title": f"Detection Event: {d.source}",
            "description": f"Host: {d.host or '-'}",
            "entityId": d.event_id,
            "url": "/detection/dashboard",
        })

    # 5. Recent High/Critical SIEM Events
    siem_events = SiemEvent.query.filter(
        SiemEvent.severity.in_(["critical", "high"])
    ).order_by(SiemEvent.id.desc()).limit(limit).all()
    for s in siem_events:
        items.append({
            "timestamp": s.timestamp,
            "timeStr": s.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if s.timestamp else "-",
            "source": "SIEM",
            "severity": s.severity,
            "title": f"SIEM Alert ({s.source})",
            "description": s.message,
            "entityId": f"SIEM-{s.id}",
            "url": "/siem/dashboard",
        })

    # Sort descending by timestamp
    items.sort(key=lambda x: x["timestamp"] or datetime.min, reverse=True)

    # Clean non-serializable datetime before returning
    formatted = []
    for it in items[:limit]:
        item_copy = dict(it)
        item_copy["timestamp"] = it["timeStr"]
        formatted.append(item_copy)

    return formatted


def _build_trend_timeline(now):
    """
    Computes 24 hourly buckets of security events over the last 24 hours.
    Returns:
      hours: ["14:00", "15:00", ...]
      alerts: [c0, c1, ...]
      idsAlerts: [c0, c1, ...]
      detections: [c0, c1, ...]
    """
    last_24h = now - timedelta(hours=23)

    # Initialize 24 hourly buckets
    hours = []
    bucket_keys = []
    for i in range(24):
        slot_time = last_24h + timedelta(hours=i)
        hours.append(slot_time.strftime("%H:00"))
        bucket_keys.append((slot_time.year, slot_time.month, slot_time.day, slot_time.hour))

    alerts_map = {k: 0 for k in bucket_keys}
    ids_map = {k: 0 for k in bucket_keys}
    detections_map = {k: 0 for k in bucket_keys}

    # 1. Fetch Alerts within last 24h
    alerts_24h = db.session.query(Alert.created_at).filter(Alert.created_at >= last_24h).all()
    for (ts,) in alerts_24h:
        if ts:
            key = (ts.year, ts.month, ts.day, ts.hour)
            if key in alerts_map:
                alerts_map[key] += 1

    # 2. Fetch genuine IDS Alerts within last 24h
    sec_filter = get_security_alert_sql_filter()
    ids_24h = db.session.query(NetworkIDSEvent.timestamp).filter(
        NetworkIDSEvent.timestamp >= last_24h,
        sec_filter,
    ).all()
    for (ts,) in ids_24h:
        if ts:
            key = (ts.year, ts.month, ts.day, ts.hour)
            if key in ids_map:
                ids_map[key] += 1

    # 3. Fetch Detection Events within last 24h
    detections_24h = db.session.query(DetectionEvent.timestamp).filter(DetectionEvent.timestamp >= last_24h).all()
    for (ts,) in detections_24h:
        if ts:
            key = (ts.year, ts.month, ts.day, ts.hour)
            if key in detections_map:
                detections_map[key] += 1

    return {
        "hours": hours,
        "alerts": [alerts_map[k] for k in bucket_keys],
        "idsAlerts": [ids_map[k] for k in bucket_keys],
        "detections": [detections_map[k] for k in bucket_keys],
    }
