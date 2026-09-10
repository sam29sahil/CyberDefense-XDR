"""
CyberDefense XDR
Security Reports Service Layer
Provides data collection across all platform security modules,
KPI aggregation, and high-fidelity PDF / CSV generation.
"""

from datetime import datetime, timedelta
import csv
import io
import json
import os
import secrets
from typing import Any, Dict, List, Optional, Tuple

from flask import current_app
from sqlalchemy import and_, desc, func, not_

from app.extensions import db
from app.reports.models import Report, generate_report_id

# Cross-module Model imports
from app.assets.models import Asset
from app.alerts.models import Alert
from app.incidents.models import Incident
from app.scanner.models import Scan, VulnerabilityFinding
from app.ids.models import NetworkIDSEvent
from app.ids.services import get_security_alert_sql_filter
from app.siem.models import SiemEvent
from app.detection.models import DetectionRule, DetectionEvent
from app.threatintel.models import IOC, ThreatCampaign, ThreatFeed, ThreatActor


# ReportLab Imports for PDF Generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ============================================================
# REPORT TYPES REGISTRY
# ============================================================

REPORT_TYPES = {
    "executive_summary": {
        "id": "executive_summary",
        "name": "Executive Security Summary",
        "description": "High-level enterprise security posture, risk indices, critical incident & vulnerability exposure.",
        "category": "Executive",
        "supported_formats": ["pdf", "csv"],
    },
    "soc_operations": {
        "id": "soc_operations",
        "name": "SOC Operations Report",
        "description": "Operational throughput, alert ingestion, triage efficacy, and incident lifecycle metrics.",
        "category": "Operations",
        "supported_formats": ["pdf", "csv"],
    },
    "vulnerability_assessment": {
        "id": "vulnerability_assessment",
        "name": "Vulnerability Assessment Report",
        "description": "Detailed vulnerability posture across scanned assets, CVE/CWE distributions, and CVSS scores.",
        "category": "Vulnerability",
        "supported_formats": ["pdf", "csv"],
    },
    "incident_response": {
        "id": "incident_response",
        "name": "Incident Response Report",
        "description": "Comprehensive tracking of security incidents, severity profiles, containment status, and responders.",
        "category": "Incident",
        "supported_formats": ["pdf", "csv"],
    },
    "alert_detection": {
        "id": "alert_detection",
        "name": "Alert & Detection Report",
        "description": "Security alerts, top firing detection rules, MITRE ATT&CK tactic/technique alignment, and triage status.",
        "category": "Detection",
        "supported_formats": ["pdf", "csv"],
    },
    "network_ids": {
        "id": "network_ids",
        "name": "Network IDS Report",
        "description": "Suricata network intrusion detections, signatures, protocol distribution, excluding checksum diagnostic noise.",
        "category": "Network",
        "supported_formats": ["pdf", "csv"],
    },
    "asset_risk": {
        "id": "asset_risk",
        "name": "Asset Risk Report",
        "description": "Inventory profile, environment classification, OS distribution, and correlated asset risk scores.",
        "category": "Asset",
        "supported_formats": ["pdf", "csv"],
    },
    "threat_intel": {
        "id": "threat_intel",
        "name": "Threat Intelligence Report",
        "description": "Active IOCs, threat actors, campaigns, feed health, and indicator type distribution.",
        "category": "Threat Intel",
        "supported_formats": ["pdf", "csv"],
    },
}


# ============================================================
# FILE SYSTEM & SECURITY HELPERS
# ============================================================

def get_reports_dir() -> str:
    """Returns absolute path to reports instance directory, ensuring it exists."""
    try:
        base_dir = current_app.instance_path
    except RuntimeError:
        base_dir = os.path.abspath("instance")
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return os.path.abspath(reports_dir)


def get_safe_report_path(report_id: str, file_format: str) -> str:
    """
    Constructs and strictly validates that the generated file resides within
    the reports directory to prevent directory traversal attacks.
    """
    if not report_id or ".." in report_id or "/" in report_id or "\\" in report_id:
        raise ValueError("Illegal file path resolution detected: Path traversal attempt.")

    safe_id = "".join(c for c in report_id if c.isalnum() or c in ("-", "_"))
    if not safe_id:
        raise ValueError("Invalid report ID provided.")

    safe_ext = "pdf" if file_format.lower() == "pdf" else "csv"
    reports_dir = get_reports_dir()
    candidate_path = os.path.abspath(os.path.join(reports_dir, f"{safe_id}.{safe_ext}"))
    
    # Path traversal verification
    common = os.path.commonpath([reports_dir, candidate_path])
    if common != reports_dir:
        raise ValueError("Illegal file path resolution detected.")
    return candidate_path


def parse_date_range(
    preset: Optional[str] = None,
    date_from_str: Optional[str] = None,
    date_to_str: Optional[str] = None,
) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    Parses preset date ranges or explicit ISO strings into UTC datetime objects.
    """
    now = datetime.utcnow()
    
    if preset:
        p = preset.lower().strip()
        if p in ("24h", "last_24h", "last_24_hours"):
            return now - timedelta(hours=24), now
        elif p in ("7d", "last_7d", "last_7_days"):
            return now - timedelta(days=7), now
        elif p in ("30d", "last_30d", "last_30_days"):
            return now - timedelta(days=30), now
        elif p in ("all", "all_time"):
            return None, None

    date_from = None
    date_to = None

    if date_from_str:
        try:
            cleaned = date_from_str.replace("Z", "+00:00")
            date_from = datetime.fromisoformat(cleaned)
            if date_from.tzinfo:
                date_from = date_from.replace(tzinfo=None)
        except Exception:
            pass

    if date_to_str:
        try:
            cleaned = date_to_str.replace("Z", "+00:00")
            date_to = datetime.fromisoformat(cleaned)
            if date_to.tzinfo:
                date_to = date_to.replace(tzinfo=None)
        except Exception:
            pass

    return date_from, date_to


# ============================================================
# DATA COLLECTION SERVICES (8 DISTINCT REPORT TYPES)
# ============================================================

def collect_executive_summary(date_from: Optional[datetime], date_to: Optional[datetime], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregates executive posture telemetry across all security domains."""
    total_assets = Asset.query.count()
    crit_assets = Asset.query.filter(Asset.criticality.in_(["Mission Critical", "High"])).count()

    alert_q = Alert.query
    if date_from:
        alert_q = alert_q.filter(Alert.created_at >= date_from)
    if date_to:
        alert_q = alert_q.filter(Alert.created_at <= date_to)
    total_alerts = alert_q.count()
    crit_high_alerts = alert_q.filter(Alert.severity.in_(["critical", "high"])).count()
    open_alerts = alert_q.filter(Alert.status.in_(["new", "investigating", "triaged"])).count()

    inc_q = Incident.query
    if date_from:
        inc_q = inc_q.filter(Incident.created_at >= date_from)
    if date_to:
        inc_q = inc_q.filter(Incident.created_at <= date_to)
    total_incidents = inc_q.count()
    active_incidents = inc_q.filter(Incident.status.in_(["new", "investigating", "active", "contained"])).count()
    crit_incidents = inc_q.filter(Incident.severity == "critical").count()

    vuln_q = VulnerabilityFinding.query
    total_vulns = vuln_q.count()
    crit_vulns = vuln_q.filter(VulnerabilityFinding.severity == "critical").count()
    high_vulns = vuln_q.filter(VulnerabilityFinding.severity == "high").count()

    ids_q = NetworkIDSEvent.query.filter(get_security_alert_sql_filter())
    if date_from:
        ids_q = ids_q.filter(NetworkIDSEvent.timestamp >= date_from)
    if date_to:
        ids_q = ids_q.filter(NetworkIDSEvent.timestamp <= date_to)
    ids_alerts_count = ids_q.count()

    penalty = (crit_incidents * 15) + (active_incidents * 5) + (crit_high_alerts * 3) + (crit_vulns * 4) + (high_vulns * 2)
    posture_score = max(10, min(100, 100 - penalty))

    kpi_metrics = [
        {"label": "Security Posture Index", "value": f"{posture_score}/100", "subtitle": "Enterprise Risk Rating", "tone": "success" if posture_score >= 80 else ("warning" if posture_score >= 60 else "danger")},
        {"label": "Active Incidents", "value": str(active_incidents), "subtitle": f"{crit_incidents} Critical Priority", "tone": "danger" if active_incidents > 0 else "success"},
        {"label": "Critical/High Alerts", "value": str(crit_high_alerts), "subtitle": f"{open_alerts} Open for Triage", "tone": "warning" if crit_high_alerts > 0 else "info"},
        {"label": "Critical Vulnerabilities", "value": str(crit_vulns), "subtitle": f"{high_vulns} High Severity", "tone": "danger" if crit_vulns > 0 else "info"},
        {"label": "Monitored Assets", "value": str(total_assets), "subtitle": f"{crit_assets} Mission Critical", "tone": "primary"},
        {"label": "Network IDS Detections", "value": str(ids_alerts_count), "subtitle": "Genuine Intrusions", "tone": "warning" if ids_alerts_count > 0 else "info"},
    ]

    recent_incs = inc_q.order_by(desc(Incident.created_at)).limit(10).all()
    inc_rows = [
        [i.incident_id, i.title[:45], i.severity.upper(), i.status.capitalize(), i.affected_host or "Enterprise", i.created_at.strftime("%Y-%m-%d %H:%M")]
        for i in recent_incs
    ]

    top_vulns = vuln_q.filter(VulnerabilityFinding.severity.in_(["critical", "high"])).order_by(desc(VulnerabilityFinding.cvss_score)).limit(10).all()
    vuln_rows = [
        [v.finding_id, v.cve or "N/A", v.title[:45], v.severity.upper(), f"{v.cvss_score:.1f}", v.host]
        for v in top_vulns
    ]

    sections = [
        {
            "title": "Top Active Incidents Requiring Executive Attention",
            "columns": ["Incident ID", "Title", "Severity", "Status", "Target Host", "Reported At"],
            "rows": inc_rows,
        },
        {
            "title": "Highest Risk Vulnerability Exposures",
            "columns": ["Finding ID", "CVE ID", "Vulnerability Title", "Severity", "CVSS", "Affected Host"],
            "rows": vuln_rows,
        },
    ]

    recommendations = [
        "Ensure prompt containment and root-cause analysis for open Critical and High priority incidents.",
        "Prioritize patch management and mitigation for identified Critical CVSS vulnerabilities on external and mission-critical assets.",
        "Continuously review Network IDS alerts and maintain updated Suricata detection rules to detect emerging lateral movement.",
    ]

    return {
        "kpi_metrics": kpi_metrics,
        "sections": sections,
        "recommendations": recommendations,
        "summary": {
            "posture_score": posture_score,
            "active_incidents": active_incidents,
            "crit_high_alerts": crit_high_alerts,
            "total_assets": total_assets,
            "total_vulns": total_vulns,
        },
    }


def collect_soc_operations(date_from: Optional[datetime], date_to: Optional[datetime], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregates SOC operational throughput, triage rates, and telemetry ingestion."""
    alert_q = Alert.query
    if date_from:
        alert_q = alert_q.filter(Alert.created_at >= date_from)
    if date_to:
        alert_q = alert_q.filter(Alert.created_at <= date_to)
    
    total_alerts = alert_q.count()
    triaged_alerts = alert_q.filter(Alert.status.in_(["closed", "resolved", "investigating"])).count()
    open_alerts = total_alerts - triaged_alerts
    triage_rate = round((triaged_alerts / total_alerts * 100), 1) if total_alerts > 0 else 100.0

    siem_q = SiemEvent.query
    if date_from:
        siem_q = siem_q.filter(SiemEvent.timestamp >= date_from)
    if date_to:
        siem_q = siem_q.filter(SiemEvent.timestamp <= date_to)
    total_siem = siem_q.count()

    ids_q = NetworkIDSEvent.query.filter(get_security_alert_sql_filter())
    if date_from:
        ids_q = ids_q.filter(NetworkIDSEvent.timestamp >= date_from)
    if date_to:
        ids_q = ids_q.filter(NetworkIDSEvent.timestamp <= date_to)
    total_ids = ids_q.count()

    inc_q = Incident.query
    if date_from:
        inc_q = inc_q.filter(Incident.created_at >= date_from)
    if date_to:
        inc_q = inc_q.filter(Incident.created_at <= date_to)
    total_incidents = inc_q.count()
    closed_incidents = inc_q.filter(Incident.status.in_(["resolved", "closed"])).count()

    kpi_metrics = [
        {"label": "Alerts Processed", "value": str(total_alerts), "subtitle": f"{open_alerts} Awaiting Triage", "tone": "primary"},
        {"label": "Triage Rate", "value": f"{triage_rate}%", "subtitle": f"{triaged_alerts} Completed", "tone": "success" if triage_rate >= 80 else "warning"},
        {"label": "SIEM Events Ingested", "value": str(total_siem), "subtitle": "Telemetry Ingestion", "tone": "info"},
        {"label": "IDS Genuine Intrusions", "value": str(total_ids), "subtitle": "Suricata Detections", "tone": "warning" if total_ids > 0 else "info"},
        {"label": "Incidents Escalated", "value": str(total_incidents), "subtitle": f"{closed_incidents} Resolved", "tone": "primary"},
        {"label": "Detection Rules Active", "value": str(DetectionRule.query.filter_by(status="active").count()), "subtitle": "Live Correlation Rules", "tone": "info"},
    ]

    source_counts = (
        db.session.query(Alert.source, func.count(Alert.id))
        .group_by(Alert.source)
        .order_by(desc(func.count(Alert.id)))
        .limit(8)
        .all()
    )
    source_rows = [[s or "System", str(c)] for s, c in source_counts]

    recent_alerts = alert_q.order_by(desc(Alert.created_at)).limit(10).all()
    alert_rows = [
        [a.alert_id, a.title[:45], a.severity.upper(), a.status.capitalize(), a.source or "System", a.created_at.strftime("%Y-%m-%d %H:%M")]
        for a in recent_alerts
    ]

    sections = [
        {
            "title": "Alert Ingestion by Security Source",
            "columns": ["Source System", "Event Count"],
            "rows": source_rows,
        },
        {
            "title": "Recent Operational Alerts",
            "columns": ["Alert ID", "Title", "Severity", "Status", "Source", "Generated At"],
            "rows": alert_rows,
        },
    ]

    recommendations = [
        "Review open alerts exceeding standard 4-hour SLA to maintain SOC response agility.",
        "Ensure SIEM ingestion pipelines and parser mappings maintain zero unparsed log drop rates.",
    ]

    return {
        "kpi_metrics": kpi_metrics,
        "sections": sections,
        "recommendations": recommendations,
        "summary": {
            "total_alerts": total_alerts,
            "triage_rate": triage_rate,
            "total_siem": total_siem,
            "total_ids": total_ids,
            "total_incidents": total_incidents,
        },
    }


def collect_vulnerability_assessment(date_from: Optional[datetime], date_to: Optional[datetime], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregates vulnerability assessment telemetry, scan runs, and host exposures."""
    vuln_q = VulnerabilityFinding.query
    if date_from:
        vuln_q = vuln_q.filter(VulnerabilityFinding.discovered_at >= date_from)
    if date_to:
        vuln_q = vuln_q.filter(VulnerabilityFinding.discovered_at <= date_to)
    
    sev_filter = filters.get("severity")
    if sev_filter and sev_filter != "all":
        vuln_q = vuln_q.filter(VulnerabilityFinding.severity == sev_filter.lower())

    total_vulns = vuln_q.count()
    crit_count = vuln_q.filter(VulnerabilityFinding.severity == "critical").count()
    high_count = vuln_q.filter(VulnerabilityFinding.severity == "high").count()
    med_count = vuln_q.filter(VulnerabilityFinding.severity == "medium").count()
    low_count = vuln_q.filter(VulnerabilityFinding.severity == "low").count()

    scan_q = Scan.query
    if date_from:
        scan_q = scan_q.filter(Scan.started_at >= date_from)
    if date_to:
        scan_q = scan_q.filter(Scan.started_at <= date_to)
    total_scans = scan_q.count()
    completed_scans = scan_q.filter(Scan.status == "completed").count()

    kpi_metrics = [
        {"label": "Total Findings", "value": str(total_vulns), "subtitle": "Identified Exposures", "tone": "primary"},
        {"label": "Critical Severity", "value": str(crit_count), "subtitle": "Immediate Fix Required", "tone": "danger" if crit_count > 0 else "info"},
        {"label": "High Severity", "value": str(high_count), "subtitle": "CVSS 7.0 - 8.9", "tone": "warning" if high_count > 0 else "info"},
        {"label": "Medium Severity", "value": str(med_count), "subtitle": "CVSS 4.0 - 6.9", "tone": "info"},
        {"label": "Low / Informational", "value": str(low_count), "subtitle": "Hardening Recommendations", "tone": "info"},
        {"label": "Completed Scans", "value": str(completed_scans), "subtitle": f"{total_scans} Total Executions", "tone": "success"},
    ]

    top_findings = vuln_q.order_by(desc(VulnerabilityFinding.cvss_score)).limit(15).all()
    finding_rows = [
        [f.finding_id, f.cve or "N/A", f.title[:45], f.severity.upper(), f"{f.cvss_score:.1f}", f.host, str(f.port or "N/A"), f.tool]
        for f in top_findings
    ]

    host_counts = (
        db.session.query(VulnerabilityFinding.host, func.count(VulnerabilityFinding.id))
        .group_by(VulnerabilityFinding.host)
        .order_by(desc(func.count(VulnerabilityFinding.id)))
        .limit(10)
        .all()
    )
    host_rows = [[h, str(c)] for h, c in host_counts]

    sections = [
        {
            "title": "Evaluated Vulnerability Findings",
            "columns": ["Finding ID", "CVE ID", "Title", "Severity", "CVSS", "Target Host", "Port", "Tool"],
            "rows": finding_rows,
        },
        {
            "title": "Most Exposed Target Hosts",
            "columns": ["Host Address / Name", "Identified Vulnerabilities"],
            "rows": host_rows,
        },
    ]

    recommendations = [
        "Deploy vendor security patches for all CVEs with CVSS >= 7.0.",
        "Disable unauthenticated remote management services discovered on exposed ports.",
        "Conduct follow-up verification scans once corrective actions have been applied.",
    ]

    return {
        "kpi_metrics": kpi_metrics,
        "sections": sections,
        "recommendations": recommendations,
        "summary": {
            "total_vulns": total_vulns,
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "scans": completed_scans,
        },
    }


def collect_incident_response(date_from: Optional[datetime], date_to: Optional[datetime], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregates security incident lifecycle, severity distribution, and response tracking."""
    inc_q = Incident.query
    if date_from:
        inc_q = inc_q.filter(Incident.created_at >= date_from)
    if date_to:
        inc_q = inc_q.filter(Incident.created_at <= date_to)

    sev_filter = filters.get("severity")
    if sev_filter and sev_filter != "all":
        inc_q = inc_q.filter(Incident.severity == sev_filter.lower())

    status_filter = filters.get("status")
    if status_filter and status_filter != "all":
        inc_q = inc_q.filter(Incident.status == status_filter.lower())

    total_incs = inc_q.count()
    crit_count = inc_q.filter(Incident.severity == "critical").count()
    high_count = inc_q.filter(Incident.severity == "high").count()
    active_count = inc_q.filter(Incident.status.in_(["new", "investigating", "active", "contained"])).count()
    closed_count = inc_q.filter(Incident.status.in_(["resolved", "closed"])).count()

    kpi_metrics = [
        {"label": "Total Incidents", "value": str(total_incs), "subtitle": "Tracked Cases", "tone": "primary"},
        {"label": "Active / In-Progress", "value": str(active_count), "subtitle": "Under Active Containment", "tone": "danger" if active_count > 0 else "success"},
        {"label": "Critical Severity", "value": str(crit_count), "subtitle": "Highest Escalation", "tone": "danger" if crit_count > 0 else "info"},
        {"label": "High Severity", "value": str(high_count), "subtitle": "Elevated Threat", "tone": "warning" if high_count > 0 else "info"},
        {"label": "Resolved / Closed", "value": str(closed_count), "subtitle": "Cases Remediated", "tone": "success"},
        {"label": "Resolution Rate", "value": f"{round((closed_count / total_incs * 100), 1) if total_incs > 0 else 100.0}%", "subtitle": "Closure Efficacy", "tone": "info"},
    ]

    all_incs = inc_q.order_by(desc(Incident.created_at)).limit(20).all()
    inc_rows = [
        [i.incident_id, i.title[:40], i.severity.upper(), i.status.capitalize(), i.affected_host or "Enterprise", i.category or "Security", i.created_at.strftime("%Y-%m-%d %H:%M")]
        for i in all_incs
    ]

    sections = [
        {
            "title": "Incident Log & Remediation Progress",
            "columns": ["Incident ID", "Title", "Severity", "Status", "Target Host", "Category", "Created At"],
            "rows": inc_rows,
        },
    ]

    recommendations = [
        "Complete post-incident reviews (PIR) for all closed Critical and High priority incidents.",
        "Preserve evidentiary forensic timelines and PCAP traces for active investigations.",
    ]

    return {
        "kpi_metrics": kpi_metrics,
        "sections": sections,
        "recommendations": recommendations,
        "summary": {
            "total_incidents": total_incs,
            "active_incidents": active_count,
            "critical_incidents": crit_count,
            "closed_incidents": closed_count,
        },
    }


def collect_alert_detection(date_from: Optional[datetime], date_to: Optional[datetime], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregates alert telemetry, detection rule triggering, and MITRE ATT&CK coverage."""
    alert_q = Alert.query
    if date_from:
        alert_q = alert_q.filter(Alert.created_at >= date_from)
    if date_to:
        alert_q = alert_q.filter(Alert.created_at <= date_to)

    sev_filter = filters.get("severity")
    if sev_filter and sev_filter != "all":
        alert_q = alert_q.filter(Alert.severity == sev_filter.lower())

    total_alerts = alert_q.count()
    crit_count = alert_q.filter(Alert.severity == "critical").count()
    high_count = alert_q.filter(Alert.severity == "high").count()
    med_count = alert_q.filter(Alert.severity == "medium").count()
    low_count = alert_q.filter(Alert.severity.in_(["low", "info"])).count()

    total_rules = DetectionRule.query.count()
    active_rules = DetectionRule.query.filter_by(status="active").count()

    kpi_metrics = [
        {"label": "Total Alerts", "value": str(total_alerts), "subtitle": "Security Detections", "tone": "primary"},
        {"label": "Critical Alerts", "value": str(crit_count), "subtitle": "Urgent Response Needed", "tone": "danger" if crit_count > 0 else "info"},
        {"label": "High Alerts", "value": str(high_count), "subtitle": "High Impact", "tone": "warning" if high_count > 0 else "info"},
        {"label": "Medium Alerts", "value": str(med_count), "subtitle": "Standard Priority", "tone": "info"},
        {"label": "Low / Informational", "value": str(low_count), "subtitle": "Baseline Visibility", "tone": "info"},
        {"label": "Active Detection Rules", "value": f"{active_rules}/{total_rules}", "subtitle": "Rule Catalog", "tone": "success"},
    ]

    recent_alerts = alert_q.order_by(desc(Alert.created_at)).limit(15).all()
    alert_rows = [
        [a.alert_id, a.title[:45], a.severity.upper(), a.status.capitalize(), a.source or "Detection Engine", a.mitre_id or "N/A", a.created_at.strftime("%Y-%m-%d %H:%M")]
        for a in recent_alerts
    ]

    rules = DetectionRule.query.filter(DetectionRule.triggers_30d > 0).order_by(desc(DetectionRule.triggers_30d)).limit(10).all()
    rule_rows = [
        [r.rule_id, r.name[:45], r.severity.upper(), r.category, str(r.triggers_30d), r.mitre_id or "N/A"]
        for r in rules
    ]

    sections = [
        {
            "title": "Triggered Security Alerts",
            "columns": ["Alert ID", "Title", "Severity", "Status", "Source", "MITRE ATT&CK", "Timestamp"],
            "rows": alert_rows,
        },
        {
            "title": "Top Firing Detection Rules",
            "columns": ["Rule ID", "Rule Name", "Severity", "Category", "Triggers (30d)", "MITRE ATT&CK"],
            "rows": rule_rows,
        },
    ]

    recommendations = [
        "Tune detection rules with high trigger counts and zero escalation to reduce analyst fatigue.",
        "Expand MITRE ATT&CK coverage for credential access and persistence tactics.",
    ]

    return {
        "kpi_metrics": kpi_metrics,
        "sections": sections,
        "recommendations": recommendations,
        "summary": {
            "total_alerts": total_alerts,
            "critical_alerts": crit_count,
            "high_alerts": high_count,
            "active_rules": active_rules,
        },
    }


def collect_network_ids(date_from: Optional[datetime], date_to: Optional[datetime], filters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Aggregates Suricata Network IDS events.
    CRITICAL: Strictly excludes diagnostic noise (SID 2200074 checksum offload artifacts)
    via get_security_alert_sql_filter().
    """
    sec_filter = get_security_alert_sql_filter()
    ids_q = NetworkIDSEvent.query.filter(sec_filter)

    if date_from:
        ids_q = ids_q.filter(NetworkIDSEvent.timestamp >= date_from)
    if date_to:
        ids_q = ids_q.filter(NetworkIDSEvent.timestamp <= date_to)

    sev_filter = filters.get("severity")
    if sev_filter and sev_filter != "all":
        ids_q = ids_q.filter(NetworkIDSEvent.severity == sev_filter.lower())

    total_events = ids_q.count()
    crit_count = ids_q.filter(NetworkIDSEvent.severity == "critical").count()
    high_count = ids_q.filter(NetworkIDSEvent.severity == "high").count()
    med_count = ids_q.filter(NetworkIDSEvent.severity == "medium").count()
    low_count = ids_q.filter(NetworkIDSEvent.severity.in_(["low", "info"])).count()

    blocked_count = ids_q.filter(NetworkIDSEvent.action.in_(["blocked", "dropped"])).count()

    kpi_metrics = [
        {"label": "Genuine Intrusions", "value": str(total_events), "subtitle": "Excludes Checksum Noise", "tone": "warning" if total_events > 0 else "info"},
        {"label": "Critical Severity", "value": str(crit_count), "subtitle": "High Confidence Attacks", "tone": "danger" if crit_count > 0 else "info"},
        {"label": "High Severity", "value": str(high_count), "subtitle": "Malicious Signatures", "tone": "warning" if high_count > 0 else "info"},
        {"label": "Medium Severity", "value": str(med_count), "subtitle": "Suspicious Anomalies", "tone": "info"},
        {"label": "Blocked / Dropped", "value": str(blocked_count), "subtitle": "Inline Actions", "tone": "success"},
        {"label": "Sensors Active", "value": "1", "subtitle": "Suricata eth0", "tone": "info"},
    ]

    top_sigs = (
        db.session.query(NetworkIDSEvent.signature, func.count(NetworkIDSEvent.id))
        .filter(sec_filter)
        .group_by(NetworkIDSEvent.signature)
        .order_by(desc(func.count(NetworkIDSEvent.id)))
        .limit(10)
        .all()
    )
    sig_rows = [[s or "Unknown Signature", str(c)] for s, c in top_sigs]

    recent_ids = ids_q.order_by(desc(NetworkIDSEvent.timestamp)).limit(15).all()
    event_rows = [
        [
            ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            (ev.signature or "Alert")[:45],
            ev.severity.upper(),
            ev.protocol or "TCP",
            f"{ev.src_ip or 'N/A'}:{ev.src_port or 0}",
            f"{ev.dest_ip or 'N/A'}:{ev.dest_port or 0}",
            ev.action.capitalize(),
        ]
        for ev in recent_ids
    ]

    sections = [
        {
            "title": "Top Intrusion Signatures Detected",
            "columns": ["Signature Name", "Detection Count"],
            "rows": sig_rows,
        },
        {
            "title": "Recent Security Intrusion Events",
            "columns": ["Timestamp", "Signature", "Severity", "Proto", "Source IP:Port", "Dest IP:Port", "Action"],
            "rows": event_rows,
        },
    ]

    recommendations = [
        "Investigate recurring source IP addresses identified in intrusion signatures for potential botnet or scanner activity.",
        "Maintain Suricata ruleset updates via suricata-update to ensure coverage for current zero-day threats.",
    ]

    return {
        "kpi_metrics": kpi_metrics,
        "sections": sections,
        "recommendations": recommendations,
        "summary": {
            "total_events": total_events,
            "critical_events": crit_count,
            "high_events": high_count,
            "blocked_events": blocked_count,
        },
    }


def collect_asset_risk(date_from: Optional[datetime], date_to: Optional[datetime], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregates enterprise asset inventory, classification, and correlated risk scores."""
    asset_q = Asset.query

    env_filter = filters.get("environment")
    if env_filter and env_filter != "all":
        asset_q = asset_q.filter(Asset.environment == env_filter)

    total_assets = asset_q.count()
    crit_assets = asset_q.filter(Asset.criticality.in_(["Mission Critical", "High"])).count()
    high_risk_assets = asset_q.filter(Asset.risk_score >= 70).count()
    med_risk_assets = asset_q.filter(and_(Asset.risk_score >= 40, Asset.risk_score < 70)).count()
    low_risk_assets = asset_q.filter(Asset.risk_score < 40).count()

    total_open_vulns = sum((getattr(a, "open_vulnerabilities_count", 0) or getattr(a, "open_vulnerabilities", 0)) for a in asset_q.all())

    kpi_metrics = [
        {"label": "Total Assets", "value": str(total_assets), "subtitle": "Tracked IT/OT Nodes", "tone": "primary"},
        {"label": "High Risk Profile", "value": str(high_risk_assets), "subtitle": "Score >= 70", "tone": "danger" if high_risk_assets > 0 else "info"},
        {"label": "Medium Risk Profile", "value": str(med_risk_assets), "subtitle": "Score 40 - 69", "tone": "warning" if med_risk_assets > 0 else "info"},
        {"label": "Low Risk / Hardened", "value": str(low_risk_assets), "subtitle": "Score < 40", "tone": "success"},
        {"label": "Critical Assets", "value": str(crit_assets), "subtitle": "Mission Critical & High", "tone": "info"},
        {"label": "Correlated Vulns", "value": str(total_open_vulns), "subtitle": "Active on Monitored Hosts", "tone": "warning" if total_open_vulns > 0 else "info"},
    ]

    env_counts = (
        db.session.query(Asset.environment, func.count(Asset.id))
        .group_by(Asset.environment)
        .order_by(desc(func.count(Asset.id)))
        .all()
    )
    env_rows = [[e or "Unassigned", str(c)] for e, c in env_counts]

    top_assets = asset_q.order_by(desc(Asset.risk_score)).limit(15).all()
    asset_rows = [
        [a.asset_id, a.name[:35], a.ip_address or "N/A", a.asset_type, a.environment, a.criticality, f"{a.risk_score:.0f}", str(getattr(a, "open_vulnerabilities_count", 0) or getattr(a, "open_vulnerabilities", 0))]
        for a in top_assets
    ]

    sections = [
        {
            "title": "Asset Inventory by Environment",
            "columns": ["Environment", "Node Count"],
            "rows": env_rows,
        },
        {
            "title": "High-Risk Enterprise Assets",
            "columns": ["Asset ID", "Asset Name", "IP Address", "Type", "Environment", "Criticality", "Risk Score", "Open Vulns"],
            "rows": asset_rows,
        },
    ]

    recommendations = [
        "Prioritize vulnerability remediation for assets categorized as Mission Critical with Risk Scores >= 70.",
        "Ensure all endpoints in Production environments have active EDR agents and recent vulnerability scan results.",
    ]

    return {
        "kpi_metrics": kpi_metrics,
        "sections": sections,
        "recommendations": recommendations,
        "summary": {
            "total_assets": total_assets,
            "high_risk_assets": high_risk_assets,
            "critical_assets": crit_assets,
            "total_open_vulns": total_open_vulns,
        },
    }


def collect_threat_intel(date_from: Optional[datetime], date_to: Optional[datetime], filters: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregates threat intelligence telemetry, active feeds, IOCs, and campaigns."""
    ioc_q = IOC.query
    total_iocs = ioc_q.count()
    crit_iocs = ioc_q.filter(IOC.threat_level == "critical").count()
    high_iocs = ioc_q.filter(IOC.threat_level == "high").count()

    total_feeds = ThreatFeed.query.count()
    active_feeds = ThreatFeed.query.filter_by(status="active").count()

    total_campaigns = ThreatCampaign.query.count()
    active_campaigns = ThreatCampaign.query.filter_by(status="active").count()

    kpi_metrics = [
        {"label": "Total IOCs", "value": str(total_iocs), "subtitle": "Threat Indicators", "tone": "primary"},
        {"label": "Critical Threat Level", "value": str(crit_iocs), "subtitle": "High Confidence Malicious", "tone": "danger" if crit_iocs > 0 else "info"},
        {"label": "High Threat Level", "value": str(high_iocs), "subtitle": "Confirmed Bad Indicators", "tone": "warning" if high_iocs > 0 else "info"},
        {"label": "Active Feeds", "value": f"{active_feeds}/{total_feeds}", "subtitle": "Threat Intel Ingestion", "tone": "success"},
        {"label": "Active Campaigns", "value": str(active_campaigns), "subtitle": f"{total_campaigns} Monitored", "tone": "warning" if active_campaigns > 0 else "info"},
        {"label": "Known Threat Actors", "value": str(ThreatActor.query.count()), "subtitle": "Adversary Profiles", "tone": "info"},
    ]

    type_counts = (
        db.session.query(IOC.type, func.count(IOC.id))
        .group_by(IOC.type)
        .order_by(desc(func.count(IOC.id)))
        .all()
    )
    type_rows = [[t.upper(), str(c)] for t, c in type_counts]

    sample_iocs = ioc_q.order_by(desc(IOC.confidence)).limit(15).all()
    ioc_rows = [
        [i.ioc_id, i.value[:45], i.type.upper(), i.threat_level.upper(), f"{i.confidence}%", i.source or "ThreatIntel"]
        for i in sample_iocs
    ]

    sections = [
        {
            "title": "Indicator of Compromise (IOC) Distribution by Type",
            "columns": ["Indicator Type", "Record Count"],
            "rows": type_rows,
        },
        {
            "title": "High Confidence Threat Indicators",
            "columns": ["IOC ID", "Indicator Value", "Type", "Threat Level", "Confidence", "Source"],
            "rows": ioc_rows,
        },
    ]

    recommendations = [
        "Ensure automated SIEM and IDS matching against Critical and High confidence IOC feeds.",
        "Block identified malicious IPs and domain indicators at perimeter firewalls and DNS sinkholes.",
    ]

    return {
        "kpi_metrics": kpi_metrics,
        "sections": sections,
        "recommendations": recommendations,
        "summary": {
            "total_iocs": total_iocs,
            "critical_iocs": crit_iocs,
            "active_feeds": active_feeds,
            "active_campaigns": active_campaigns,
        },
    }


# ============================================================
# DISPATCHER
# ============================================================

COLLECTORS = {
    "executive_summary": collect_executive_summary,
    "soc_operations": collect_soc_operations,
    "vulnerability_assessment": collect_vulnerability_assessment,
    "incident_response": collect_incident_response,
    "alert_detection": collect_alert_detection,
    "network_ids": collect_network_ids,
    "asset_risk": collect_asset_risk,
    "threat_intel": collect_threat_intel,
}


def build_report_telemetry(
    report_type: str,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    filters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Executes telemetry gathering for requested report type and structures metadata.
    """
    if report_type not in REPORT_TYPES:
        raise ValueError(f"Unsupported report type: '{report_type}'")

    filters = filters or {}
    collector = COLLECTORS[report_type]
    data = collector(date_from, date_to, filters)

    telemetry = {
        "report_type": report_type,
        "report_title": REPORT_TYPES[report_type]["name"],
        "category": REPORT_TYPES[report_type]["category"],
        "date_from": date_from.isoformat() if date_from else None,
        "date_to": date_to.isoformat() if date_to else None,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "filters": filters,
        "kpi_metrics": data["kpi_metrics"],
        "sections": data["sections"],
        "recommendations": data["recommendations"],
        "summary": data["summary"],
    }
    return telemetry


# ============================================================
# PDF GENERATOR (REPORTLAB)
# ============================================================

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        # Top Header line
        self.setStrokeColor(colors.HexColor("#334155"))
        self.setLineWidth(0.5)
        self.line(40, letter[1] - 35, letter[0] - 40, letter[1] - 35)

        # Header Title
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0284c7"))
        self.drawString(40, letter[1] - 30, "CYBERDEFENSE XDR")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(145, letter[1] - 30, "|  Enterprise Security Report")

        # Bottom Footer line
        self.line(40, 38, letter[0] - 40, 38)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(40, 26, "CyberDefense XDR Security Platform - Strictly Confidential")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 40, 26, page_str)
        self.restoreState()


def generate_report_pdf(telemetry: Dict[str, Any], output_path: str) -> int:
    """
    Renders professional vector PDF report to output_path.
    Returns file size in bytes.
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=50,
    )

    styles = getSampleStyleSheet()
    normal_style = styles["Normal"]
    normal_style.fontSize = 8
    normal_style.leading = 10

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12,
    )

    section_heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6,
    )

    cell_style = ParagraphStyle(
        "CellText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#1e293b"),
    )

    cell_header_style = ParagraphStyle(
        "CellHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white,
    )

    story = []

    # Title & Subtitle
    story.append(Paragraph(telemetry["report_title"], title_style))
    date_scope_str = "All Time"
    if telemetry.get("date_from") and telemetry.get("date_to"):
        date_scope_str = f"{telemetry['date_from'][:10]} to {telemetry['date_to'][:10]}"
    elif telemetry.get("date_from"):
        date_scope_str = f"Since {telemetry['date_from'][:10]}"
    
    sub_text = f"Report Scope: {date_scope_str}  |  Generated: {telemetry['generated_at'][:19]} UTC  |  Classification: Amber"
    story.append(Paragraph(sub_text, subtitle_style))

    # KPI Metric Cards (Grid of blocks)
    kpis = telemetry.get("kpi_metrics", [])
    if kpis:
        kpi_cells = []
        chunk_size = 3
        for i in range(0, len(kpis), chunk_size):
            row = []
            for item in kpis[i : i + chunk_size]:
                card_text = (
                    f"<b><font size='14' color='#0284c7'>{item['value']}</font></b><br/>"
                    f"<b><font size='8' color='#1e293b'>{item['label']}</font></b><br/>"
                    f"<font size='7' color='#64748b'>{item['subtitle']}</font>"
                )
                p = Paragraph(card_text, normal_style)
                row.append(p)
            while len(row) < chunk_size:
                row.append(Paragraph("", normal_style))
            kpi_cells.append(row)

        col_w = (letter[0] - 80) / chunk_size
        kpi_table = Table(kpi_cells, colWidths=[col_w] * chunk_size)
        kpi_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(kpi_table)
        story.append(Spacer(1, 12))

    # Sections & Tables
    for section in telemetry.get("sections", []):
        story.append(Paragraph(section["title"], section_heading_style))
        columns = section.get("columns", [])
        raw_rows = section.get("rows", [])

        if not raw_rows:
            story.append(Paragraph("<i>No records found within the specified evaluation scope.</i>", normal_style))
            story.append(Spacer(1, 8))
            continue

        header_row = [Paragraph(col, cell_header_style) for col in columns]
        table_data = [header_row]

        for r in raw_rows:
            row_cells = []
            for val in r:
                text_val = str(val) if val is not None else "—"
                row_cells.append(Paragraph(text_val, cell_style))
            table_data.append(row_cells)

        num_cols = len(columns)
        total_width = letter[0] - 80
        col_width = total_width / num_cols if num_cols > 0 else total_width

        sec_table = Table(table_data, colWidths=[col_width] * num_cols, repeatRows=1)
        sec_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
                    ("TOPPADDING", (0, 0), (-1, 0), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 1), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ]
            )
        )
        story.append(sec_table)
        story.append(Spacer(1, 10))

    # Recommendations / Action Items
    recs = telemetry.get("recommendations", [])
    if recs:
        story.append(Paragraph("Strategic Recommendations & Action Items", section_heading_style))
        rec_items = []
        for i, rec in enumerate(recs, 1):
            p = Paragraph(f"<b>{i}.</b> {rec}", normal_style)
            rec_items.append([p])
        
        rec_table = Table(rec_items, colWidths=[letter[0] - 80])
        rec_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#86efac")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bbf7d0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(rec_table)

    doc.build(story, canvasmaker=NumberedCanvas)
    return os.path.getsize(output_path)


# ============================================================
# CSV GENERATOR
# ============================================================

def generate_report_csv(telemetry: Dict[str, Any], output_path: str) -> int:
    """
    Renders structured CSV report with metadata, KPIs, and tabular sections.
    Returns file size in bytes.
    """
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        # Header Metadata
        writer.writerow(["# CyberDefense XDR Security Report"])
        writer.writerow(["# Report Title", telemetry["report_title"]])
        writer.writerow(["# Report Type", telemetry["report_type"]])
        writer.writerow(["# Generated At", telemetry["generated_at"]])
        writer.writerow(["# Date Scope", f"{telemetry.get('date_from') or 'All Time'} to {telemetry.get('date_to') or 'Present'}"])
        writer.writerow([])

        # KPI Metrics Section
        writer.writerow(["--- KPI METRICS SUMMARY ---"])
        writer.writerow(["Metric Label", "Value", "Subtitle"])
        for kpi in telemetry.get("kpi_metrics", []):
            writer.writerow([kpi["label"], kpi["value"], kpi["subtitle"]])
        writer.writerow([])

        # Tables
        for section in telemetry.get("sections", []):
            writer.writerow([f"--- SECTION: {section['title'].upper()} ---"])
            columns = section.get("columns", [])
            writer.writerow(columns)
            for row in section.get("rows", []):
                writer.writerow(row)
            writer.writerow([])

        # Recommendations
        recs = telemetry.get("recommendations", [])
        if recs:
            writer.writerow(["--- STRATEGIC RECOMMENDATIONS ---"])
            for idx, r in enumerate(recs, 1):
                writer.writerow([f"#{idx}", r])

    return os.path.getsize(output_path)


# ============================================================
# REPORT LIFECYCLE MANAGEMENT
# ============================================================

def create_report(
    report_type: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    file_format: str = "pdf",
    date_range_preset: Optional[str] = None,
    date_from_str: Optional[str] = None,
    date_to_str: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None,
    generated_by: str = "SOC Analyst",
) -> Report:
    """
    Orchestrates full report lifecycle:
    1. Validates inputs & parses date range
    2. Collects live DB telemetry
    3. Generates PDF or CSV file
    4. Persists Report record in PostgreSQL
    """
    if report_type not in REPORT_TYPES:
        raise ValueError(f"Invalid report type: '{report_type}'")

    file_format = file_format.lower().strip()
    if file_format not in ("pdf", "csv"):
        raise ValueError("Unsupported format. Allowed formats are 'pdf' or 'csv'.")

    date_from, date_to = parse_date_range(date_range_preset, date_from_str, date_to_str)
    filters = filters or {}

    report_title = title.strip() if title and title.strip() else f"{REPORT_TYPES[report_type]['name']} - {datetime.utcnow().strftime('%Y-%m-%d')}"
    report_id = generate_report_id()
    file_path = get_safe_report_path(report_id, file_format)

    # Collect telemetry
    telemetry = build_report_telemetry(report_type, date_from, date_to, filters)
    telemetry["report_id"] = report_id
    telemetry["generated_by"] = generated_by

    # Generate Export Artifact
    try:
        if file_format == "pdf":
            file_size = generate_report_pdf(telemetry, file_path)
        else:
            file_size = generate_report_csv(telemetry, file_path)
        status = "completed"
        error_msg = None
    except Exception as e:
        status = "failed"
        file_size = 0
        error_msg = str(e)

    # Persist in DB
    rep = Report(
        report_id=report_id,
        report_type=report_type,
        title=report_title,
        description=description or "",
        format=file_format,
        status=status,
        date_from=date_from,
        date_to=date_to,
        filters=filters,
        summary=telemetry,
        file_path=file_path,
        file_size_bytes=file_size,
        generated_by=generated_by,
        error_message=error_msg,
    )

    db.session.add(rep)
    db.session.commit()

    if status == "failed":
        raise RuntimeError(f"Report artifact generation failed: {error_msg}")

    return rep


def list_reports(
    page: int = 1,
    per_page: int = 20,
    report_type: Optional[str] = None,
    file_format: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves paginated and filtered report history."""
    query = Report.query

    if report_type and report_type != "all":
        query = query.filter(Report.report_type == report_type)

    if file_format and file_format != "all":
        query = query.filter(Report.format == file_format.lower())

    if status and status != "all":
        query = query.filter(Report.status == status.lower())

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            db.or_(
                Report.title.ilike(s),
                Report.report_id.ilike(s),
                Report.generated_by.ilike(s),
            )
        )

    pagination = query.order_by(desc(Report.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return {
        "reports": [r.to_dict() for r in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": pagination.per_page,
    }


def get_report_by_id(report_id: str) -> Optional[Report]:
    """Finds Report record by public report_id."""
    return Report.query.filter_by(report_id=report_id).first()


def delete_report(report_id: str) -> bool:
    """Deletes DB record and underlying physical artifact file."""
    rep = get_report_by_id(report_id)
    if not rep:
        return False

    if rep.file_path and os.path.isfile(rep.file_path):
        try:
            os.remove(rep.file_path)
        except Exception:
            pass

    db.session.delete(rep)
    db.session.commit()
    return True
