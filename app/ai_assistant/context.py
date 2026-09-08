"""
CyberDefense XDR
AI Security Assistant Context Ingestion
Extracts relevant telemetry, assets, alerts, vulnerabilities, and IOCs from
the database and packages them into sanitized, bounded prompt context.
"""

import re
from sqlalchemy import or_, desc
from app.assets.models import Asset
from app.alerts.models import Alert
from app.ids.models import NetworkIDSEvent as IDSEvent
from app.siem.models import SiemEvent as SiemLog
from app.scanner.models import VulnerabilityFinding
from app.threatintel.models import IOC
from app.ids.services import is_diagnostic_event
from app.ai_assistant.security import wrap_untrusted_data, scrub_secrets


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_REGEX = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")
ALERT_REGEX = re.compile(r"(?i)\b(?:ALT|ALERT)-[a-zA-Z0-9-]+\b")


def extract_entities_from_text(text: str):
    """Detects IPs, CVEs, and Alert IDs from user text."""
    ips = IP_REGEX.findall(text)
    cves = CVE_REGEX.findall(text)
    alerts = ALERT_REGEX.findall(text)
    return {
        "ips": list(set(ips)),
        "cves": [c.upper() for c in set(cves)],
        "alerts": list(set(alerts)),
    }


def gather_security_context(user_query: str) -> dict:
    """
    Gathers bounded real database context relevant to user query.
    Returns structured dict with raw elements and formatted prompt string.
    """
    entities = extract_entities_from_text(user_query)
    context_lines = []
    evidence = {
        "assets": [],
        "alerts": [],
        "ids_events": [],
        "vulns": [],
        "iocs": [],
    }

    # 1. IP Context
    for ip in entities["ips"][:3]:  # Bound to top 3 IPs
        # Asset
        ast = Asset.query.filter(Asset.ip_address == ip).first()
        if ast:
            evidence["assets"].append({
                "id": ast.id,
                "name": ast.name,
                "ip": ast.ip_address,
                "criticality": ast.criticality,
                "status": ast.status,
            })
            context_lines.append(f"Asset: {ast.name} (IP: {ast.ip_address}, Criticality: {ast.criticality}, OS: {ast.os_type})")

        # Active Alerts
        alerts = Alert.query.filter(
            or_(
                Alert.affected_host == ip,
                Alert.affected_asset == ip,
                Alert.affected_host.ilike(f"%{ip}%"),
                Alert.metadata_json.ilike(f"%{ip}%"),
            )
        ).order_by(desc(Alert.created_at)).limit(5).all()
        for a in alerts:
            evidence["alerts"].append({"id": a.id, "title": a.title, "severity": a.severity, "status": a.status})
            context_lines.append(f"Alert [{a.severity}]: {a.title} (Host: {a.affected_host or a.affected_asset or '-'}, Status: {a.status})")

        # IDS Events (ignoring diagnostic noise)
        ids_raw = IDSEvent.query.filter(
            or_(IDSEvent.src_ip == ip, IDSEvent.dest_ip == ip)
        ).order_by(desc(IDSEvent.timestamp)).limit(5).all()
        for ev in ids_raw:
            if not is_diagnostic_event(ev.signature_id, ev.signature):
                evidence["ids_events"].append({"sid": ev.signature_id, "signature": ev.signature, "severity": ev.severity})
                context_lines.append(f"Network IDS Threat [{ev.severity}]: {ev.signature} (Src: {ev.src_ip}, Dst: {ev.dest_ip})")

        # Vulnerabilities
        vulns = VulnerabilityFinding.query.filter(
            or_(VulnerabilityFinding.host == ip, VulnerabilityFinding.host.ilike(f"%{ip}%"))
        ).order_by(desc(VulnerabilityFinding.id)).limit(5).all()
        for v in vulns:
            cve_val = getattr(v, "cve", "CVE")
            evidence["vulns"].append({"cve": cve_val, "title": v.title, "severity": v.severity, "cvss": v.cvss_score})
            context_lines.append(f"Vulnerability [{v.severity} / CVSS {v.cvss_score}]: {cve_val} - {v.title}")

        # Threat Intel
        iocs = IOC.query.filter(IOC.value == ip).all()
        for i in iocs:
            ioc_val = getattr(i, "value", ip)
            evidence["iocs"].append({"value": ioc_val, "threat_level": i.threat_level, "actor": getattr(i, "source", "Threat Feed")})
            context_lines.append(f"Threat Intel IOC [{i.threat_level}]: {ioc_val} (Source: {getattr(i, 'source', 'Unknown')})")

    # 2. CVE Context
    for cve in entities["cves"][:3]:
        vulns = VulnerabilityFinding.query.filter(VulnerabilityFinding.cve.ilike(cve)).limit(5).all()
        for v in vulns:
            cve_val = getattr(v, "cve", cve)
            evidence["vulns"].append({"cve": cve_val, "title": v.title, "severity": v.severity, "target_ip": v.host})
            context_lines.append(f"Vulnerability {cve_val}: {v.title} on host {v.host} (Severity: {v.severity})")

    # 3. Alert ID Context
    for alt_id in entities["alerts"][:3]:
        a = Alert.query.filter(
            or_(
                Alert.id == int(alt_id) if str(alt_id).isdigit() else False,
                Alert.alert_id == str(alt_id)
            )
        ).first()
        if a:
            evidence["alerts"].append({"id": a.id, "title": a.title, "severity": a.severity, "description": a.description})
            context_lines.append(f"Alert {a.alert_id}: {a.title} (Severity: {a.severity}, Host: {a.affected_host or a.affected_asset or '-'}, Desc: {a.description})")

    # Fallback if no specific entity: pull top 3 active critical/high alerts
    if not context_lines:
        top_alerts = Alert.query.filter(
            Alert.severity.in_(["CRITICAL", "HIGH"]),
            Alert.status != "resolved"
        ).order_by(desc(Alert.created_at)).limit(3).all()
        for a in top_alerts:
            evidence["alerts"].append({"id": a.id, "title": a.title, "severity": a.severity})
            context_lines.append(f"Active System Alert [{a.severity}]: {a.title} (Src: {a.source_ip}, Dst: {a.dest_ip})")

    formatted_raw = "\n".join(context_lines) if context_lines else "No specific database security telemetry found matching the query."
    wrapped_prompt = wrap_untrusted_data(formatted_raw, label="xdr_telemetry_context")

    return {
        "evidence": evidence,
        "raw_text": formatted_raw,
        "wrapped_context": wrapped_prompt,
    }
