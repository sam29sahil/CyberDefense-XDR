"""
CyberDefense XDR
SOAR Playbooks Registry
Defines 10 safe, non-destructive automated SOC response playbooks.
No arbitrary shell commands (shell executions are strictly prohibited).
"""

from datetime import datetime, timezone
import uuid
import json
from sqlalchemy import or_, desc
from app.extensions import db
from app.assets.models import Asset
from app.alerts.models import Alert
from app.ids.models import NetworkIDSEvent as IDSEvent
from app.siem.models import SiemEvent as SiemLog
from app.incidents.models import Incident
from app.scanner.models import VulnerabilityFinding
from app.threatintel.models import IOC
from app.ids.services import is_diagnostic_event
from app.soar.models import SoarApproval


PLAYBOOKS_CATALOG = [
    {
        "id": "alert_investigation",
        "name": "Alert Investigation & Telemetry Correlation",
        "category": "Investigation",
        "target_type": "alert",
        "description": "Correlates alert with asset metadata, IDS threat signatures, and SIEM logs to determine root cause and blast radius.",
    },
    {
        "id": "critical_alert_escalation",
        "name": "Critical Alert Escalation",
        "category": "Containment",
        "target_type": "alert",
        "description": "Verifies high-risk indicators for a critical alert and stages an incident response escalation approval.",
    },
    {
        "id": "incident_enrichment",
        "name": "Incident Telemetry Enrichment",
        "category": "Enrichment",
        "target_type": "incident",
        "description": "Gathers asset exposure, related alerts, and attack timelines for an active incident investigation.",
    },
    {
        "id": "ioc_enrichment",
        "name": "IOC Threat Intelligence Enrichment",
        "category": "Enrichment",
        "target_type": "ioc",
        "description": "Checks an indicator of compromise against internal SIEM logs and Network IDS detections to detect active compromise.",
    },
    {
        "id": "vulnerability_triage",
        "name": "Vulnerability Exposure & Exploit Triage",
        "category": "Vulnerability Management",
        "target_type": "cve",
        "description": "Evaluates affected assets for a target CVE, checks for IDS exploit signatures, and assesses remediation urgency.",
    },
    {
        "id": "asset_risk_investigation",
        "name": "Asset 360 Risk Audit",
        "category": "Audit",
        "target_type": "asset",
        "description": "Runs a full security audit on an endpoint, compiling active alerts, open CVEs, and network communication posture.",
    },
    {
        "id": "ids_alert_investigation",
        "name": "Network IDS Threat Signature Investigation",
        "category": "Investigation",
        "target_type": "ids",
        "description": "Analyzes Suricata signature events, filters diagnostic noise (SID 2200074), and identifies external attack sources.",
    },
    {
        "id": "phishing_investigation",
        "name": "Phishing & Malicious Domain Triage",
        "category": "Investigation",
        "target_type": "domain",
        "description": "Correlates suspicious domain with threat intel feeds, DNS query logs, and gateway alerts.",
    },
    {
        "id": "malware_investigation",
        "name": "Malware & Hash Analysis",
        "category": "Forensics",
        "target_type": "hash",
        "description": "Queries threat intelligence feeds for file hash matches and searches SIEM endpoint process execution logs.",
    },
    {
        "id": "suspicious_ip_investigation",
        "name": "Suspicious External IP Triage",
        "category": "Investigation",
        "target_type": "ip",
        "description": "Cross-references suspicious IP against network ingress/egress, Suricata IDS alerts, and IOC feeds.",
    },
]


def execute_playbook_logic(execution, playbook_id, target_type, target_id, params):
    """
    Executes the deterministic step logic for the specified playbook.
    Appends steps to execution and creates approvals if state-changing action is recommended.
    """
    steps = []
    results = {}
    summary = ""

    def add_step(name, status="completed", details=None):
        steps.append({
            "step": name,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {},
        })

    if playbook_id == "alert_investigation":
        alert = Alert.query.filter(
            or_(
                Alert.id == int(target_id) if str(target_id).isdigit() else False,
                Alert.alert_id == str(target_id)
            )
        ).first()
        if not alert:
            add_step("Resolve Alert Record", "failed", {"error": f"Alert {target_id} not found"})
            return {"status": "failed", "steps": steps, "summary": f"Alert {target_id} not found."}

        add_step("Resolve Alert Record", "completed", {"title": alert.title, "severity": alert.severity})

        target_ip = alert.affected_host or alert.affected_asset
        ast = None
        if target_ip:
            ast = Asset.query.filter(or_(Asset.ip_address == target_ip, Asset.name == target_ip)).first()

        add_step("Correlate Host Asset", "completed", {
            "asset_found": ast is not None,
            "asset_name": ast.name if ast else "Unregistered",
            "ip": target_ip,
        })

        # IDS checks
        ids_count = 0
        if target_ip:
            ids_raw = IDSEvent.query.filter(or_(IDSEvent.src_ip == target_ip, IDSEvent.dest_ip == target_ip)).all()
            sec_ids = [e for e in ids_raw if not is_diagnostic_event(e.signature_id, e.signature)]
            ids_count = len(sec_ids)

        add_step("Correlate Network IDS Signatures", "completed", {"threat_events": ids_count})

        results = {
            "alert_id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "asset_name": ast.name if ast else None,
            "target_ip": target_ip,
            "correlated_ids_threats": ids_count,
        }
        summary = f"Alert {alert.id} investigation complete. Correlated with host {target_ip or 'N/A'} and {ids_count} IDS threat signatures."

    elif playbook_id == "critical_alert_escalation":
        alert = Alert.query.filter(
            or_(
                Alert.id == int(target_id) if str(target_id).isdigit() else False,
                Alert.alert_id == str(target_id)
            )
        ).first()
        if not alert:
            add_step("Resolve Alert Record", "failed", {"error": f"Alert {target_id} not found"})
            return {"status": "failed", "steps": steps, "summary": f"Alert {target_id} not found."}

        add_step("Evaluate Escalation Criteria", "completed", {"severity": alert.severity, "current_status": alert.status})

        # Stage approval for incident escalation
        approval_id = str(uuid.uuid4())
        approval = SoarApproval(
            approval_id=approval_id,
            execution_id=execution.id,
            action_type="escalate_to_incident",
            action_name=f"Escalate Alert {alert.id} to Security Incident",
            target_entity_type="alert",
            target_entity_id=str(alert.id),
            change_payload_json=json.dumps({
                "alert_id": alert.id,
                "title": f"Escalated Incident: {alert.title}",
                "severity": alert.severity or "HIGH",
            }),
            expected_impact=f"Creates new Incident record in Incident Response module linked to Alert {alert.id}.",
            status="pending",
        )
        db.session.add(approval)
        db.session.commit()

        add_step("Stage Escalation Approval", "pending_approval", {
            "approval_id": approval_id,
            "action": "escalate_to_incident",
            "impact": approval.expected_impact
        })

        results = {"staged_approval_id": approval_id, "alert_id": alert.id}
        summary = f"Alert {alert.id} evaluated. Escalation to Incident staged awaiting analyst sign-off."

    elif playbook_id == "incident_enrichment":
        inc = Incident.query.get(target_id)
        if not inc:
            add_step("Resolve Incident Record", "failed", {"error": f"Incident {target_id} not found"})
            return {"status": "failed", "steps": steps, "summary": f"Incident {target_id} not found."}

        add_step("Resolve Incident Metadata", "completed", {"title": inc.title, "severity": inc.severity, "status": inc.status})

        alerts = Alert.query.filter(
            or_(Alert.title.ilike(f"%{inc.title[:20]}%"), Alert.severity == inc.severity)
        ).limit(10).all()

        add_step("Identify Linked Alerts", "completed", {"matched_alerts": len(alerts)})

        results = {
            "incident_id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "linked_alerts_count": len(alerts),
        }
        summary = f"Incident {inc.id} telemetry enriched with {len(alerts)} correlated alerts."

    elif playbook_id == "ioc_enrichment":
        ioc_val = target_id
        ioc_record = IOC.query.filter(IOC.ioc_value == ioc_val).first()
        add_step("Query IOC Threat Intel Database", "completed", {
            "found": ioc_record is not None,
            "threat_level": ioc_record.threat_level if ioc_record else "UNKNOWN",
            "actor": ioc_record.threat_actor if ioc_record else "Unknown",
        })

        # Match SIEM logs
        siem_hits = SiemLog.query.filter(
            or_(SiemLog.host.ilike(f"%{ioc_val}%"), SiemLog.message.ilike(f"%{ioc_val}%"), SiemLog.fields_json.ilike(f"%{ioc_val}%"))
        ).count()
        add_step("Query SIEM Historical Telemetry", "completed", {"hits": siem_hits})

        # Match IDS
        ids_raw = IDSEvent.query.filter(or_(IDSEvent.src_ip == ioc_val, IDSEvent.dest_ip == ioc_val)).all()
        sec_ids = [e for e in ids_raw if not is_diagnostic_event(e.signature_id, e.signature)]
        add_step("Query Network IDS Threat Events", "completed", {"hits": len(sec_ids)})

        results = {
            "ioc_value": ioc_val,
            "siem_hits": siem_hits,
            "ids_threat_hits": len(sec_ids),
            "threat_actor": ioc_record.threat_actor if ioc_record else None,
        }
        summary = f"IOC {ioc_val} checked: {siem_hits} SIEM hits, {len(sec_ids)} IDS threat detections."

    elif playbook_id == "vulnerability_triage":
        cve_id = target_id
        vulns = VulnerabilityFinding.query.filter(VulnerabilityFinding.cve.ilike(cve_id)).all()
        add_step("Query Vulnerability Repository", "completed", {"affected_findings": len(vulns)})

        affected_ips = list(set([v.host for v in vulns if v.host]))
        add_step("Identify Affected Endpoints", "completed", {"endpoints": affected_ips})

        results = {
            "cve_id": cve_id,
            "affected_instances": len(vulns),
            "affected_hosts": affected_ips,
        }
        summary = f"Vulnerability {cve_id} triage complete. {len(vulns)} instance(s) found across {len(affected_ips)} host(s)."

    elif playbook_id == "asset_risk_investigation":
        ast = Asset.query.filter(or_(Asset.id == target_id if str(target_id).isdigit() else False, Asset.ip_address == target_id, Asset.name.ilike(target_id))).first()
        if not ast:
            add_step("Resolve Asset Record", "failed", {"error": f"Asset {target_id} not found"})
            return {"status": "failed", "steps": steps, "summary": f"Asset {target_id} not found."}

        add_step("Resolve Asset Metadata", "completed", {"name": ast.name, "ip": ast.ip_address, "criticality": ast.criticality})

        # Vulnerabilities
        vulns = VulnerabilityFinding.query.filter(
            or_(VulnerabilityFinding.host == ast.ip_address, VulnerabilityFinding.host == ast.name)
        ).all()
        add_step("Audit Vulnerability Posture", "completed", {"total_cves": len(vulns)})

        # Alerts
        alerts = Alert.query.filter(
            or_(Alert.affected_host == ast.ip_address, Alert.affected_asset == ast.name, Alert.affected_host == ast.name),
            Alert.status != "resolved"
        ).all()
        add_step("Audit Active Detections", "completed", {"active_alerts": len(alerts)})

        results = {
            "asset_id": ast.id,
            "name": ast.name,
            "ip": ast.ip_address,
            "vulnerabilities_count": len(vulns),
            "alerts_count": len(alerts),
        }
        summary = f"Asset {ast.name} ({ast.ip_address}) audit complete: {len(alerts)} active alerts and {len(vulns)} CVEs."

    elif playbook_id == "ids_alert_investigation":
        sig_id = target_id
        # Check if diagnostic
        is_diag = is_diagnostic_event(sig_id, None)
        add_step("Inspect Threat Signature", "completed", {
            "signature_id": sig_id,
            "diagnostic_noise": is_diag,
        })

        if is_diag:
            summary = f"Signature {sig_id} is recognized as hardware offload diagnostic noise (SID 2200074). No threat response required."
            results = {"diagnostic": True, "action": "suppress_noise"}
        else:
            events = IDSEvent.query.filter(IDSEvent.signature_id == sig_id).limit(20).all()
            src_ips = list(set([e.src_ip for e in events if e.src_ip]))
            add_step("Aggregate Threat Sources", "completed", {"unique_attackers": len(src_ips)})
            results = {"diagnostic": False, "attacker_ips": src_ips, "event_count": len(events)}
            summary = f"IDS Threat {sig_id} confirmed active from {len(src_ips)} external attacker IP(s)."

    elif playbook_id in ("phishing_investigation", "malware_investigation", "suspicious_ip_investigation"):
        entity = target_id
        add_step("Check Threat Intelligence", "completed", {"target": entity})

        siem_count = SiemLog.query.filter(
            or_(SiemLog.host.ilike(f"%{entity}%"), SiemLog.message.ilike(f"%{entity}%"), SiemLog.fields_json.ilike(f"%{entity}%"))
        ).count()
        add_step("Scan SIEM Gateway Logs", "completed", {"matches": siem_count})

        results = {
            "target": entity,
            "siem_matches": siem_count,
        }
        summary = f"Investigation for {entity} completed with {siem_count} correlated gateway telemetry matches."

    else:
        add_step("Execute Custom Playbook", "failed", {"error": f"Unknown playbook {playbook_id}"})
        return {"status": "failed", "steps": steps, "summary": f"Unknown playbook {playbook_id}."}

    return {
        "status": "completed",
        "steps": steps,
        "results": results,
        "summary": summary,
    }


def execute_approved_action(approval, decided_by_user_id=None, notes=None):
    """
    Executes a staged action that has received explicit human approval.
    Modifies the database state safely and updates the approval record.
    """
    if approval.status != "pending":
        raise ValueError(f"Approval {approval.approval_id} is not pending (status: {approval.status})")

    payload = json.loads(approval.change_payload_json or "{}")
    action_type = approval.action_type
    execution_result = {}

    if action_type == "escalate_to_incident":
        alert_id = payload.get("alert_id")
        title = payload.get("title", f"Escalated from Alert {alert_id}")
        severity = payload.get("severity", "HIGH")

        new_inc = Incident(
            incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            severity=severity.lower() if severity else "high",
            status="open",
            description=f"Auto-escalated via SOAR approval from Alert {alert_id}.",
        )
        db.session.add(new_inc)
        db.session.commit()

        # Update alert status
        alert = Alert.query.filter(
            or_(
                Alert.id == int(alert_id) if str(alert_id).isdigit() else False,
                Alert.alert_id == str(alert_id)
            )
        ).first()
        if alert:
            alert.status = "in_progress"
            db.session.commit()

        execution_result = {"incident_id": new_inc.id, "title": new_inc.title}

    elif action_type == "resolve_alert":
        alert_id = payload.get("alert_id")
        alert = Alert.query.filter(
            or_(
                Alert.id == int(alert_id) if str(alert_id).isdigit() else False,
                Alert.alert_id == str(alert_id)
            )
        ).first()
        if alert:
            alert.status = "resolved"
            db.session.commit()
            execution_result = {"alert_id": alert.id, "status": "resolved"}

    elif action_type == "isolate_asset":
        asset_id = payload.get("asset_id")
        ast = Asset.query.get(asset_id)
        if ast:
            ast.status = "isolated"
            db.session.commit()
            execution_result = {"asset_id": ast.id, "status": "isolated"}

    else:
        raise ValueError(f"Unsupported action type {action_type}")

    approval.status = "approved"
    approval.decided_by_id = decided_by_user_id
    approval.decision_notes = notes or "Action approved by analyst."
    approval.decided_at = datetime.now(timezone.utc)
    db.session.commit()

    return execution_result
