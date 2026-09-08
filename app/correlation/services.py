"""
CyberDefense XDR
Correlation Engine Services
Discovers multidirectional relationships between assets, telemetry, detections,
IOCs, and incidents; computes deterministic 0-100 risk scores with itemized rationale;
and generates graph payloads (nodes & links).
"""

from datetime import datetime, timezone
from sqlalchemy import or_, and_, desc
from app.extensions import db
from app.assets.models import Asset
from app.alerts.models import Alert
from app.ids.models import NetworkIDSEvent as IDSEvent
from app.siem.models import SiemEvent as SiemLog
from app.incidents.models import Incident
from app.scanner.models import VulnerabilityFinding
from app.threatintel.models import IOC
from app.ids.services import is_diagnostic_event


def calculate_risk_score(asset=None, alerts=None, ids_events=None, vulns=None, iocs=None, incidents=None):
    """
    Computes a deterministic 0-100 risk score with an explicit list of contributing reasons.
    Diagnostic IDS events (SID 2200074) are strictly ignored and never inflate risk.
    """
    score = 0
    reasons = []

    alerts = alerts or []
    ids_events = ids_events or []
    vulns = vulns or []
    iocs = iocs or []
    incidents = incidents or []

    # 1. Active Alerts
    crit_alerts = [a for a in alerts if str(getattr(a, "severity", "")).upper() == "CRITICAL" and getattr(a, "status", "").lower() != "resolved"]
    high_alerts = [a for a in alerts if str(getattr(a, "severity", "")).upper() == "HIGH" and getattr(a, "status", "").lower() != "resolved"]
    med_alerts = [a for a in alerts if str(getattr(a, "severity", "")).upper() in ("MEDIUM", "MED") and getattr(a, "status", "").lower() != "resolved"]

    if crit_alerts:
        points = min(50, len(crit_alerts) * 25)
        score += points
        reasons.append(f"{len(crit_alerts)} active CRITICAL alert(s) detected (+{points})")

    if high_alerts:
        points = min(30, len(high_alerts) * 15)
        score += points
        reasons.append(f"{len(high_alerts)} active HIGH alert(s) detected (+{points})")

    if med_alerts:
        points = min(15, len(med_alerts) * 5)
        score += points
        reasons.append(f"{len(med_alerts)} active MEDIUM alert(s) detected (+{points})")

    # 2. Network IDS (Filter out diagnostic events)
    sec_ids_events = []
    for ev in ids_events:
        sig_id = getattr(ev, "signature_id", None)
        sig = getattr(ev, "signature", None)
        if not is_diagnostic_event(sig_id, sig):
            sec_ids_events.append(ev)

    if sec_ids_events:
        crit_ids = [e for e in sec_ids_events if str(getattr(e, "severity", "")).upper() in ("1", "CRITICAL", "HIGH")]
        if crit_ids:
            score += 20
            reasons.append(f"{len(crit_ids)} high-severity Network IDS threat signature(s) triggered (+20)")
        else:
            score += 10
            reasons.append(f"{len(sec_ids_events)} Network IDS detection event(s) recorded (+10)")

    # 3. Vulnerability Findings
    crit_vulns = [v for v in vulns if str(getattr(v, "severity", "")).upper() == "CRITICAL"]
    high_vulns = [v for v in vulns if str(getattr(v, "severity", "")).upper() == "HIGH"]

    if crit_vulns:
        points = min(30, len(crit_vulns) * 15)
        score += points
        reasons.append(f"{len(crit_vulns)} unmitigated CRITICAL CVE(s) present (+{points})")
    elif high_vulns:
        points = min(20, len(high_vulns) * 10)
        score += points
        reasons.append(f"{len(high_vulns)} unmitigated HIGH CVE(s) present (+{points})")

    # 4. Threat Intel IOC Matches
    active_iocs = [i for i in iocs if getattr(i, "is_active", True) is not False]
    if active_iocs:
        crit_iocs = [i for i in active_iocs if str(getattr(i, "threat_level", "")).upper() in ("CRITICAL", "HIGH")]
        if crit_iocs:
            score += 25
            reasons.append(f"Correlated with {len(crit_iocs)} known high-threat IOC(s) / threat actors (+25)")
        else:
            score += 15
            reasons.append(f"Correlated with {len(active_iocs)} threat intelligence IOC(s) (+15)")

    # 5. Active Incidents
    open_incidents = [i for i in incidents if str(getattr(i, "status", "")).lower() not in ("closed", "resolved")]
    if open_incidents:
        score += 20
        reasons.append(f"Subject of {len(open_incidents)} active security incident investigation(s) (+20)")

    # 6. Asset Criticality Boost
    if asset:
        crit_level = str(getattr(asset, "criticality", "")).upper()
        if crit_level == "CRITICAL":
            score += 15
            reasons.append("High-value target: designated CRITICAL infrastructure asset (+15)")
        elif crit_level == "HIGH":
            score += 10
            reasons.append("High-value target: designated HIGH priority asset (+10)")

    # 7. Multi-vector Correlation Synergy
    vectors = 0
    if len(alerts) > 0:
        vectors += 1
    if len(sec_ids_events) > 0:
        vectors += 1
    if len(vulns) > 0:
        vectors += 1
    if len(active_iocs) > 0:
        vectors += 1

    if vectors >= 3:
        score += 15
        reasons.append(f"Multi-vector cross-correlation detected across {vectors} distinct security layers (+15)")
    elif vectors >= 2:
        score += 10
        reasons.append(f"Cross-layer correlation detected across {vectors} security layers (+10)")

    # Bound 0-100
    score = min(100, max(0, score))

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "CLEAN"
        reasons.append("No active security alerts, unpatched critical vulnerabilities, or malicious telemetry found.")

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }


def correlate_entity(entity_type, entity_id):
    """
    Discovers all cross-module relationships for an entity (ip, asset, alert, incident, cve, ioc)
    and computes the correlation risk profile, related objects, and graph data.
    """
    entity_type = (entity_type or "").lower().strip()
    entity_id = (str(entity_id) or "").strip()

    related = {
        "asset": None,
        "alerts": [],
        "ids_events": [],
        "siem_logs": [],
        "incidents": [],
        "vulnerabilities": [],
        "threat_intel": [],
    }

    target_ip = None
    target_asset = None

    # Resolve primary subject
    if entity_type == "asset":
        target_asset = Asset.query.filter(
            or_(Asset.id == entity_id, Asset.name.ilike(entity_id), Asset.ip_address == entity_id)
        ).first()
        if target_asset:
            target_ip = target_asset.ip_address
            related["asset"] = target_asset
    elif entity_type in ("ip", "ip_address"):
        target_ip = entity_id
        target_asset = Asset.query.filter(Asset.ip_address == target_ip).first()
        if target_asset:
            related["asset"] = target_asset
    elif entity_type == "alert":
        alert = Alert.query.filter(
            or_(
                Alert.id == int(entity_id) if str(entity_id).isdigit() else False,
                Alert.alert_id == str(entity_id)
            )
        ).first()
        if alert:
            related["alerts"].append(alert)
            target_ip = alert.affected_host or alert.affected_asset
            if target_ip:
                target_asset = Asset.query.filter(or_(Asset.ip_address == target_ip, Asset.name == target_ip)).first()
                if target_asset:
                    related["asset"] = target_asset
    elif entity_type == "incident":
        inc = Incident.query.get(entity_id)
        if inc:
            related["incidents"].append(inc)
    elif entity_type == "cve":
        v_list = VulnerabilityFinding.query.filter(VulnerabilityFinding.cve.ilike(entity_id)).all()
        related["vulnerabilities"].extend(v_list)
        if v_list and v_list[0].host:
            target_ip = v_list[0].host
            target_asset = Asset.query.filter(Asset.ip_address == target_ip).first()
            related["asset"] = target_asset
    elif entity_type in ("ioc", "hash", "domain"):
        i_list = IOC.query.filter(IOC.value.ilike(entity_id)).all()
        related["threat_intel"].extend(i_list)
        target_ip = entity_id

    # If we have a target IP, aggregate all related models
    if target_ip:
        # Alerts
        alerts = Alert.query.filter(
            or_(
                Alert.affected_host == target_ip,
                Alert.affected_asset == target_ip,
                Alert.affected_host.ilike(f"%{target_ip}%"),
                Alert.metadata_json.ilike(f"%{target_ip}%"),
            )
        ).order_by(desc(Alert.created_at)).limit(50).all()
        for a in alerts:
            if a not in related["alerts"]:
                related["alerts"].append(a)

        # IDS Events (filter diagnostic)
        ids_raw = IDSEvent.query.filter(
            or_(IDSEvent.src_ip == target_ip, IDSEvent.dest_ip == target_ip)
        ).order_by(desc(IDSEvent.timestamp)).limit(50).all()
        for ev in ids_raw:
            if not is_diagnostic_event(ev.signature_id, ev.signature):
                related["ids_events"].append(ev)

        # SIEM Logs
        siem_logs = SiemLog.query.filter(
            or_(SiemLog.host.ilike(f"%{target_ip}%"), SiemLog.message.ilike(f"%{target_ip}%"), SiemLog.fields_json.ilike(f"%{target_ip}%"))
        ).order_by(desc(SiemLog.timestamp)).limit(50).all()
        related["siem_logs"].extend(siem_logs)

        # Vulnerabilities
        vulns = VulnerabilityFinding.query.filter(
            or_(VulnerabilityFinding.host == target_ip, VulnerabilityFinding.host.ilike(f"%{target_ip}%"))
        ).order_by(desc(VulnerabilityFinding.id)).limit(50).all()
        for v in vulns:
            if v not in related["vulnerabilities"]:
                related["vulnerabilities"].append(v)

        # Threat Intel
        iocs = IOC.query.filter(IOC.value == target_ip).all()
        for i in iocs:
            if i not in related["threat_intel"]:
                related["threat_intel"].append(i)

    # If we have an asset with an ID, check direct relationships
    if target_asset:
        asset_vulns = VulnerabilityFinding.query.filter(
            or_(
                VulnerabilityFinding.host == target_asset.ip_address,
                VulnerabilityFinding.host == target_asset.name,
            )
        ).all()
        for v in asset_vulns:
            if v not in related["vulnerabilities"]:
                related["vulnerabilities"].append(v)

        asset_alerts = Alert.query.filter(
            or_(
                Alert.affected_host == target_asset.name,
                Alert.affected_asset == target_asset.name,
                Alert.affected_host == target_asset.ip_address,
            )
        ).all()
        for a in asset_alerts:
            if a not in related["alerts"]:
                related["alerts"].append(a)

    # Compute deterministic risk score
    risk = calculate_risk_score(
        asset=related["asset"],
        alerts=related["alerts"],
        ids_events=related["ids_events"],
        vulns=related["vulnerabilities"],
        iocs=related["threat_intel"],
        incidents=related["incidents"],
    )

    # Build graph representation (nodes & links)
    graph = build_correlation_graph(
        primary_entity={"type": entity_type, "id": entity_id, "ip": target_ip},
        asset=related["asset"],
        alerts=related["alerts"],
        ids_events=related["ids_events"],
        siem_logs=related["siem_logs"],
        vulns=related["vulnerabilities"],
        iocs=related["threat_intel"],
        incidents=related["incidents"],
    )

    return {
        "entity": {
            "type": entity_type,
            "id": entity_id,
            "resolved_ip": target_ip,
        },
        "risk": risk,
        "counts": {
            "alerts": len(related["alerts"]),
            "ids_events": len(related["ids_events"]),
            "siem_logs": len(related["siem_logs"]),
            "incidents": len(related["incidents"]),
            "vulnerabilities": len(related["vulnerabilities"]),
            "threat_intel": len(related["threat_intel"]),
        },
        "details": {
            "asset": _serialize_asset(related["asset"]) if related["asset"] else None,
            "alerts": [_serialize_alert(a) for a in related["alerts"][:25]],
            "ids_events": [_serialize_ids(e) for e in related["ids_events"][:25]],
            "siem_logs": [_serialize_siem(s) for s in related["siem_logs"][:25]],
            "incidents": [_serialize_incident(i) for i in related["incidents"][:25]],
            "vulnerabilities": [_serialize_vuln(v) for v in related["vulnerabilities"][:25]],
            "threat_intel": [_serialize_ioc(i) for i in related["threat_intel"][:25]],
        },
        "graph": graph,
    }


def build_correlation_graph(primary_entity, asset=None, alerts=None, ids_events=None, siem_logs=None, vulns=None, iocs=None, incidents=None):
    """
    Constructs a D3/vis-compatible { nodes: [...], links: [...] } network representation.
    """
    nodes = []
    links = []
    node_ids = set()

    def add_node(n_id, label, n_type, severity="INFO", meta=None):
        if n_id not in node_ids:
            nodes.append({
                "id": str(n_id),
                "label": str(label),
                "type": n_type,
                "severity": str(severity).upper(),
                "metadata": meta or {},
            })
            node_ids.add(n_id)

    def add_link(source_id, target_id, rel, weight=1):
        if source_id in node_ids and target_id in node_ids and source_id != target_id:
            links.append({
                "source": str(source_id),
                "target": str(target_id),
                "relationship": rel,
                "weight": weight,
            })

    # Root Node
    root_id = f"entity:{primary_entity.get('type')}:{primary_entity.get('id')}"
    add_node(
        root_id,
        primary_entity.get("id") or "Target",
        primary_entity.get("type", "target"),
        severity="CRITICAL",
        meta={"primary": True, "ip": primary_entity.get("resolved_ip")}
    )

    # Asset Node
    asset_id_node = None
    if asset:
        asset_id_node = f"asset:{asset.id}"
        add_node(
            asset_id_node,
            asset.name or asset.hostname or f"Asset-{asset.id}",
            "asset",
            severity=getattr(asset, "criticality", "MEDIUM"),
            meta={"ip": asset.ip_address, "status": asset.status}
        )
        add_link(root_id, asset_id_node, "hosts", weight=3)

    # Connect Alerts
    for a in (alerts or [])[:15]:
        a_id = f"alert:{a.id}"
        add_node(a_id, a.title[:30] + "...", "alert", severity=a.severity, meta={"id": a.id})
        target = asset_id_node if asset_id_node else root_id
        add_link(a_id, target, "detected_on", weight=2)

    # Connect IDS Events
    for e in (ids_events or [])[:10]:
        e_id = f"ids:{e.id}"
        sig = e.signature or f"SID-{e.signature_id}"
        add_node(e_id, sig[:30], "ids", severity=e.severity or "HIGH", meta={"sid": e.signature_id})
        target = asset_id_node if asset_id_node else root_id
        add_link(e_id, target, "attacks", weight=2)

    # Connect Vulnerabilities
    for v in (vulns or [])[:10]:
        v_id = f"vuln:{v.id}"
        cve_label = getattr(v, "cve", None) or getattr(v, "cve_id", "CVE")
        add_node(v_id, cve_label, "vulnerability", severity=v.severity, meta={"cvss": v.cvss_score})
        target = asset_id_node if asset_id_node else root_id
        add_link(v_id, target, "affects", weight=3)

    # Connect IOCs
    for i in (iocs or [])[:10]:
        i_id = f"ioc:{i.id}"
        ioc_t = getattr(i, "type", None) or getattr(i, "ioc_type", "IOC")
        ioc_v = getattr(i, "value", None) or getattr(i, "ioc_value", "")
        add_node(i_id, f"{ioc_t}: {ioc_v}", "ioc", severity=i.threat_level or "HIGH", meta={"actor": getattr(i, "source", None) or getattr(i, "threat_actor", "Unknown")})
        add_link(i_id, root_id, "matches_ioc", weight=3)

    # Connect Incidents
    for inc in (incidents or [])[:5]:
        inc_id = f"incident:{inc.id}"
        add_node(inc_id, inc.title[:25], "incident", severity=inc.severity, meta={"id": inc.id, "status": inc.status})
        target = asset_id_node if asset_id_node else root_id
        add_link(inc_id, target, "escalated_to", weight=4)

    return {
        "nodes": nodes,
        "links": links,
    }


def find_campaigns():
    """
    Identifies multi-target and multi-vector campaigns across existing telemetry:
    1. Attacker IPs targeting 2+ distinct internal assets
    2. Assets attacked by 2+ distinct attack types (IDS + Alert + Vuln)
    """
    campaigns = []

    # 1. Multi-target attacker detection
    # Group IDS events by src_ip attacking distinct dest_ips
    src_query = db.session.query(
        IDSEvent.src_ip,
        db.func.count(db.func.distinct(IDSEvent.dest_ip)).label("targets_count"),
        db.func.count(IDSEvent.id).label("total_events")
    ).filter(
        IDSEvent.src_ip.isnot(None),
        IDSEvent.dest_ip.isnot(None)
    ).group_by(IDSEvent.src_ip).having(db.func.count(db.func.distinct(IDSEvent.dest_ip)) >= 2).all()

    for row in src_query:
        attacker_ip = row[0]
        # Ignore diagnostic noise
        evs = IDSEvent.query.filter(IDSEvent.src_ip == attacker_ip).limit(10).all()
        sec_evs = [e for e in evs if not is_diagnostic_event(e.signature_id, e.signature)]
        if sec_evs:
            campaigns.append({
                "type": "multi_target_attack",
                "title": f"Coordinated Multi-Target Attack from {attacker_ip}",
                "entity": attacker_ip,
                "targets_count": row[1],
                "event_count": row[2],
                "severity": "HIGH",
                "confidence": 85,
                "description": f"IP {attacker_ip} has initiated exploits against {row[1]} distinct network hosts.",
            })

    # 2. Multi-vector target detection
    # Find assets having both unpatched critical vulns and active alerts
    assets = Asset.query.all()
    for a in assets:
        if not a.ip_address:
            continue
        alerts_count = Alert.query.filter(
            or_(
                Alert.affected_host == a.ip_address,
                Alert.affected_asset == a.name,
                Alert.affected_host == a.name,
            ),
            Alert.status != "resolved",
        ).count()
        vulns_count = VulnerabilityFinding.query.filter(
            or_(VulnerabilityFinding.target_ip == a.ip_address, VulnerabilityFinding.asset_id == a.id),
            VulnerabilityFinding.severity.in_(["CRITICAL", "HIGH"])
        ).count()

        if alerts_count >= 1 and vulns_count >= 1:
            campaigns.append({
                "type": "multi_vector_compromise",
                "title": f"High Exposure: Vulnerability Exploitation on {a.name or a.ip_address}",
                "entity": a.ip_address,
                "asset_id": a.id,
                "alerts_count": alerts_count,
                "vulns_count": vulns_count,
                "severity": "CRITICAL" if vulns_count >= 2 else "HIGH",
                "confidence": 90,
                "description": f"Asset {a.name} ({a.ip_address}) has {vulns_count} active critical/high vulnerabilities alongside {alerts_count} active security alert detections.",
            })

    return campaigns


# Serialization helpers
def _serialize_asset(a):
    return {
        "id": a.id,
        "name": a.name or a.hostname,
        "ip_address": a.ip_address,
        "mac_address": a.mac_address,
        "os_type": a.os_type,
        "criticality": a.criticality,
        "status": a.status,
    }


def _serialize_alert(a):
    return {
        "id": a.id,
        "alert_id": getattr(a, "alert_id", str(a.id)),
        "title": a.title,
        "severity": a.severity,
        "status": a.status,
        "source_ip": getattr(a, "source", "-"),
        "dest_ip": getattr(a, "affected_host", "-") or getattr(a, "affected_asset", "-"),
        "created_at": a.created_at.isoformat() if getattr(a, "created_at", None) else None,
    }


def _serialize_ids(e):
    return {
        "id": e.id,
        "signature_id": e.signature_id,
        "signature": e.signature,
        "severity": e.severity,
        "src_ip": e.src_ip,
        "dest_ip": e.dest_ip,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
    }


def _serialize_siem(s):
    return {
        "id": s.id,
        "source_type": getattr(s, "source", "SYSLOG"),
        "host": getattr(s, "host", "-"),
        "src_ip": getattr(s, "src_ip", "-"),
        "dest_ip": getattr(s, "dest_ip", "-"),
        "message": getattr(s, "message", ""),
        "timestamp": s.timestamp.isoformat() if getattr(s, "timestamp", None) else None,
    }


def _serialize_incident(i):
    return {
        "id": i.id,
        "title": i.title,
        "severity": i.severity,
        "status": i.status,
        "assigned_to": i.assigned_to,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }


def _serialize_vuln(v):
    return {
        "id": v.id,
        "cve_id": getattr(v, "cve", None) or getattr(v, "cve_id", "CVE"),
        "title": getattr(v, "title", "Vulnerability"),
        "severity": getattr(v, "severity", "medium"),
        "cvss_score": getattr(v, "cvss_score", 0.0),
        "target_ip": getattr(v, "host", "-") or getattr(v, "target_ip", "-"),
    }


def _serialize_ioc(i):
    return {
        "id": i.id,
        "ioc_type": getattr(i, "type", None) or getattr(i, "ioc_type", "IOC"),
        "ioc_value": getattr(i, "value", None) or getattr(i, "ioc_value", ""),
        "threat_level": getattr(i, "threat_level", "medium"),
        "threat_actor": getattr(i, "source", None) or getattr(i, "threat_actor", "Threat Intel Feed"),
        "is_active": getattr(i, "is_active", True),
    }
