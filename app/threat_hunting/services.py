"""
CyberDefense XDR
Threat Hunting Services Layer
Executes cross-module investigation, entity resolution, and chronological timeline
aggregation directly over existing authoritative PostgreSQL records.
"""

import re
import ipaddress
from datetime import datetime, timedelta
import logging
from sqlalchemy import desc, func, or_, and_

from app.extensions import db
from app.assets.models import Asset
from app.alerts.models import Alert
from app.incidents.models import Incident
from app.scanner.models import VulnerabilityFinding
from app.ids.models import NetworkIDSEvent
from app.ids.services import is_diagnostic_event, get_security_alert_sql_filter
from app.siem.models import SiemEvent
from app.detection.models import DetectionEvent, DetectionRule
from app.threatintel.models import IOC, ThreatActor, ThreatCampaign
from app.packet_analysis.models import PacketAnalysis
from app.threat_hunting.models import ThreatHuntQuery

logger = logging.getLogger("cyberdefense.threat_hunting")


# ============================================================================
# 1. Entity Type Detection & Query Parsing
# ============================================================================

def detect_entity_type(query_str):
    """
    Intelligently classifies a search query into an entity type:
    ip, cve, hash, domain, url, alert_id, incident_id, asset_id, rule_id, or general.
    """
    if not query_str:
        return "general"

    q = query_str.strip()

    # Check for IP address
    try:
        ipaddress.ip_address(q)
        return "ip"
    except ValueError:
        pass

    # Check for CVE pattern (e.g. CVE-2024-1234)
    if re.match(r"^CVE-\d{4}-\d{4,}$", q, re.IGNORECASE):
        return "cve"

    # Check for Cryptographic Hashes
    if re.match(r"^[a-fA-F0-9]{32}$", q):
        return "hash"  # MD5
    if re.match(r"^[a-fA-F0-9]{40}$", q):
        return "hash"  # SHA-1
    if re.match(r"^[a-fA-F0-9]{64}$", q):
        return "hash"  # SHA-256

    # Specific XDR Record ID Prefixes
    q_upper = q.upper()
    if q_upper.startswith("ALT-") or q_upper.startswith("ALERT-"):
        return "alert_id"
    if q_upper.startswith("INC-"):
        return "incident_id"
    if q_upper.startswith("AST-"):
        return "asset_id"
    if q_upper.startswith("RULE-") or q_upper.startswith("DET-"):
        return "rule_id"
    if q_upper.startswith("IOC-"):
        return "ioc"

    # URLs
    if q.startswith("http://") or q.startswith("https://"):
        return "url"

    # Hostname / Domain (simple heuristic)
    if "." in q and not q.endswith("."):
        parts = q.split(".")
        if all(len(p) > 0 for p in parts) and len(parts) >= 2:
            return "domain"

    return "general"


def parse_hunt_time_range(range_param=None, start_param=None, end_param=None):
    """
    Validates and bounds search time ranges.
    Defaults to 7 days.
    """
    now = datetime.utcnow()
    range_key = (range_param or "7d").strip().lower()

    if start_param and end_param:
        try:
            s_dt = datetime.strptime(start_param[:10], "%Y-%m-%d")
            e_dt = datetime.strptime(end_param[:10], "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            if s_dt > e_dt:
                s_dt, e_dt = e_dt, s_dt
            # Max bound: 365 days
            if (e_dt - s_dt).days > 365:
                s_dt = e_dt - timedelta(days=365)
            return s_dt, e_dt, "custom"
        except (ValueError, TypeError):
            pass

    if range_key == "24h":
        return now - timedelta(hours=24), now, "24h"
    elif range_key == "30d":
        return now - timedelta(days=30), now, "30d"
    elif range_key == "90d":
        return now - timedelta(days=90), now, "90d"
    elif range_key == "all":
        return now - timedelta(days=365 * 2), now, "all"
    else:
        return now - timedelta(days=7), now, "7d"


# ============================================================================
# 2. Cross-Module Search Engine
# ============================================================================

def execute_hunt(
    query_text,
    search_type=None,
    time_range="7d",
    start_date=None,
    end_date=None,
    severity=None,
    source_module=None,
    page=1,
    limit=50,
):
    """
    Executes a comprehensive, multi-source threat hunt query across authoritative tables.
    Returns partitioned results by module, matches count, and unified timeline items.
    """
    query_text = (query_text or "").strip()
    if not query_text:
        return {
            "success": True,
            "query": "",
            "detected_type": "general",
            "time_range": time_range,
            "total_matches": 0,
            "results_by_module": {},
            "timeline": [],
            "page": page,
            "limit": limit,
        }

    detected_type = search_type or detect_entity_type(query_text)
    start_dt, end_dt, effective_range = parse_hunt_time_range(time_range, start_date, end_date)

    search_term = f"%{query_text}%"
    results = {
        "assets": [],
        "alerts": [],
        "incidents": [],
        "ids_events": [],
        "siem_events": [],
        "detections": [],
        "vulnerabilities": [],
        "iocs": [],
        "packets": [],
    }

    timeline = []

    # ----------------------------------------------------
    # 1. Assets Search
    # ----------------------------------------------------
    if not source_module or source_module in ["assets", "all"]:
        asset_q = Asset.query.filter(
            or_(
                Asset.name.ilike(search_term),
                Asset.ip_address.ilike(search_term),
                Asset.asset_id.ilike(search_term),
                Asset.environment.ilike(search_term),
            )
        )
        for a in asset_q.limit(limit).all():
            rec = {
                "id": a.id,
                "asset_id": a.asset_id,
                "name": a.name,
                "ip_address": a.ip_address,
                "type": a.asset_type,
                "environment": a.environment,
                "criticality": a.criticality,
                "status": a.status,
                "risk_score": a.risk_score,
            }
            results["assets"].append(rec)

    # ----------------------------------------------------
    # 2. Alert Center Search
    # ----------------------------------------------------
    if not source_module or source_module in ["alerts", "all"]:
        alert_q = Alert.query.filter(
            Alert.created_at >= start_dt,
            Alert.created_at <= end_dt,
            or_(
                Alert.title.ilike(search_term),
                Alert.alert_id.ilike(search_term),
                Alert.affected_host.ilike(search_term),
                Alert.affected_asset.ilike(search_term),
                Alert.category.ilike(search_term),
                Alert.source.ilike(search_term),
            ),
        )
        if severity:
            alert_q = alert_q.filter(Alert.severity == severity.lower())

        for al in alert_q.order_by(desc(Alert.created_at)).limit(limit).all():
            rec = {
                "id": al.id,
                "alert_id": al.alert_id,
                "title": al.title,
                "severity": al.severity,
                "status": al.status,
                "affected_host": al.affected_host or al.affected_asset,
                "source": al.source,
                "created_at": al.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if al.created_at else None,
            }
            results["alerts"].append(rec)
            timeline.append({
                "timestamp": al.created_at,
                "timestamp_str": al.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if al.created_at else None,
                "source_module": "Alert Center",
                "event_type": "Alert",
                "severity": al.severity,
                "entity": al.affected_host or al.affected_asset or al.alert_id,
                "title": al.title,
                "record_id": al.alert_id,
                "link": f"/alert-center/?search={al.alert_id}",
                "is_diagnostic": False,
            })

    # ----------------------------------------------------
    # 3. Incident Response Search
    # ----------------------------------------------------
    if not source_module or source_module in ["incidents", "all"]:
        inc_q = Incident.query.filter(
            Incident.created_at >= start_dt,
            Incident.created_at <= end_dt,
            or_(
                Incident.title.ilike(search_term),
                Incident.incident_id.ilike(search_term),
                Incident.category.ilike(search_term),
                Incident.source.ilike(search_term),
            ),
        )
        if severity:
            inc_q = inc_q.filter(Incident.severity == severity.lower())

        for inc in inc_q.order_by(desc(Incident.created_at)).limit(limit).all():
            rec = {
                "id": inc.id,
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "category": inc.category,
                "created_at": inc.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if inc.created_at else None,
            }
            results["incidents"].append(rec)
            timeline.append({
                "timestamp": inc.created_at,
                "timestamp_str": inc.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if inc.created_at else None,
                "source_module": "Incident Response",
                "event_type": "Incident",
                "severity": inc.severity,
                "entity": inc.incident_id,
                "title": inc.title,
                "record_id": inc.incident_id,
                "link": f"/incidents/?id={inc.incident_id}",
                "is_diagnostic": False,
            })

    # ----------------------------------------------------
    # 4. Network IDS / Suricata Search
    # ----------------------------------------------------
    if not source_module or source_module in ["ids", "all"]:
        ids_q = NetworkIDSEvent.query.filter(
            NetworkIDSEvent.timestamp >= start_dt,
            NetworkIDSEvent.timestamp <= end_dt,
            or_(
                NetworkIDSEvent.src_ip.ilike(search_term),
                NetworkIDSEvent.dest_ip.ilike(search_term),
                NetworkIDSEvent.signature.ilike(search_term),
                NetworkIDSEvent.category.ilike(search_term),
            ),
        )
        if severity:
            ids_q = ids_q.filter(NetworkIDSEvent.severity == severity.lower())

        for ev in ids_q.order_by(desc(NetworkIDSEvent.timestamp)).limit(limit).all():
            is_diag = is_diagnostic_event(ev.signature_id, ev.signature)
            rec = {
                "id": ev.id,
                "event_uuid": ev.event_uuid,
                "timestamp": ev.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if ev.timestamp else None,
                "signature": ev.signature,
                "signature_id": ev.signature_id,
                "severity": ev.severity,
                "src_ip": ev.src_ip,
                "dest_ip": ev.dest_ip,
                "protocol": ev.protocol,
                "is_diagnostic": is_diag,
            }
            results["ids_events"].append(rec)
            timeline.append({
                "timestamp": ev.timestamp,
                "timestamp_str": ev.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if ev.timestamp else None,
                "source_module": "Network IDS",
                "event_type": "IDS Checksum Diagnostic" if is_diag else "IDS Alert",
                "severity": "info" if is_diag else ev.severity,
                "entity": f"{ev.src_ip} -> {ev.dest_ip}",
                "title": ev.signature,
                "record_id": ev.event_uuid,
                "link": f"/network-ids/events/{ev.event_uuid}",
                "is_diagnostic": is_diag,
            })

    # ----------------------------------------------------
    # 5. SIEM & Log Explorer Search
    # ----------------------------------------------------
    if not source_module or source_module in ["siem", "all"]:
        siem_q = SiemEvent.query.filter(
            SiemEvent.timestamp >= start_dt,
            SiemEvent.timestamp <= end_dt,
            or_(
                SiemEvent.host.ilike(search_term),
                SiemEvent.source.ilike(search_term),
                SiemEvent.category.ilike(search_term),
                SiemEvent.message.ilike(search_term),
                SiemEvent.raw_log.ilike(search_term),
            ),
        )
        if severity:
            siem_q = siem_q.filter(SiemEvent.severity == severity.lower())

        for s in siem_q.order_by(desc(SiemEvent.timestamp)).limit(limit).all():
            rec = {
                "id": s.id,
                "event_id": s.event_id,
                "timestamp": s.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if s.timestamp else None,
                "source": s.source,
                "host": s.host,
                "severity": s.severity,
                "message": s.message,
            }
            results["siem_events"].append(rec)
            timeline.append({
                "timestamp": s.timestamp,
                "timestamp_str": s.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if s.timestamp else None,
                "source_module": "SIEM",
                "event_type": "SIEM Log",
                "severity": s.severity,
                "entity": s.host or s.source,
                "title": s.message or s.source,
                "record_id": s.event_id,
                "link": f"/log-explorer/?q={s.event_id}",
                "is_diagnostic": False,
            })

    # ----------------------------------------------------
    # 6. Detection Engine Search
    # ----------------------------------------------------
    if not source_module or source_module in ["detection", "all"]:
        det_q = (
            DetectionEvent.query.outerjoin(DetectionRule, DetectionEvent.rule_id == DetectionRule.id)
            .filter(
                DetectionEvent.timestamp >= start_dt,
                DetectionEvent.timestamp <= end_dt,
                or_(
                    DetectionEvent.host.ilike(search_term),
                    DetectionEvent.source.ilike(search_term),
                    DetectionEvent.event_id.ilike(search_term),
                    DetectionRule.name.ilike(search_term),
                    DetectionRule.rule_id.ilike(search_term),
                ),
            )
        )
        if severity:
            det_q = det_q.filter(DetectionEvent.severity == severity.lower())

        for d in det_q.order_by(desc(DetectionEvent.timestamp)).limit(limit).all():
            rule_name = d.rule.name if d.rule else "Detection Event"
            rec = {
                "id": d.id,
                "event_id": d.event_id,
                "timestamp": d.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if d.timestamp else None,
                "source": d.source,
                "host": d.host,
                "severity": d.severity,
                "rule_name": rule_name,
            }
            results["detections"].append(rec)
            timeline.append({
                "timestamp": d.timestamp,
                "timestamp_str": d.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if d.timestamp else None,
                "source_module": "Detection Engine",
                "event_type": "Detection",
                "severity": d.severity,
                "entity": d.host or d.source,
                "title": rule_name,
                "record_id": d.event_id,
                "link": "/detection/dashboard",
                "is_diagnostic": False,
            })

    # ----------------------------------------------------
    # 7. Vulnerability Scanner Findings
    # ----------------------------------------------------
    if not source_module or source_module in ["vulnerabilities", "all"]:
        vuln_q = VulnerabilityFinding.query.filter(
            VulnerabilityFinding.discovered_at >= start_dt,
            VulnerabilityFinding.discovered_at <= end_dt,
            or_(
                VulnerabilityFinding.cve.ilike(search_term),
                VulnerabilityFinding.title.ilike(search_term),
                VulnerabilityFinding.host.ilike(search_term),
            ),
        )
        if severity:
            vuln_q = vuln_q.filter(VulnerabilityFinding.severity == severity.lower())

        for v in vuln_q.order_by(desc(VulnerabilityFinding.discovered_at)).limit(limit).all():
            rec = {
                "id": v.id,
                "cve": v.cve,
                "title": v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "host": v.host,
                "status": v.status,
                "discovered_at": v.discovered_at.strftime("%Y-%m-%dT%H:%M:%SZ") if v.discovered_at else None,
            }
            results["vulnerabilities"].append(rec)
            timeline.append({
                "timestamp": v.discovered_at,
                "timestamp_str": v.discovered_at.strftime("%Y-%m-%dT%H:%M:%SZ") if v.discovered_at else None,
                "source_module": "Vulnerability Scanner",
                "event_type": "Vulnerability Finding",
                "severity": v.severity,
                "entity": v.host or v.cve,
                "title": f"{v.cve}: {v.title}" if v.cve else v.title,
                "record_id": str(v.id),
                "link": "/vuln-scanner/",
                "is_diagnostic": False,
            })

    # ----------------------------------------------------
    # 8. Threat Intelligence IOCs
    # ----------------------------------------------------
    if not source_module or source_module in ["threat_intel", "all"]:
        ioc_q = IOC.query.filter(
            or_(
                IOC.value.ilike(search_term),
                IOC.ioc_id.ilike(search_term),
                IOC.type.ilike(search_term),
                IOC.source.ilike(search_term),
            )
        )
        if severity:
            ioc_q = ioc_q.filter(IOC.threat_level == severity.lower())

        for ioc in ioc_q.limit(limit).all():
            rec = {
                "id": ioc.id,
                "ioc_id": ioc.ioc_id,
                "value": ioc.value,
                "type": ioc.type,
                "threat_level": ioc.threat_level,
                "confidence": ioc.confidence,
                "source": ioc.source,
            }
            results["iocs"].append(rec)
            ts = ioc.first_seen or datetime.utcnow()
            timeline.append({
                "timestamp": ts,
                "timestamp_str": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_module": "Threat Intelligence",
                "event_type": "IOC Match",
                "severity": ioc.threat_level,
                "entity": ioc.value,
                "title": f"IOC ({ioc.type}): {ioc.value}",
                "record_id": ioc.ioc_id,
                "link": f"/threat-intelligence/ioc-feed?q={ioc.ioc_id}",
                "is_diagnostic": False,
            })

    # ----------------------------------------------------
    # 9. Packet Analysis
    # ----------------------------------------------------
    if not source_module or source_module in ["packet_analysis", "all"]:
        pcap_q = PacketAnalysis.query.filter(
            or_(
                PacketAnalysis.filename.ilike(search_term),
                PacketAnalysis.sha256.ilike(search_term),
            )
        )
        for p in pcap_q.limit(limit).all():
            rec = {
                "id": p.id,
                "analysis_uuid": getattr(p, "analysis_uuid", str(p.id)),
                "pcap_filename": p.filename,
                "status": p.status,
                "packet_count": p.packet_count,
            }
            results["packets"].append(rec)

    # Sort unified timeline chronologically descending
    timeline.sort(key=lambda item: item["timestamp"], reverse=True)
    # Remove raw datetime object before JSON serialization
    for it in timeline:
        it.pop("timestamp", None)

    total_matches = sum(len(v) for v in results.values())

    return {
        "success": True,
        "query": query_text,
        "detected_type": detected_type,
        "time_range": effective_range,
        "start_time": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_time": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_matches": total_matches,
        "counts": {k: len(v) for k, v in results.items()},
        "results_by_module": results,
        "timeline": timeline[:limit * 2],
        "page": page,
        "limit": limit,
    }


# ============================================================================
# 3. Entity 360-Degree Profile View
# ============================================================================

def get_entity_profile(entity_type, entity_id):
    """
    Constructs a comprehensive 360-degree security view of an entity:
    all relationships, sightings, alert history, open CVEs, and timeline.
    """
    entity_type = (entity_type or "ip").strip().lower()
    entity_id = (entity_id or "").strip()

    if not entity_id:
        return {"success": False, "error": "Entity identifier is required"}

    # Run broad search over the last 90 days
    hunt_results = execute_hunt(
        query_text=entity_id,
        search_type=entity_type,
        time_range="90d",
        limit=50,
    )

    by_module = hunt_results.get("results_by_module", {})
    timeline = hunt_results.get("timeline", [])

    # Calculate first seen & last seen from timeline
    timestamps = [t["timestamp_str"] for t in timeline if t.get("timestamp_str")]
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None

    # Severity distribution
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in timeline:
        sev = (item.get("severity") or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["info"] += 1

    # Extract associated asset if any
    matched_asset = None
    if by_module.get("assets"):
        matched_asset = by_module["assets"][0]
    else:
        # Check if entity is IP or Hostname matching an asset
        asset_obj = Asset.query.filter(
            or_(Asset.ip_address == entity_id, Asset.name == entity_id, Asset.asset_id == entity_id)
        ).first()
        if asset_obj:
            matched_asset = {
                "id": asset_obj.id,
                "asset_id": asset_obj.asset_id,
                "name": asset_obj.name,
                "ip_address": asset_obj.ip_address,
                "criticality": asset_obj.criticality,
                "risk_score": asset_obj.risk_score,
                "environment": asset_obj.environment,
            }

    # Extract associated IOCs
    matched_ioc = None
    if by_module.get("iocs"):
        matched_ioc = by_module["iocs"][0]
    else:
        ioc_obj = IOC.query.filter(or_(IOC.value == entity_id, IOC.ioc_id == entity_id)).first()
        if ioc_obj:
            matched_ioc = {
                "ioc_id": ioc_obj.ioc_id,
                "value": ioc_obj.value,
                "type": ioc_obj.type,
                "threat_level": ioc_obj.threat_level,
                "confidence": ioc_obj.confidence,
                "source": ioc_obj.source,
            }

    return {
        "success": True,
        "entity": {
            "type": entity_type,
            "id": entity_id,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "total_sightings": hunt_results.get("total_matches", 0),
        },
        "matched_asset": matched_asset,
        "matched_ioc": matched_ioc,
        "severity_distribution": severity_counts,
        "counts": hunt_results.get("counts", {}),
        "alerts": by_module.get("alerts", []),
        "incidents": by_module.get("incidents", []),
        "ids_events": by_module.get("ids_events", []),
        "siem_events": by_module.get("siem_events", []),
        "detections": by_module.get("detections", []),
        "vulnerabilities": by_module.get("vulnerabilities", []),
        "iocs": by_module.get("iocs", []),
        "timeline": timeline,
    }


# ============================================================================
# 4. Summary & Saved Search Management
# ============================================================================

def get_hunting_summary():
    """Returns high-level statistics for the Threat Hunting dashboard."""
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    total_assets = Asset.query.count()
    total_alerts_24h = Alert.query.filter(Alert.created_at >= last_24h).count()
    sec_filter = get_security_alert_sql_filter()
    total_ids_24h = NetworkIDSEvent.query.filter(NetworkIDSEvent.timestamp >= last_24h, sec_filter).count()
    total_siem_24h = SiemEvent.query.filter(SiemEvent.timestamp >= last_24h).count()
    total_iocs = IOC.query.count()

    # Recent queries executed
    recent_queries = [
        q.to_dict()
        for q in ThreatHuntQuery.query.order_by(desc(ThreatHuntQuery.created_at)).limit(6).all()
    ]

    # Saved hunts
    saved_hunts = [
        q.to_dict()
        for q in ThreatHuntQuery.query.filter_by(is_saved=True).order_by(desc(ThreatHuntQuery.created_at)).limit(6).all()
    ]

    return {
        "success": True,
        "stats": {
            "total_assets": total_assets,
            "alerts_24h": total_alerts_24h,
            "ids_threats_24h": total_ids_24h,
            "siem_logs_24h": total_siem_24h,
            "total_iocs": total_iocs,
            "searchable_events_24h": total_alerts_24h + total_ids_24h + total_siem_24h,
        },
        "recent_queries": recent_queries,
        "saved_hunts": saved_hunts,
    }


def record_hunt_query(query_text, entity_type, result_count=0, user_id=None, filters=None, title=None, is_saved=False):
    """Logs or bookmarks an analyst hunt search."""
    import uuid
    import json

    hunt_id = f"HUNT-{uuid.uuid4().hex[:8].upper()}"
    record = ThreatHuntQuery(
        hunt_id=hunt_id,
        title=title or query_text,
        query_text=query_text,
        entity_type=entity_type or "general",
        filters_json=json.dumps(filters or {}),
        result_count=result_count,
        is_saved=is_saved,
        user_id=user_id,
    )
    db.session.add(record)
    db.session.commit()
    return record
