"""
CyberDefense XDR
Asset Management Services
Provides business logic for asset inventory, validation, dynamic risk calculation,
and cross-module correlation with Vulnerability Scanner, Alert Center, Incidents, SIEM, and IDS.
"""

import ipaddress
import logging
import re
from datetime import datetime, timedelta

from app.extensions import db
from app.assets.models import Asset, generate_asset_id

logger = logging.getLogger(__name__)

# Valid choices for enums
VALID_ASSET_TYPES = {
    "Server", "Database", "Workstation", "Firewall", "Router",
    "Domain Controller", "Mail Gateway", "Container Host",
    "Load Balancer", "Cloud Instance", "Network Device", "IoT/OT Device", "Other"
}

VALID_ENVIRONMENTS = {
    "Production", "Staging", "Development", "Testing", "DMZ", "Internal", "External", "Other"
}

VALID_CRITICALITIES = {"critical", "high", "medium", "low"}
VALID_STATUSES = {"online", "offline", "decommissioned", "maintenance"}

MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


# ==============================================================================
# Validation Helpers
# ==============================================================================

def validate_ip_address(ip_str):
    """Validates IPv4 or IPv6 address string. Returns cleaned string or None if invalid/empty."""
    if not ip_str or not str(ip_str).strip():
        return None
    cleaned = str(ip_str).strip()
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except (ValueError, AttributeError):
        return None


def validate_mac_address(mac_str):
    """Validates MAC address string format. Returns normalized string or None if invalid/empty."""
    if not mac_str or not str(mac_str).strip():
        return None
    cleaned = str(mac_str).strip()
    if not MAC_PATTERN.match(cleaned):
        return None
    return cleaned.upper()


def sanitize_string(val, max_len=255, default=None):
    """Cleans text fields and enforces length boundaries."""
    if val is None:
        return default
    s = str(val).strip()
    return s[:max_len] if s else default


ENV_MAP = {e.lower(): e for e in VALID_ENVIRONMENTS}
TYPE_MAP = {t.lower(): t for t in VALID_ASSET_TYPES}


# ==============================================================================
# Asset CRUD Operations
# ==============================================================================

def create_asset(data):
    """
    Creates and persists a new Asset record with server-side validation.
    Computes initial risk score and logs to SIEM.
    """
    if not data or not isinstance(data, dict):
        raise ValueError("Invalid asset payload.")

    name = sanitize_string(data.get("name"), max_len=128)
    if not name:
        raise ValueError("Asset 'name' is required.")

    # Unique name or asset_id check
    existing_name = Asset.query.filter(db.func.lower(Asset.name) == name.lower()).first()
    if existing_name:
        raise ValueError(f"An asset named '{name}' already exists.")

    raw_ip = data.get("ip_address") or data.get("ip")
    ip_address = None
    if raw_ip and str(raw_ip).strip():
        ip_address = validate_ip_address(raw_ip)
        if not ip_address:
            raise ValueError(f"Invalid IP address format: '{raw_ip}'.")
        existing_ip = Asset.query.filter_by(ip_address=ip_address).first()
        if existing_ip:
            raise ValueError(f"An asset with IP address '{ip_address}' already exists ({existing_ip.name}).")

    hostname = sanitize_string(data.get("hostname"), max_len=255)
    fqdn = sanitize_string(data.get("fqdn"), max_len=255)

    raw_mac = data.get("mac_address") or data.get("mac")
    mac_address = None
    if raw_mac and str(raw_mac).strip():
        mac_address = validate_mac_address(raw_mac)
        if not mac_address:
            raise ValueError(f"Invalid MAC address format: '{raw_mac}'.")

    raw_type = sanitize_string(data.get("asset_type") or data.get("type"), max_len=64, default="Server")
    asset_type = TYPE_MAP.get(raw_type.lower() if raw_type else "", "Server")

    raw_env = sanitize_string(data.get("environment") or data.get("env"), max_len=64, default="Production")
    environment = ENV_MAP.get(raw_env.lower() if raw_env else "", "Production")

    criticality = str(data.get("criticality") or "medium").lower().strip()
    if criticality not in VALID_CRITICALITIES:
        criticality = "medium"

    status = str(data.get("status") or "online").lower().strip()
    if status not in VALID_STATUSES:
        status = "online"

    owner = sanitize_string(data.get("owner"), max_len=128)
    owner_team = sanitize_string(data.get("owner_team") or data.get("ownerTeam"), max_len=128, default=owner)

    raw_tags = data.get("tags") or []
    tags = [str(t).strip() for t in raw_tags if str(t).strip()] if isinstance(raw_tags, list) else []

    asset = Asset(
        asset_id=generate_asset_id(),
        name=name,
        hostname=hostname,
        fqdn=fqdn,
        ip_address=ip_address,
        mac_address=mac_address,
        asset_type=asset_type,
        environment=environment,
        criticality=criticality,
        owner=owner,
        owner_team=owner_team,
        tags=tags,
        operating_system=sanitize_string(data.get("operating_system") or data.get("os"), max_len=128),
        os_version=sanitize_string(data.get("os_version"), max_len=64),
        platform=sanitize_string(data.get("platform"), max_len=64),
        architecture=sanitize_string(data.get("architecture"), max_len=32),
        discovered_ports=data.get("discovered_ports") or [],
        discovered_services=data.get("discovered_services") or [],
        status=status,
        metadata_json=data.get("metadata_json") or {},
    )

    db.session.add(asset)
    db.session.commit()

    # Calculate real risk posture based on existing database findings/alerts
    calculate_asset_risk(asset)
    db.session.commit()

    # Dispatch audit log to SIEM
    _dispatch_siem_audit("Asset Created", f"New asset registered: {asset.name} ({asset.asset_id}) with IP {asset.ip_address or 'N/A'}.")

    return asset


def update_asset(asset_id_or_pk, data):
    """Updates permitted asset attributes and re-derives security risk score."""
    asset = get_asset(asset_id_or_pk)
    if not asset:
        raise ValueError(f"Asset '{asset_id_or_pk}' not found.")

    if not data or not isinstance(data, dict):
        raise ValueError("Invalid update payload.")

    if "name" in data:
        new_name = sanitize_string(data["name"], max_len=128)
        if not new_name:
            raise ValueError("Asset name cannot be empty.")
        if new_name.lower() != asset.name.lower():
            dup = Asset.query.filter(db.func.lower(Asset.name) == new_name.lower(), Asset.id != asset.id).first()
            if dup:
                raise ValueError(f"Another asset named '{new_name}' already exists.")
        asset.name = new_name

    if "ip_address" in data or "ip" in data:
        raw_ip = data.get("ip_address") or data.get("ip")
        if raw_ip and str(raw_ip).strip():
            new_ip = validate_ip_address(raw_ip)
            if not new_ip:
                raise ValueError(f"Invalid IP address format: '{raw_ip}'.")
            if new_ip != asset.ip_address:
                dup_ip = Asset.query.filter(Asset.ip_address == new_ip, Asset.id != asset.id).first()
                if dup_ip:
                    raise ValueError(f"Another asset with IP '{new_ip}' already exists ({dup_ip.name}).")
            asset.ip_address = new_ip
        else:
            asset.ip_address = None

    if "hostname" in data:
        asset.hostname = sanitize_string(data["hostname"], max_len=255)
    if "fqdn" in data:
        asset.fqdn = sanitize_string(data["fqdn"], max_len=255)

    if "mac_address" in data or "mac" in data:
        raw_mac = data.get("mac_address") or data.get("mac")
        if raw_mac and str(raw_mac).strip():
            new_mac = validate_mac_address(raw_mac)
            if not new_mac:
                raise ValueError(f"Invalid MAC address format: '{raw_mac}'.")
            asset.mac_address = new_mac
        else:
            asset.mac_address = None

    if "asset_type" in data or "type" in data:
        at = sanitize_string(data.get("asset_type") or data.get("type"), max_len=64)
        if at and at.lower() in TYPE_MAP:
            asset.asset_type = TYPE_MAP[at.lower()]

    if "environment" in data or "env" in data:
        env = sanitize_string(data.get("environment") or data.get("env"), max_len=64)
        if env and env.lower() in ENV_MAP:
            asset.environment = ENV_MAP[env.lower()]

    if "criticality" in data:
        crit = str(data["criticality"]).lower().strip()
        if crit in VALID_CRITICALITIES:
            asset.criticality = crit

    if "status" in data:
        st = str(data["status"]).lower().strip()
        if st in VALID_STATUSES:
            asset.status = st

    if "owner" in data:
        asset.owner = sanitize_string(data["owner"], max_len=128)
    if "owner_team" in data or "ownerTeam" in data:
        asset.owner_team = sanitize_string(data.get("owner_team") or data.get("ownerTeam"), max_len=128)

    if "tags" in data and isinstance(data["tags"], list):
        asset.tags = [str(t).strip() for t in data["tags"] if str(t).strip()]

    if "operating_system" in data or "os" in data:
        asset.operating_system = sanitize_string(data.get("operating_system") or data.get("os"), max_len=128)
    if "os_version" in data:
        asset.os_version = sanitize_string(data["os_version"], max_len=64)
    if "platform" in data:
        asset.platform = sanitize_string(data["platform"], max_len=64)
    if "architecture" in data:
        asset.architecture = sanitize_string(data["architecture"], max_len=32)

    asset.updated_at = datetime.utcnow()
    calculate_asset_risk(asset)
    db.session.commit()

    _dispatch_siem_audit("Asset Updated", f"Asset {asset.name} ({asset.asset_id}) was updated.")
    return asset


def delete_asset(asset_id_or_pk, soft=False):
    """
    Deletes an asset record or marks as decommissioned.
    Preserves historical findings and alert records.
    """
    asset = get_asset(asset_id_or_pk)
    if not asset:
        raise ValueError(f"Asset '{asset_id_or_pk}' not found.")

    asset_label = f"{asset.name} ({asset.asset_id})"

    if soft:
        asset.status = "decommissioned"
        asset.updated_at = datetime.utcnow()
        db.session.commit()
        _dispatch_siem_audit("Asset Decommissioned", f"Asset {asset_label} marked as decommissioned.")
        return True

    db.session.delete(asset)
    db.session.commit()
    _dispatch_siem_audit("Asset Deleted", f"Asset {asset_label} removed from inventory.")
    return True


def get_asset(asset_id_or_pk):
    """
    Retrieves single Asset by:
    1. Integer PK `id`
    2. String `asset_id` (e.g. AST-XXXXXXXX)
    3. IP address
    4. Hostname
    """
    if not asset_id_or_pk:
        return None

    if isinstance(asset_id_or_pk, int) or (isinstance(asset_id_or_pk, str) and asset_id_or_pk.isdigit()):
        rec = db.session.get(Asset, int(asset_id_or_pk))
        if rec:
            return rec

    val = str(asset_id_or_pk).strip()

    # Match by AST-XXXXXXXX
    if val.upper().startswith("AST-"):
        rec = Asset.query.filter(db.func.upper(Asset.asset_id) == val.upper()).first()
        if rec:
            return rec

    # Match by IP address
    rec = Asset.query.filter_by(ip_address=val).first()
    if rec:
        return rec

    # Match by Hostname or Name
    rec = Asset.query.filter(
        db.or_(
            db.func.lower(Asset.hostname) == val.lower(),
            db.func.lower(Asset.name) == val.lower(),
        )
    ).first()
    return rec


def list_assets(filters=None, page=1, per_page=20, sort_by="created_at", sort_dir="desc", **kwargs):
    """
    Retrieves filtered, searchable, sorted, paginated asset records from PostgreSQL.
    """
    filters = dict(filters or {})
    filters.update(kwargs)
    q = Asset.query

    # Search term across name, hostname, IP, owner, fqdn, tags
    search = filters.get("search") or filters.get("q") or filters.get("search_query")
    if search:
        term = f"%{str(search).strip()}%"
        q = q.filter(
            db.or_(
                Asset.name.ilike(term),
                Asset.hostname.ilike(term),
                Asset.ip_address.ilike(term),
                Asset.owner.ilike(term),
                Asset.owner_team.ilike(term),
                Asset.asset_id.ilike(term),
            )
        )

    # Filters
    if filters.get("asset_type") or filters.get("type"):
        at = str(filters.get("asset_type") or filters.get("type")).strip()
        if at:
            q = q.filter(Asset.asset_type == at)

    if filters.get("environment") or filters.get("env"):
        env = str(filters.get("environment") or filters.get("env")).strip()
        if env:
            q = q.filter(Asset.environment == env)

    if filters.get("criticality"):
        crit = str(filters["criticality"]).lower().strip()
        if crit:
            q = q.filter(Asset.criticality == crit)

    if filters.get("status"):
        st = str(filters["status"]).lower().strip()
        if st:
            q = q.filter(Asset.status == st)

    if filters.get("risk_severity") or filters.get("sev"):
        sev = str(filters.get("risk_severity") or filters.get("sev")).lower().strip()
        if sev:
            q = q.filter(Asset.risk_severity == sev)

    # Sorting
    sort_column_map = {
        "name": Asset.name,
        "ip": Asset.ip_address,
        "ip_address": Asset.ip_address,
        "status": Asset.status,
        "risk": Asset.risk_score,
        "risk_score": Asset.risk_score,
        "criticality": Asset.criticality,
        "created_at": Asset.created_at,
        "last_seen": Asset.last_seen,
    }
    col = sort_column_map.get(str(sort_by).lower(), Asset.created_at)
    order_expr = col.desc() if str(sort_dir).lower() == "desc" else col.asc()
    q = q.order_by(order_expr)

    total = q.count()
    pagination = q.paginate(page=max(1, int(page)), per_page=max(1, min(int(per_page), 100)), error_out=False)

    return {
        "items": [a.to_dict() for a in pagination.items],
        "assets": [a.to_dict() for a in pagination.items],
        "total": total,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "pages": pagination.pages,
        "has_prev": pagination.has_prev,
        "has_next": pagination.has_next,
    }


def update_last_seen(asset_id_or_pk, seen_time=None):
    """Updates last_seen timestamp for an asset."""
    asset = get_asset(asset_id_or_pk)
    if asset:
        asset.last_seen = seen_time or datetime.utcnow()
        db.session.commit()
        return True
    return False


# ==============================================================================
# Real Dynamic Risk Calculation & Cross-Module Correlation
# ==============================================================================

def calculate_asset_risk(asset):
    """
    Derives real risk score and severity from actual stored security data:
    1. Vulnerability Findings from Vulnerability Scanner (`VulnerabilityFinding`)
    2. Active Alerts from Alert Center (`Alert`)
    3. Asset Criticality weighting
    Caps at 100. Never invents random or fake numbers.
    """
    if not asset:
        return 0, "low"

    identifiers = [id_val for id_val in [asset.ip_address, asset.hostname, asset.name] if id_val]

    vuln_points = 0
    open_vulns_count = 0

    alert_points = 0
    open_alerts_count = 0

    # 1. Query Vulnerability Findings
    try:
        from app.scanner.models import VulnerabilityFinding
        finding_query = VulnerabilityFinding.query.filter(
            db.or_(
                VulnerabilityFinding.host.in_(identifiers),
                db.func.lower(VulnerabilityFinding.host).in_([i.lower() for i in identifiers]),
            )
        )
        findings = finding_query.all()
        open_vulns_count = len(findings)

        for f in findings:
            sev = (f.severity or "low").lower()
            if sev == "critical":
                vuln_points += 25
            elif sev == "high":
                vuln_points += 15
            elif sev == "medium":
                vuln_points += 8
            else:
                vuln_points += 3
    except Exception as e:
        logger.warning(f"Failed to aggregate vulnerabilities for asset {asset.id}: {e}")

    # 2. Query Alert Center Alerts
    try:
        from app.alerts.models import Alert
        alert_query = Alert.query.filter(
            Alert.status.in_(["new", "acknowledged", "investigating"]),
            db.or_(
                Alert.affected_asset.in_(identifiers),
                Alert.affected_host.in_(identifiers),
                db.func.lower(Alert.affected_asset).in_([i.lower() for i in identifiers]),
                db.func.lower(Alert.affected_host).in_([i.lower() for i in identifiers]),
            )
        )
        alerts = alert_query.all()
        open_alerts_count = len(alerts)

        for a in alerts:
            sev = (a.severity or "low").lower()
            if sev == "critical":
                alert_points += 20
            elif sev == "high":
                alert_points += 12
            elif sev == "medium":
                alert_points += 5
            else:
                alert_points += 2
    except Exception as e:
        logger.warning(f"Failed to aggregate alerts for asset {asset.id}: {e}")

    # 3. Criticality Multiplier
    multiplier_map = {
        "critical": 1.25,
        "high": 1.10,
        "medium": 1.0,
        "low": 0.8,
    }
    crit_multiplier = multiplier_map.get(asset.criticality, 1.0)

    # 4. Compute Final Capped Score
    raw_score = (vuln_points + alert_points) * crit_multiplier
    final_score = int(min(100, round(raw_score)))

    # Determine Severity Level
    if final_score >= 80:
        severity = "critical"
    elif final_score >= 60:
        severity = "high"
    elif final_score >= 35:
        severity = "medium"
    elif final_score > 0:
        severity = "low"
    else:
        severity = "low"

    asset.risk_score = final_score
    asset.risk_severity = severity
    asset.open_vulnerabilities_count = open_vulns_count
    asset.open_alerts_count = open_alerts_count

    return final_score, severity


def refresh_asset_security_summary(asset_id_or_pk):
    """Forces recalculation of an asset's risk posture and returns updated summary."""
    asset = get_asset(asset_id_or_pk)
    if not asset:
        raise ValueError(f"Asset '{asset_id_or_pk}' not found.")

    score, severity = calculate_asset_risk(asset)
    db.session.commit()
    return {
        "asset_id": asset.asset_id,
        "risk_score": score,
        "risk_severity": severity,
        "open_vulnerabilities_count": asset.open_vulnerabilities_count,
        "open_alerts_count": asset.open_alerts_count,
    }


def get_asset_security_details(asset_id_or_pk):
    """
    Gathers correlated real security data across XDR modules for this asset:
    - Scanner Vulnerability Findings
    - Alert Center Alerts
    - Incidents
    - Network IDS Events
    - SIEM Events
    """
    asset = get_asset(asset_id_or_pk)
    if not asset:
        raise ValueError(f"Asset '{asset_id_or_pk}' not found.")

    identifiers = [id_val for id_val in [asset.ip_address, asset.hostname, asset.name] if id_val]

    # Vulnerability Findings
    vulnerabilities = []
    try:
        from app.scanner.models import VulnerabilityFinding
        findings = VulnerabilityFinding.query.filter(
            db.or_(
                VulnerabilityFinding.host.in_(identifiers),
                db.func.lower(VulnerabilityFinding.host).in_([i.lower() for i in identifiers]),
            )
        ).order_by(VulnerabilityFinding.id.desc()).all()
        vulnerabilities = [f.to_dict() for f in findings]
    except Exception as e:
        logger.warning(f"Error fetching findings for asset {asset.id}: {e}")

    # Alerts
    alerts = []
    try:
        from app.alerts.models import Alert
        alert_records = Alert.query.filter(
            db.or_(
                Alert.affected_asset.in_(identifiers),
                Alert.affected_host.in_(identifiers),
                db.func.lower(Alert.affected_asset).in_([i.lower() for i in identifiers]),
                db.func.lower(Alert.affected_host).in_([i.lower() for i in identifiers]),
            )
        ).order_by(Alert.id.desc()).all()
        alerts = [a.to_dict() for a in alert_records]
    except Exception as e:
        logger.warning(f"Error fetching alerts for asset {asset.id}: {e}")

    # Incidents
    incidents = []
    try:
        from app.incidents.models import Incident
        incident_records = Incident.query.filter(
            db.or_(
                Incident.affected_asset.in_(identifiers),
                db.func.lower(Incident.affected_asset).in_([i.lower() for i in identifiers]),
            )
        ).order_by(Incident.id.desc()).all()
        incidents = [inc.to_dict() for inc in incident_records]
    except Exception as e:
        logger.warning(f"Error fetching incidents for asset {asset.id}: {e}")

    # Network IDS Events
    ids_events = []
    if asset.ip_address:
        try:
            from app.ids.models import NetworkIDSEvent
            events = NetworkIDSEvent.query.filter(
                db.or_(
                    NetworkIDSEvent.src_ip == asset.ip_address,
                    NetworkIDSEvent.dest_ip == asset.ip_address,
                )
            ).order_by(NetworkIDSEvent.timestamp.desc()).limit(25).all()
            ids_events = [e.to_dict() for e in events]
        except Exception as e:
            logger.warning(f"Error fetching IDS events for asset {asset.id}: {e}")

    # SIEM Logs
    siem_events = []
    try:
        from app.siem.models import SiemEvent
        logs = SiemEvent.query.filter(
            db.or_(
                SiemEvent.host.in_(identifiers),
                db.func.lower(SiemEvent.host).in_([i.lower() for i in identifiers]),
            )
        ).order_by(SiemEvent.timestamp.desc()).limit(25).all()
        siem_events = [l.to_dict() for l in logs]
    except Exception as e:
        logger.warning(f"Error fetching SIEM logs for asset {asset.id}: {e}")

    return {
        "asset": asset.to_dict(include_details=True),
        "vulnerabilities": vulnerabilities,
        "alerts": alerts,
        "incidents": incidents,
        "ids_events": ids_events,
        "siem_events": siem_events,
    }


# ==============================================================================
# Inventory Statistics & Real Counts
# ==============================================================================

def get_asset_inventory_stats():
    """
    Computes real-time statistics across all stored Asset records in PostgreSQL.
    No hardcoded or fake demo numbers.
    """
    total = Asset.query.count()
    online = Asset.query.filter_by(status="online").count()
    offline = Asset.query.filter_by(status="offline").count()

    critical_risk = Asset.query.filter(
        db.or_(Asset.risk_severity == "critical", Asset.risk_score >= 80)
    ).count()

    unassigned = Asset.query.filter(
        db.or_(Asset.owner.is_(None), Asset.owner == "", Asset.owner == "Unassigned")
    ).count()

    threshold_24h = datetime.utcnow() - timedelta(hours=24)
    recently_seen = Asset.query.filter(Asset.last_seen >= threshold_24h).count()

    # Group counts by Type
    type_counts = dict(
        db.session.query(Asset.asset_type, db.func.count(Asset.id))
        .group_by(Asset.asset_type)
        .all()
    )

    # Group counts by Environment
    env_counts = dict(
        db.session.query(Asset.environment, db.func.count(Asset.id))
        .group_by(Asset.environment)
        .all()
    )
    return {
        "total": total,
        "totalAssets": total,
        "total_assets": total,
        "online": online,
        "onlineAssets": online,
        "online_assets": online,
        "offline": offline,
        "offlineAssets": offline,
        "offline_assets": offline,
        "critical_risk": critical_risk,
        "criticalRiskAssets": critical_risk,
        "critical_risk_assets": critical_risk,
        "unassigned_owner": unassigned,
        "unassignedOwnerAssets": unassigned,
        "unassigned_owner_assets": unassigned,
        "recently_seen": recently_seen,
        "recentlySeenAssets": recently_seen,
        "recently_seen_assets": recently_seen,
        "by_type": type_counts,
        "byType": type_counts,
        "by_environment": env_counts,
        "byEnvironment": env_counts,
        "environmentCount": len(env_counts),
        "environment_count": len(env_counts),
    }


# ==============================================================================
# Scanner Integration & Discovery
# ==============================================================================

def trigger_asset_scan(asset_id_or_pk, scan_type="Quick Scan", user_id=None):
    """
    Invokes the real Vulnerability Scanner on an asset's target IP or hostname.
    Reuses existing validation and authorized scope controls.
    """
    asset = get_asset(asset_id_or_pk)
    if not asset:
        raise ValueError(f"Asset '{asset_id_or_pk}' not found.")

    target = asset.ip_address or asset.hostname
    if not target:
        raise ValueError(f"Asset '{asset.name}' has no IP address or hostname to scan.")

    from app.scanner.services import normalize_and_validate_target, create_scan

    # Validate target authorization
    is_valid, t_info, err_msg = normalize_and_validate_target(target)
    if not is_valid:
        raise ValueError(f"Target '{target}' cannot be scanned: {err_msg}")

    # Launch scan
    scan = create_scan({
        "name": f"Scan: {asset.name} ({target})",
        "targets": [target],
        "scan_type": scan_type,
        "created_by": user_id,
        "asset_id": asset.id,
    })

    # Update asset last_seen and refresh risk
    update_last_seen(asset.id)
    return scan


def rescan_inventory():
    """
    Safe inventory discovery trigger.
    Checks for configured authorized discovery targets or subnets.
    If none are configured, truthful report is returned without fabricating results.
    """
    from app.scanner.models import ScanTarget, Scan

    configured_targets = ScanTarget.query.count()
    if configured_targets == 0:
        return {
            "success": True,
            "message": "No authorized discovery scope configured. Configure authorized scan targets in Vulnerability Scanner to discover network assets.",
            "discovered": 0,
        }

    # If targets exist, check recent scans for hosts not yet in asset inventory
    discovered_count = 0
    scans = Scan.query.filter(Scan.status == "completed").all()

    for s in scans:
        host = s.target
        if not host:
            continue
        existing = get_asset(host)
        if not existing:
            try:
                create_asset({
                    "name": f"Discovered Host ({host})",
                    "ip_address": host if not any(c.isalpha() for c in host) else None,
                    "hostname": host if any(c.isalpha() for c in host) else None,
                    "asset_type": "Server",
                    "environment": "Internal",
                    "criticality": "medium",
                    "owner": "Auto-Discovered",
                    "tags": ["auto-discovered", "scanner"],
                })
                discovered_count += 1
            except Exception as e:
                logger.warning(f"Could not auto-create asset for host {host}: {e}")

    return {
        "success": True,
        "message": f"Inventory refresh completed. {discovered_count} new assets registered from authorized scan targets.",
        "discovered": discovered_count,
    }


def _dispatch_siem_audit(action, message):
    """Dispatches a lightweight audit log into SIEM."""
    """Dispatches an audit log into AuditLog table and SIEM."""
    try:
        from app.siem.services import ingest_event as siem_ingest
        siem_ingest({
            "source": "Asset Management",
            "severity": "info",
            "category": "Asset Inventory",
            "host": "localhost",
            "message": f"[Asset Management] {action}: {message}",
            "fields": {"action": action},
        })
        from app.audit_logs.services import record_audit_event
        norm_action = f"ASSET_{action.upper().replace(' ', '_')}"
        record_audit_event(
            action=norm_action,
            category="Asset Management",
            message=message,
            resource_type="Asset",
            result="SUCCESS",
            severity="info",
            details={"action": action},
            sync_to_siem=True,
        )
    except Exception as e:
        logger.warning(f"Failed to log SIEM audit: {e}")
        logger.warning(f"Failed to record asset audit log: {e}")
