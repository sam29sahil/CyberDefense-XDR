"""
CyberDefense XDR
SIEM & Log Explorer Service Layer
"""

import json
import re
import secrets
from datetime import datetime, timedelta
from sqlalchemy import or_, desc, asc

from app.extensions import db
from app.siem.models import SiemEvent, SiemSavedSearch


# ============================================================
# HELPERS & ID GENERATION
# ============================================================

def generate_log_id():
    """Generates a unique LOG-XXXXXX identifier."""
    while True:
        log_id = f"LOG-{secrets.randbelow(900000) + 100000}"
        if not SiemEvent.query.filter_by(event_id=log_id).first():
            return log_id


def generate_search_id():
    """Generates a unique SRCH-XX identifier."""
    while True:
        num = secrets.randbelow(90) + 10
        search_id = f"SRCH-{num}"
        if not SiemSavedSearch.query.filter_by(search_id=search_id).first():
            return search_id


# ============================================================
# LOG INGESTION & CORRELATION
# ============================================================

def correlate_threat_intel(fields, message=None):
    """
    Checks extracted fields and message against known IOCs (threat_iocs).
    Returns matched IOC object or None.
    """
    try:
        from app.threatintel.models import IOC
    except ImportError:
        return None

    candidate_values = set()

    # Extract IPs
    for ip_key in ("src_ip", "dst_ip", "ip", "sourceIPAddress", "client_ip"):
        val = fields.get(ip_key)
        if val and isinstance(val, str) and val.strip():
            candidate_values.add(val.strip())

    # Extract domains/hosts/hashes
    for hash_key in ("sha256", "md5", "hash", "file_hash"):
        val = fields.get(hash_key)
        if val and isinstance(val, str) and val.strip():
            candidate_values.add(val.strip())

    # Check for IP or domain patterns in message if any
    if message:
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        for ip in ip_matches:
            if not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("127."):
                candidate_values.add(ip)

    if not candidate_values:
        return None

    matched = IOC.query.filter(IOC.value.in_(list(candidate_values))).first()
    return matched


def trigger_detection_evaluation(siem_event, matched_ioc=None):
    """
    Evaluates detection rules or triggers a DetectionEvent for high/critical threats or IOC hits.
    Also automatically connects to the Alert Center via create_detection_event.
    """
    try:
        from app.detection.models import DetectionRule
        from app.detection.services import create_detection_event
    except ImportError:
        return None

    # Check if a matching rule exists for the source/category
    rule = None
    if matched_ioc:
        rule = DetectionRule.query.filter(
            or_(
                DetectionRule.name.ilike("%threat intel%"),
                DetectionRule.name.ilike("%ioc%"),
                DetectionRule.category.ilike("%threat%"),
            )
        ).first()

    if not rule and siem_event.severity in ("high", "critical"):
        rule = DetectionRule.query.filter(
            DetectionRule.severity == siem_event.severity
        ).first()

    if not rule:
        rule = DetectionRule.query.filter_by(status="active").first()

    # Create detection event if rule exists and severity is high/critical or IOC matched
    if rule and (siem_event.severity in ("high", "critical") or matched_ioc):
        evt = create_detection_event(
            rule=rule,
            source=siem_event.source,
            host=siem_event.host,
            severity=siem_event.severity,
            status="new",
            raw_event={
                "siem_event_id": siem_event.event_id,
                "message": siem_event.message,
                "fields": siem_event.fields,
                "ioc_match": matched_ioc.ioc_id if matched_ioc else None,
            },
        )
        return evt.id

    return None


def ingest_event(data):
    """
    Ingests, normalizes, correlates, and stores a security log event.
    """
    event_id = str(data.get("id") or data.get("event_id") or "").strip()
    if not event_id:
        event_id = generate_log_id()

    # Timestamp handling
    ts = data.get("ts") or data.get("timestamp")
    if ts:
        if isinstance(ts, str):
            try:
                # Replace trailing 'Z' if present
                clean_ts = ts.replace("Z", "+00:00")
                parsed_ts = datetime.fromisoformat(clean_ts).replace(tzinfo=None)
            except Exception:
                parsed_ts = datetime.utcnow()
        elif isinstance(ts, datetime):
            parsed_ts = ts
        else:
            parsed_ts = datetime.utcnow()
    else:
        parsed_ts = datetime.utcnow()

    severity = str(data.get("sev") or data.get("severity") or "info").strip().lower()
    allowed_sevs = {"critical", "high", "medium", "low", "info"}
    if severity not in allowed_sevs:
        severity = "info"

    category = str(data.get("category") or "Application").strip()
    source = str(data.get("source") or "System").strip()
    host = str(data.get("host") or "UNKNOWN-HOST").strip()
    message = str(data.get("message") or "Security event captured").strip()
    raw_log = str(data.get("raw") or data.get("raw_log") or message).strip()

    # Fields
    fields = data.get("fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    # Tags
    tags = data.get("tags") or []
    if not isinstance(tags, list):
        tags = []

    # Threat Intelligence Correlation Check
    matched_ioc = correlate_threat_intel(fields, message)
    ioc_match_id = None
    if matched_ioc:
        ioc_match_id = matched_ioc.ioc_id
        if "threat-intel-match" not in tags:
            tags.append("threat-intel-match")
        if matched_ioc.threat_level in ("high", "critical") and severity in ("low", "info", "medium"):
            severity = matched_ioc.threat_level.lower()

    event = SiemEvent(
        event_id=event_id,
        timestamp=parsed_ts,
        severity=severity,
        category=category,
        source=source,
        host=host,
        message=message,
        raw_log=raw_log,
        fields_json=json.dumps(fields),
        tags_json=json.dumps(tags),
        ioc_match_id=ioc_match_id,
    )

    db.session.add(event)
    db.session.flush()

    # Detection Engine Trigger Check
    detection_evt_id = trigger_detection_evaluation(event, matched_ioc)
    if detection_evt_id:
        event.detection_event_id = detection_evt_id

    db.session.commit()
    return event


def ingest_events_bulk(events_list):
    """Bulk ingestion for high throughput logs."""
    created = []
    for item in events_list:
        event_id = str(item.get("id") or item.get("event_id") or "").strip() or generate_log_id()
        ts = item.get("ts") or item.get("timestamp")
        parsed_ts = datetime.utcnow()
        if isinstance(ts, str):
            try:
                parsed_ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass
        elif isinstance(ts, datetime):
            parsed_ts = ts

        sev = str(item.get("sev") or item.get("severity") or "info").lower()
        if sev not in {"critical", "high", "medium", "low", "info"}:
            sev = "info"

        fields = item.get("fields") if isinstance(item.get("fields"), dict) else {}
        tags = item.get("tags") if isinstance(item.get("tags"), list) else []

        event = SiemEvent(
            event_id=event_id,
            timestamp=parsed_ts,
            severity=sev,
            category=str(item.get("category") or "Application"),
            source=str(item.get("source") or "System"),
            host=str(item.get("host") or "UNKNOWN-HOST"),
            message=str(item.get("message") or ""),
            raw_log=str(item.get("raw") or item.get("raw_log") or item.get("message") or ""),
            fields_json=json.dumps(fields),
            tags_json=json.dumps(tags),
        )
        db.session.add(event)
        created.append(event)

    db.session.commit()
    return created


# ============================================================
# LOG EXPLORER QUERY & FILTERING
# ============================================================

def get_logs(
    filters=None,
    page=1,
    per_page=10,
    sort_key="ts",
    sort_dir="desc",
):
    """
    Search and filter security events with pagination and sorting.
    """
    filters = filters or {}
    query = SiemEvent.query

    # Severity filter
    sev = filters.get("sev") or filters.get("severity")
    if sev:
        query = query.filter(SiemEvent.severity == str(sev).strip().lower())

    # Source filter
    source = filters.get("source")
    if source:
        query = query.filter(SiemEvent.source == str(source).strip())

    # Host filter
    host = filters.get("host")
    if host:
        query = query.filter(SiemEvent.host == str(host).strip())

    # Category filter
    category = filters.get("category")
    if category:
        query = query.filter(SiemEvent.category == str(category).strip())

    # Tag filter
    tag = filters.get("tag")
    if tag:
        query = query.filter(SiemEvent.tags_json.ilike(f'%"{tag}"%'))

    # Time range filter in minutes (e.g. 15, 60, 360, 1440)
    time_range = filters.get("timeRange") or filters.get("time_range")
    if time_range:
        try:
            mins = int(time_range)
            cutoff = datetime.utcnow() - timedelta(minutes=mins)
            query = query.filter(SiemEvent.timestamp >= cutoff)
        except (ValueError, TypeError):
            pass

    # Free text search query
    q = filters.get("query") or filters.get("q") or filters.get("search")
    if q and str(q).strip() and str(q).strip() != "*:*":
        search_str = f"%{str(q).strip()}%"
        query = query.filter(
            or_(
                SiemEvent.message.ilike(search_str),
                SiemEvent.host.ilike(search_str),
                SiemEvent.source.ilike(search_str),
                SiemEvent.event_id.ilike(search_str),
                SiemEvent.raw_log.ilike(search_str),
            )
        )

    # Sorting
    if sort_key in ("ts", "timestamp"):
        col = SiemEvent.timestamp
    elif sort_key in ("sev", "severity"):
        col = SiemEvent.severity
    elif sort_key == "host":
        col = SiemEvent.host
    elif sort_key == "source":
        col = SiemEvent.source
    else:
        col = SiemEvent.timestamp

    if str(sort_dir).lower() == "asc":
        query = query.order_by(asc(col))
    else:
        query = query.order_by(desc(col))

    # Pagination
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page if per_page > 0 else 1

    return {
        "items": [event.to_dict() for event in items],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


def get_filter_options():
    """
    Returns unique lists of sources, hosts, categories, and tags for filter dropdowns.
    """
    sources = [
        r[0] for r in db.session.query(SiemEvent.source).distinct().order_by(SiemEvent.source).all() if r[0]
    ]
    hosts = [
        r[0] for r in db.session.query(SiemEvent.host).distinct().order_by(SiemEvent.host).all() if r[0]
    ]
    categories = [
        r[0] for r in db.session.query(SiemEvent.category).distinct().order_by(SiemEvent.category).all() if r[0]
    ]

    # Extract all distinct tags from tags_json
    all_events_tags = db.session.query(SiemEvent.tags_json).all()
    unique_tags = set()
    for row in all_events_tags:
        if row[0]:
            try:
                parsed = json.loads(row[0])
                if isinstance(parsed, list):
                    for t in parsed:
                        unique_tags.add(t)
            except Exception:
                pass

    return {
        "sources": sources,
        "hosts": hosts,
        "categories": categories,
        "tags": sorted(list(unique_tags)),
    }


def get_log_by_event_id(event_id):
    """
    Fetches a single log event by its event_id and includes related events from the same host.
    """
    event = SiemEvent.query.filter_by(event_id=event_id).first()
    if not event:
        return None

    # Related events: same host, excluding current event, up to 6 most recent
    related = (
        SiemEvent.query.filter(
            SiemEvent.host == event.host,
            SiemEvent.event_id != event.event_id,
        )
        .order_by(desc(SiemEvent.timestamp))
        .limit(6)
        .all()
    )

    data = event.to_dict()
    data["related"] = [r.to_dict() for r in related]
    return data


# ============================================================
# SIEM DASHBOARD STATS
# ============================================================

def get_siem_dashboard_stats():
    """
    Computes all SIEM Dashboard KPIs, 24h event volume chart data,
    severity distributions, top sources, noisiest hosts, and live stream.
    """
    now = datetime.utcnow()
    one_day_ago = now - timedelta(hours=24)

    total_events_24h = SiemEvent.query.filter(SiemEvent.timestamp >= one_day_ago).count()
    if total_events_24h == 0:
        total_events_24h = SiemEvent.query.count()

    # Active sources in 24h
    active_sources_count = (
        db.session.query(SiemEvent.source)
        .filter(SiemEvent.timestamp >= one_day_ago)
        .distinct()
        .count()
    )
    if active_sources_count == 0:
        active_sources_count = db.session.query(SiemEvent.source).distinct().count()

    # Calculate EPS: events in last 10 minutes / 600, or a representative baseline
    ten_mins_ago = now - timedelta(minutes=10)
    events_10m = SiemEvent.query.filter(SiemEvent.timestamp >= ten_mins_ago).count()
    eps = max(120, int(events_10m / 600.0 * 1000)) if events_10m > 0 else 812

    # Severity distribution
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_counts = {}
    for s in sev_order:
        sev_counts[s] = SiemEvent.query.filter_by(severity=s).count()

    # Top sources (up to 6)
    from sqlalchemy import func
    top_sources_query = (
        db.session.query(SiemEvent.source, func.count(SiemEvent.id).label("count"))
        .group_by(SiemEvent.source)
        .order_by(desc("count"))
        .limit(6)
        .all()
    )
    max_source_count = top_sources_query[0][1] if top_sources_query else 1
    top_sources = [
        {
            "name": row[0],
            "count": row[1],
            "percent": int(round((row[1] / max_source_count) * 100)),
        }
        for row in top_sources_query
    ]

    # Noisiest hosts (up to 6) with highest severity rank
    host_stats_query = (
        db.session.query(SiemEvent.host, func.count(SiemEvent.id).label("count"))
        .group_by(SiemEvent.host)
        .order_by(desc("count"))
        .limit(6)
        .all()
    )

    noisiest_hosts = []
    for host_name, count in host_stats_query:
        # Find highest severity for this host
        host_events = SiemEvent.query.filter_by(host=host_name).all()
        best_rank = 4
        for ev in host_events:
            if ev.severity in sev_order:
                rank = sev_order.index(ev.severity)
                if rank < best_rank:
                    best_rank = rank
        noisiest_hosts.append({
            "host": host_name,
            "count": count,
            "severity": sev_order[best_rank],
        })

    # 24h Event Volume Chart Buckets (hour 23 to 0)
    hour_buckets = {h: {s: 0 for s in sev_order} for h in range(24)}
    recent_events = SiemEvent.query.filter(SiemEvent.timestamp >= one_day_ago).all()
    for ev in recent_events:
        hours_ago = int((now - ev.timestamp).total_seconds() // 3600)
        if 0 <= hours_ago < 24:
            s = ev.severity.lower()
            if s in hour_buckets[hours_ago]:
                hour_buckets[hours_ago][s] += 1

    hour_labels = [f"{h}h ago" for h in range(23, -1, -1)]
    chart_datasets = {}
    for sev in ("critical", "high", "medium"):
        chart_datasets[sev] = [hour_buckets[23 - i][sev] for i in range(24)]

    # Live recent stream (latest 18 events)
    stream_events = (
        SiemEvent.query.order_by(desc(SiemEvent.timestamp))
        .limit(18)
        .all()
    )

    # Pinned saved searches
    pinned_searches = SiemSavedSearch.query.filter_by(pinned=True).all()

    return {
        "kpi": {
            "total_events_24h": total_events_24h,
            "active_sources_count": active_sources_count,
            "eps": eps,
            "parsed_rate": "99.8%",
        },
        "severity_counts": sev_counts,
        "top_sources": top_sources,
        "noisiest_hosts": noisiest_hosts,
        "chart": {
            "labels": hour_labels,
            "datasets": chart_datasets,
        },
        "stream": [ev.to_dict() for ev in stream_events],
        "pinned_searches": [s.to_dict() for s in pinned_searches],
    }


# ============================================================
# SAVED SEARCHES MANAGEMENT
# ============================================================

def get_saved_searches(scope=None, alerting=None, search=None):
    """
    Returns list of saved searches filtered by scope, alerting, or search keyword.
    """
    query = SiemSavedSearch.query

    if scope and str(scope).strip():
        query = query.filter(SiemSavedSearch.scope == str(scope).strip())

    if alerting is not None:
        if str(alerting).lower() in ("on", "true", "1"):
            query = query.filter(SiemSavedSearch.alerting.is_(True))
        elif str(alerting).lower() in ("off", "false", "0"):
            query = query.filter(SiemSavedSearch.alerting.is_(False))

    if search and str(search).strip():
        term = f"%{str(search).strip()}%"
        query = query.filter(
            or_(
                SiemSavedSearch.name.ilike(term),
                SiemSavedSearch.query_text.ilike(term),
                SiemSavedSearch.description.ilike(term),
                SiemSavedSearch.owner.ilike(term),
            )
        )

    results = query.order_by(desc(SiemSavedSearch.pinned), desc(SiemSavedSearch.created_at)).all()
    return [s.to_dict() for s in results]


def create_saved_search(data, owner="Aria Reyes"):
    """
    Creates a new saved search query.
    """
    name = str(data.get("name", "")).strip()
    if not name:
        raise ValueError("Search name is required.")

    query_str = str(data.get("query", "*:*")).strip()
    description = str(data.get("description", "")).strip()
    scope = str(data.get("scope", "Team")).strip()
    if scope not in ("Team", "Private"):
        scope = "Team"

    pinned = bool(data.get("pinned", False))
    alerting = bool(data.get("alerting", False))
    filters = data.get("filters") or {}

    saved_search = SiemSavedSearch(
        search_id=generate_search_id(),
        name=name,
        query=query_str,
        description=description,
        owner=str(owner or data.get("owner", "Aria Reyes")),
        scope=scope,
        pinned=pinned,
        alerting=alerting,
        hits=0,
        last_run=datetime.utcnow(),
        filters_json=json.dumps(filters if isinstance(filters, dict) else {}),
    )

    db.session.add(saved_search)
    db.session.commit()
    return saved_search


def toggle_pin_saved_search(search_id):
    """
    Toggles the pinned status of a saved search.
    """
    search = SiemSavedSearch.query.filter_by(search_id=search_id).first()
    if not search:
        return None

    search.pinned = not search.pinned
    search.updated_at = datetime.utcnow()
    db.session.commit()
    return search


def delete_saved_search(search_id):
    """
    Deletes a saved search.
    """
    search = SiemSavedSearch.query.filter_by(search_id=search_id).first()
    if not search:
        return False

    db.session.delete(search)
    db.session.commit()
    return True


# ============================================================
# INITIAL SEEDER
# ============================================================

def seed_initial_siem_data():
    """
    Seeds initial realistic logs and saved searches into PostgreSQL if empty.
    """
    if SiemEvent.query.count() == 0:
        import os
        js_data_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "static", "js", "data", "logs_data.js"
        )
        if os.path.exists(js_data_path):
            try:
                with open(js_data_path, "r", encoding="utf-8") as f:
                    content = f.read()
                # Parse JS variable 'const LOGS_DATA = [...];'
                match = re.search(r"const\s+LOGS_DATA\s*=\s*(\[.*?\]);", content, re.DOTALL)
                if match:
                    logs_json = match.group(1)
                    items = json.loads(logs_json)
                    for item in items:
                        event_id = item.get("id") or generate_log_id()
                        ts_str = item.get("ts")
                        ts = datetime.utcnow()
                        if ts_str:
                            try:
                                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                            except Exception:
                                pass

                        event = SiemEvent(
                            event_id=event_id,
                            timestamp=ts,
                            severity=item.get("sev", "info"),
                            category=item.get("category", "Application"),
                            source=item.get("source", "System"),
                            host=item.get("host", "UNKNOWN-HOST"),
                            message=item.get("message", ""),
                            raw_log=item.get("raw", ""),
                            fields_json=json.dumps(item.get("fields", {})),
                            tags_json=json.dumps(item.get("tags", [])),
                        )
                        db.session.add(event)
                    db.session.commit()
            except Exception as e:
                db.session.rollback()

    if SiemSavedSearch.query.count() == 0:
        default_searches = [
            {
                "search_id": "SRCH-01",
                "name": "Critical alerts — last 24h",
                "query": "sev:critical AND ts:[now-24h TO now]",
                "owner": "Aria Reyes",
                "scope": "Team",
                "pinned": True,
                "alerting": True,
                "hits": 6,
                "description": "All critical-severity events across every source in the last 24 hours.",
            },
            {
                "search_id": "SRCH-02",
                "name": "Failed admin logins",
                "query": 'message:"login" AND result:failure AND user:admin*',
                "owner": "Marcus Lee",
                "scope": "Team",
                "pinned": True,
                "alerting": True,
                "hits": 23,
                "description": "Failed authentication attempts against administrative accounts.",
            },
            {
                "search_id": "SRCH-03",
                "name": "PowerShell encoded commands",
                "query": 'source:"CrowdStrike EDR" AND message:"PowerShell" AND message:"encoded"',
                "owner": "Priya Nair",
                "scope": "Private",
                "pinned": False,
                "alerting": True,
                "hits": 4,
                "description": "Suspicious obfuscated PowerShell execution across endpoints.",
            },
            {
                "search_id": "SRCH-04",
                "name": "Outbound to new external domains",
                "query": "category:Network AND action:alert AND tags:external",
                "owner": "Aria Reyes",
                "scope": "Team",
                "pinned": False,
                "alerting": False,
                "hits": 41,
                "description": "Traffic flagged toward domains not previously seen on the network.",
            },
            {
                "search_id": "SRCH-05",
                "name": "AWS CloudTrail — IAM changes",
                "query": 'source:"AWS CloudTrail" AND eventName:(CreateUser OR AssumeRole OR DeleteBucket)',
                "owner": "J. Chen",
                "scope": "Team",
                "pinned": False,
                "alerting": False,
                "hits": 12,
                "description": "Sensitive identity and access management activity in AWS.",
            },
            {
                "search_id": "SRCH-06",
                "name": "VPN logins outside business hours",
                "query": 'source:"VPN Gateway" AND result:success AND hour:[19 TO 6]',
                "owner": "D. Okafor",
                "scope": "Private",
                "pinned": False,
                "alerting": False,
                "hits": 9,
                "description": "Successful VPN connections between 7 PM and 6 AM local time.",
            },
            {
                "search_id": "SRCH-07",
                "name": "TLS certificates expiring soon",
                "query": 'message:"expiring in" AND category:Endpoint',
                "owner": "Priya Nair",
                "scope": "Team",
                "pinned": False,
                "alerting": False,
                "hits": 3,
                "description": "Endpoint TLS certificates expiring within 30 days.",
            },
            {
                "search_id": "SRCH-08",
                "name": "Endpoint isolation events",
                "query": 'message:"Endpoint isolation triggered" OR action:blocked',
                "owner": "Aria Reyes",
                "scope": "Team",
                "pinned": True,
                "alerting": True,
                "hits": 5,
                "description": "Critical host isolation containment actions triggered by EDR.",
            },
        ]
        try:
            for s in default_searches:
                search = SiemSavedSearch(
                    search_id=s["search_id"],
                    name=s["name"],
                    query=s["query"],
                    owner=s["owner"],
                    scope=s["scope"],
                    pinned=s["pinned"],
                    alerting=s["alerting"],
                    hits=s["hits"],
                    description=s["description"],
                    last_run=datetime.utcnow(),
                    filters_json="{}",
                )
                db.session.add(search)
            db.session.commit()
        except Exception:
            db.session.rollback()
