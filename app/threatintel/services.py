"""
CyberDefense XDR
Threat Intelligence Services

Business logic for IOC, campaign, feed and threat-actor management.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import or_

from app.extensions import db
from app.threatintel.models import (
    IOC,
    ThreatCampaign,
    ThreatFeed,
    ThreatActor,
)


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

def _parse_datetime(value):
    """Convert an ISO datetime string to datetime."""
    if not value:
        return None

    if isinstance(value, datetime):
        return value

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _clean_list(value):
    """Normalize a list-like value."""
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]

    return []


# ---------------------------------------------------------------------------
# IOC Services
# ---------------------------------------------------------------------------

def get_iocs(
    page=1,
    per_page=50,
    search=None,
    ioc_type=None,
    threat_level=None,
    status=None,
    source=None,
    campaign_id=None,
):
    """Return paginated IOC records with optional filters."""

    query = IOC.query

    if search:
        search_value = f"%{search}%"
        query = query.filter(
            or_(
                IOC.ioc_id.ilike(search_value),
                IOC.value.ilike(search_value),
                IOC.source.ilike(search_value),
                IOC.campaign_name.ilike(search_value),
                IOC.tags.ilike(search_value),
            )
        )

    if ioc_type:
        query = query.filter(IOC.type == ioc_type)

    if threat_level:
        query = query.filter(IOC.threat_level == threat_level)

    if status:
        query = query.filter(IOC.status == status)

    if source:
        query = query.filter(IOC.source == source)

    if campaign_id:
        query = query.filter(IOC.campaign_id == campaign_id)

    query = query.order_by(IOC.last_seen.desc())

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )

    return {
        "items": [ioc.to_dict() for ioc in pagination.items],
        "page": pagination.page,
        "per_page": pagination.per_page,
        "total": pagination.total,
        "pages": pagination.pages,
        "has_next": pagination.has_next,
        "has_prev": pagination.has_prev,
    }


def get_ioc(ioc_id):
    """Return a single IOC by public IOC ID."""
    return IOC.query.filter_by(ioc_id=ioc_id).first()


def create_ioc(data):
    """Create a new IOC."""

    value = (data.get("value") or "").strip()

    if not value:
        raise ValueError("IOC value is required")

    existing = IOC.query.filter_by(value=value).first()

    if existing:
        raise ValueError("IOC already exists")

    ioc = IOC(
        ioc_id=data.get("ioc_id") or _generate_ioc_id(),
        value=value,
        type=data.get("type", "ip"),
        threat_level=data.get("threat_level", data.get("threatLevel", "medium")),
        confidence=data.get("confidence", "Medium"),
        source=data.get("source", "Manual"),
        first_seen=_parse_datetime(
            data.get("first_seen", data.get("firstSeen"))
        ) or datetime.utcnow(),
        last_seen=_parse_datetime(
            data.get("last_seen", data.get("lastSeen"))
        ) or datetime.utcnow(),
        sightings=int(data.get("sightings", 0) or 0),
        campaign_id=data.get("campaign_id", data.get("campaignId")),
        campaign_name=data.get("campaign_name", data.get("campaignName")),
        status=data.get("status", "active"),
    )

    ioc.set_tags(
        data.get("tags", [])
    )

    db.session.add(ioc)
    db.session.commit()

    return ioc


def update_ioc(ioc_id, data):
    """Update an existing IOC."""

    ioc = get_ioc(ioc_id)

    if not ioc:
        return None

    field_map = {
        "value": "value",
        "type": "type",
        "threat_level": "threat_level",
        "threatLevel": "threat_level",
        "confidence": "confidence",
        "source": "source",
        "sightings": "sightings",
        "campaign_id": "campaign_id",
        "campaignId": "campaign_id",
        "campaign_name": "campaign_name",
        "campaignName": "campaign_name",
        "status": "status",
    }

    for incoming, model_field in field_map.items():
        if incoming not in data:
            continue

        value = data[incoming]

        if model_field == "sightings":
            try:
                value = int(value)
            except (TypeError, ValueError):
                value = 0

        setattr(ioc, model_field, value)

    if "tags" in data:
        ioc.set_tags(data["tags"])

    if "first_seen" in data or "firstSeen" in data:
        ioc.first_seen = _parse_datetime(
            data.get("first_seen", data.get("firstSeen"))
        )

    if "last_seen" in data or "lastSeen" in data:
        ioc.last_seen = _parse_datetime(
            data.get("last_seen", data.get("lastSeen"))
        )

    ioc.updated_at = datetime.utcnow()

    db.session.commit()

    return ioc


def update_ioc_status(ioc_id, status):
    """Update IOC status."""

    ioc = get_ioc(ioc_id)

    if not ioc:
        return None

    allowed = {
        "active",
        "blocked",
        "expired",
        "whitelisted",
    }

    if status not in allowed:
        raise ValueError(
            f"Invalid IOC status. Allowed values: {', '.join(sorted(allowed))}"
        )

    ioc.status = status
    ioc.updated_at = datetime.utcnow()

    db.session.commit()

    return ioc


def delete_ioc(ioc_id):
    """Delete an IOC."""

    ioc = get_ioc(ioc_id)

    if not ioc:
        return False

    db.session.delete(ioc)
    db.session.commit()

    return True


def get_ioc_statistics():
    """Return IOC statistics used by the Threat Intelligence dashboard."""

    total = IOC.query.count()

    active = IOC.query.filter_by(status="active").count()

    critical = IOC.query.filter_by(threat_level="critical").count()

    high = IOC.query.filter_by(threat_level="high").count()

    medium = IOC.query.filter_by(threat_level="medium").count()

    low = IOC.query.filter_by(threat_level="low").count()

    blocked = IOC.query.filter_by(status="blocked").count()

    expired = IOC.query.filter_by(status="expired").count()

    whitelisted = IOC.query.filter_by(status="whitelisted").count()

    type_distribution = {}

    for ioc in IOC.query.with_entities(IOC.type).all():
        value = ioc[0] or "unknown"
        type_distribution[value] = type_distribution.get(value, 0) + 1

    return {
        "total": total,
        "active": active,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "blocked": blocked,
        "expired": expired,
        "whitelisted": whitelisted,
        "type_distribution": type_distribution,
    }


def _generate_ioc_id():
    """Generate a public IOC identifier."""

    latest = (
        IOC.query
        .order_by(IOC.id.desc())
        .first()
    )

    next_number = (latest.id + 1) if latest else 1

    return f"IOC-{next_number:06d}"


# ---------------------------------------------------------------------------
# Campaign Services
# ---------------------------------------------------------------------------

def get_campaigns(
    page=1,
    per_page=50,
    search=None,
    status=None,
    actor_id=None,
):
    """Return paginated threat campaigns."""

    query = ThreatCampaign.query

    if search:
        search_value = f"%{search}%"

        query = query.filter(
            or_(
                ThreatCampaign.campaign_id.ilike(search_value),
                ThreatCampaign.name.ilike(search_value),
                ThreatCampaign.actor_name.ilike(search_value),
                ThreatCampaign.description.ilike(search_value),
            )
        )

    if status:
        query = query.filter(ThreatCampaign.status == status)

    if actor_id:
        query = query.filter(ThreatCampaign.actor_id == actor_id)

    query = query.order_by(
        ThreatCampaign.first_observed.desc()
    )

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )

    return {
        "items": [campaign.to_dict() for campaign in pagination.items],
        "page": pagination.page,
        "per_page": pagination.per_page,
        "total": pagination.total,
        "pages": pagination.pages,
        "has_next": pagination.has_next,
        "has_prev": pagination.has_prev,
    }


def get_campaign(campaign_id):
    """Return a campaign by public ID."""

    return ThreatCampaign.query.filter_by(
        campaign_id=campaign_id
    ).first()


def create_campaign(data):
    """Create a threat campaign."""

    name = (data.get("name") or "").strip()

    if not name:
        raise ValueError("Campaign name is required")

    campaign = ThreatCampaign(
        campaign_id=data.get("campaign_id", data.get("id"))
        or _generate_campaign_id(),
        name=name,
        actor_id=data.get("actor_id", data.get("actorId")),
        actor_name=data.get("actor_name", data.get("actorName")),
        status=data.get("status", "active"),
        first_observed=_parse_datetime(
            data.get("first_observed", data.get("firstObserved"))
        ) or datetime.utcnow(),
        ioc_count=int(data.get("ioc_count", data.get("iocCount", 0)) or 0),
        description=data.get("description"),
    )

    campaign.set_target_sectors(
        data.get("target_sectors", data.get("targetSectors", []))
    )

    campaign.set_ttps(
        data.get("ttps", [])
    )

    db.session.add(campaign)
    db.session.commit()

    return campaign


def update_campaign(campaign_id, data):
    """Update a campaign."""

    campaign = get_campaign(campaign_id)

    if not campaign:
        return None

    fields = {
        "name": "name",
        "actor_id": "actor_id",
        "actorId": "actor_id",
        "actor_name": "actor_name",
        "actorName": "actor_name",
        "status": "status",
        "ioc_count": "ioc_count",
        "iocCount": "ioc_count",
        "description": "description",
    }

    for incoming, model_field in fields.items():
        if incoming in data:
            setattr(campaign, model_field, data[incoming])

    if "first_observed" in data or "firstObserved" in data:
        campaign.first_observed = _parse_datetime(
            data.get("first_observed", data.get("firstObserved"))
        )

    if "target_sectors" in data or "targetSectors" in data:
        campaign.set_target_sectors(
            data.get("target_sectors", data.get("targetSectors"))
        )

    if "ttps" in data:
        campaign.set_ttps(data["ttps"])

    campaign.updated_at = datetime.utcnow()

    db.session.commit()

    return campaign


def delete_campaign(campaign_id):
    """Delete a campaign."""

    campaign = get_campaign(campaign_id)

    if not campaign:
        return False

    db.session.delete(campaign)
    db.session.commit()

    return True


def _generate_campaign_id():
    latest = (
        ThreatCampaign.query
        .order_by(ThreatCampaign.id.desc())
        .first()
    )

    next_number = (latest.id + 1) if latest else 1

    return f"CMP-{next_number:05d}"


# ---------------------------------------------------------------------------
# Feed Services
# ---------------------------------------------------------------------------

def get_feeds(
    page=1,
    per_page=50,
    search=None,
    status=None,
    provider=None,
):
    """Return paginated threat intelligence feeds."""

    query = ThreatFeed.query

    if search:
        search_value = f"%{search}%"

        query = query.filter(
            or_(
                ThreatFeed.feed_id.ilike(search_value),
                ThreatFeed.name.ilike(search_value),
                ThreatFeed.provider.ilike(search_value),
                ThreatFeed.feed_type.ilike(search_value),
            )
        )

    if status:
        query = query.filter(ThreatFeed.status == status)

    if provider:
        query = query.filter(ThreatFeed.provider == provider)

    query = query.order_by(
        ThreatFeed.last_sync.desc()
    )

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )

    return {
        "items": [feed.to_dict() for feed in pagination.items],
        "page": pagination.page,
        "per_page": pagination.per_page,
        "total": pagination.total,
        "pages": pagination.pages,
        "has_next": pagination.has_next,
        "has_prev": pagination.has_prev,
    }


def get_feed(feed_id):
    """Return a feed by public ID."""

    return ThreatFeed.query.filter_by(
        feed_id=feed_id
    ).first()


def create_feed(data):
    """Create a threat intelligence feed."""

    name = (data.get("name") or "").strip()

    if not name:
        raise ValueError("Feed name is required")

    feed = ThreatFeed(
        feed_id=data.get("feed_id", data.get("id"))
        or _generate_feed_id(),
        name=name,
        provider=data.get("provider"),
        feed_type=data.get("feed_type", data.get("type", "Open Source")),
        status=data.get("status", "active"),
        ioc_count=int(data.get("ioc_count", data.get("iocCount", 0)) or 0),
        last_sync=_parse_datetime(
            data.get("last_sync", data.get("lastSync"))
        ),
        reliability=data.get("reliability"),
    )

    db.session.add(feed)
    db.session.commit()

    return feed


def update_feed(feed_id, data):
    """Update a threat intelligence feed."""

    feed = get_feed(feed_id)

    if not feed:
        return None

    fields = {
        "name": "name",
        "provider": "provider",
        "feed_type": "feed_type",
        "type": "feed_type",
        "status": "status",
        "ioc_count": "ioc_count",
        "iocCount": "ioc_count",
        "reliability": "reliability",
    }

    for incoming, model_field in fields.items():
        if incoming not in data:
            continue

        value = data[incoming]

        if model_field == "ioc_count":
            try:
                value = int(value)
            except (TypeError, ValueError):
                value = 0

        setattr(feed, model_field, value)

    if "last_sync" in data or "lastSync" in data:
        feed.last_sync = _parse_datetime(
            data.get("last_sync", data.get("lastSync"))
        )

    feed.updated_at = datetime.utcnow()

    db.session.commit()

    return feed


def update_feed_status(feed_id, status):
    """Update feed status."""

    feed = get_feed(feed_id)

    if not feed:
        return None

    allowed = {
        "active",
        "inactive",
        "error",
        "syncing",
    }

    if status not in allowed:
        raise ValueError(
            f"Invalid feed status. Allowed values: {', '.join(sorted(allowed))}"
        )

    feed.status = status
    feed.updated_at = datetime.utcnow()

    db.session.commit()

    return feed


def delete_feed(feed_id):
    """Delete a threat feed."""

    feed = get_feed(feed_id)

    if not feed:
        return False

    db.session.delete(feed)
    db.session.commit()

    return True


def _generate_feed_id():
    latest = (
        ThreatFeed.query
        .order_by(ThreatFeed.id.desc())
        .first()
    )

    next_number = (latest.id + 1) if latest else 1

    return f"FEED-{next_number:05d}"


# ---------------------------------------------------------------------------
# Threat Actor Services
# ---------------------------------------------------------------------------

def get_actors(
    page=1,
    per_page=50,
    search=None,
    origin=None,
    sophistication=None,
):
    """Return paginated threat actors."""

    query = ThreatActor.query

    if search:
        search_value = f"%{search}%"

        query = query.filter(
            or_(
                ThreatActor.actor_id.ilike(search_value),
                ThreatActor.name.ilike(search_value),
                ThreatActor.origin.ilike(search_value),
                ThreatActor.motivation.ilike(search_value),
                ThreatActor.description.ilike(search_value),
            )
        )

    if origin:
        query = query.filter(ThreatActor.origin == origin)

    if sophistication:
        query = query.filter(
            ThreatActor.sophistication == sophistication
        )

    query = query.order_by(
        ThreatActor.last_activity.desc()
    )

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )

    return {
        "items": [actor.to_dict() for actor in pagination.items],
        "page": pagination.page,
        "per_page": pagination.per_page,
        "total": pagination.total,
        "pages": pagination.pages,
        "has_next": pagination.has_next,
        "has_prev": pagination.has_prev,
    }


def get_actor(actor_id):
    """Return a threat actor by public ID."""

    return ThreatActor.query.filter_by(
        actor_id=actor_id
    ).first()


def create_actor(data):
    """Create a threat actor."""

    name = (data.get("name") or "").strip()

    if not name:
        raise ValueError("Threat actor name is required")

    actor = ThreatActor(
        actor_id=data.get("actor_id", data.get("id"))
        or _generate_actor_id(),
        name=name,
        origin=data.get("origin"),
        sophistication=data.get("sophistication"),
        motivation=data.get("motivation"),
        campaign_count=int(
            data.get(
                "campaign_count",
                data.get("campaignCount", 0),
            ) or 0
        ),
        last_activity=_parse_datetime(
            data.get("last_activity", data.get("lastActivity"))
        ),
        first_seen=_parse_datetime(
            data.get("first_seen", data.get("firstSeen"))
        ) or datetime.utcnow(),
        description=data.get("description"),
    )

    actor.set_target_sectors(
        data.get(
            "target_sectors",
            data.get("targetSectors", []),
        )
    )

    actor.set_mitre_tactics(
        data.get("mitre_tactics", data.get("mitreTactics", []))
    )

    db.session.add(actor)
    db.session.commit()

    return actor


def update_actor(actor_id, data):
    """Update a threat actor."""

    actor = get_actor(actor_id)

    if not actor:
        return None

    fields = {
        "name": "name",
        "origin": "origin",
        "sophistication": "sophistication",
        "motivation": "motivation",
        "campaign_count": "campaign_count",
        "campaignCount": "campaign_count",
        "description": "description",
    }

    for incoming, model_field in fields.items():
        if incoming not in data:
            continue

        value = data[incoming]

        if model_field == "campaign_count":
            try:
                value = int(value)
            except (TypeError, ValueError):
                value = 0

        setattr(actor, model_field, value)

    if "last_activity" in data or "lastActivity" in data:
        actor.last_activity = _parse_datetime(
            data.get("last_activity", data.get("lastActivity"))
        )

    if "first_seen" in data or "firstSeen" in data:
        actor.first_seen = _parse_datetime(
            data.get("first_seen", data.get("firstSeen"))
        )

    if "target_sectors" in data or "targetSectors" in data:
        actor.set_target_sectors(
            data.get("target_sectors", data.get("targetSectors"))
        )

    if "mitre_tactics" in data or "mitreTactics" in data:
        actor.set_mitre_tactics(
            data.get("mitre_tactics", data.get("mitreTactics"))
        )

    actor.updated_at = datetime.utcnow()

    db.session.commit()

    return actor


def delete_actor(actor_id):
    """Delete a threat actor."""

    actor = get_actor(actor_id)

    if not actor:
        return False

    db.session.delete(actor)
    db.session.commit()

    return True


def _generate_actor_id():
    latest = (
        ThreatActor.query
        .order_by(ThreatActor.id.desc())
        .first()
    )

    next_number = (latest.id + 1) if latest else 1

    return f"ACT-{next_number:05d}"


# ---------------------------------------------------------------------------
# Dashboard Services
# ---------------------------------------------------------------------------

def get_dashboard_statistics():
    """Return aggregated Threat Intelligence dashboard data."""

    ioc_stats = get_ioc_statistics()

    total_campaigns = ThreatCampaign.query.count()

    active_campaigns = ThreatCampaign.query.filter_by(
        status="active"
    ).count()

    total_feeds = ThreatFeed.query.count()

    active_feeds = ThreatFeed.query.filter_by(
        status="active"
    ).count()

    total_actors = ThreatActor.query.count()

    return {
        "iocs": ioc_stats,
        "campaigns": {
            "total": total_campaigns,
            "active": active_campaigns,
        },
        "feeds": {
            "total": total_feeds,
            "active": active_feeds,
        },
        "actors": {
            "total": total_actors,
        },
    }


# ---------------------------------------------------------------------------
# Relationship / enrichment helpers
# ---------------------------------------------------------------------------

def get_campaign_iocs(campaign_id):
    """Return all IOCs associated with a campaign."""

    return [
        ioc.to_dict()
        for ioc in IOC.query.filter_by(
            campaign_id=campaign_id
        ).order_by(IOC.last_seen.desc()).all()
    ]


def get_actor_campaigns(actor_id):
    """Return all campaigns associated with a threat actor."""

    return [
        campaign.to_dict()
        for campaign in ThreatCampaign.query.filter_by(
            actor_id=actor_id
        ).order_by(ThreatCampaign.first_observed.desc()).all()
    ]


def enrich_ioc(ioc_value):
    """
    Find an IOC by value.

    This is the basic enrichment entry point that can later be
    connected to Detection Engine and Alert Center.
    """

    if not ioc_value:
        return None

    ioc = IOC.query.filter_by(value=ioc_value.strip()).first()

    if not ioc:
        return None

    return ioc.to_dict()