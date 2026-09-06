"""
CyberDefense XDR
Threat Intelligence Routes
"""

from flask import jsonify, request, render_template

from app.threatintel import threatintel
from app.threatintel.services import (
    get_iocs,
    get_ioc,
    create_ioc,
    update_ioc,
    update_ioc_status,
    delete_ioc,
    get_ioc_statistics,
    get_campaigns,
    get_campaign,
    create_campaign,
    update_campaign,
    delete_campaign,
    get_campaign_iocs,
    get_feeds,
    get_feed,
    create_feed,
    update_feed,
    update_feed_status,
    delete_feed,
    get_actors,
    get_actor,
    create_actor,
    update_actor,
    delete_actor,
    get_actor_campaigns,
    get_dashboard_statistics,
    enrich_ioc,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_body():
    """Return a JSON request body or an empty dictionary."""
    return request.get_json(silent=True) or {}


def _pagination_params():
    """Read and normalize pagination parameters."""
    try:
        page = max(request.args.get("page", 1, type=int), 1)
    except (TypeError, ValueError):
        page = 1

    try:
        per_page = request.args.get("per_page", 50, type=int)
        per_page = min(max(per_page, 1), 100)
    except (TypeError, ValueError):
        per_page = 50

    return page, per_page


def _error(message, status=400):
    return jsonify({
        "success": False,
        "error": message,
    }), status


def _success(data=None, message=None, status=200):
    response = {
        "success": True,
    }

    if message:
        response["message"] = message

    if data is not None:
        response["data"] = data

    return jsonify(response), status


# ---------------------------------------------------------------------------
# Threat Intelligence Dashboard
# ---------------------------------------------------------------------------

@threatintel.get("/")
def index():
    """Threat Intelligence module entry point."""

    return _success({
        "module": "Threat Intelligence",
        "status": "online",
        "endpoints": {
            "dashboard": "/threat-intelligence/dashboard/data",
            "iocs": "/threat-intelligence/iocs",
            "campaigns": "/threat-intelligence/campaigns",
            "feeds": "/threat-intelligence/feeds",
            "actors": "/threat-intelligence/actors",
        },
    })

@threatintel.get("/dashboard")
def dashboard_page():
    """Render the Threat Intelligence dashboard."""

    return render_template("threatintel/threat-dashboard.html")    


@threatintel.get("/dashboard/data")
def dashboard_data():
    """Return aggregated Threat Intelligence dashboard data."""

    return _success(get_dashboard_statistics())


# ---------------------------------------------------------------------------
# IOC Routes
# ---------------------------------------------------------------------------

@threatintel.get("/iocs")
def ioc_list():
    """Return paginated IOC records."""

    page, per_page = _pagination_params()

    result = get_iocs(
        page=page,
        per_page=per_page,
        search=request.args.get("search"),
        ioc_type=request.args.get("type"),
        threat_level=request.args.get("threat_level"),
        status=request.args.get("status"),
        source=request.args.get("source"),
        campaign_id=request.args.get("campaign_id"),
    )

    return _success(result)


@threatintel.get("/iocs/statistics")
def ioc_statistics():
    """Return IOC statistics."""

    return _success(get_ioc_statistics())


@threatintel.get("/iocs/<string:ioc_id>")
def ioc_details(ioc_id):
    """Return a single IOC."""

    ioc = get_ioc(ioc_id)

    if not ioc:
        return _error("IOC not found", 404)

    return _success(ioc.to_dict())


@threatintel.post("/iocs")
def ioc_create():
    """Create a new IOC."""

    data = _json_body()

    try:
        ioc = create_ioc(data)
    except ValueError as exc:
        return _error(str(exc), 400)

    return _success(
        ioc.to_dict(),
        message="IOC created successfully",
        status=201,
    )


@threatintel.put("/iocs/<string:ioc_id>")
@threatintel.patch("/iocs/<string:ioc_id>")
def ioc_update(ioc_id):
    """Update an IOC."""

    data = _json_body()

    try:
        ioc = update_ioc(ioc_id, data)
    except ValueError as exc:
        return _error(str(exc), 400)

    if not ioc:
        return _error("IOC not found", 404)

    return _success(
        ioc.to_dict(),
        message="IOC updated successfully",
    )


@threatintel.patch("/iocs/<string:ioc_id>/status")
def ioc_status(ioc_id):
    """Update IOC status."""

    data = _json_body()
    status = data.get("status")

    if not status:
        return _error("Status is required")

    try:
        ioc = update_ioc_status(ioc_id, status)
    except ValueError as exc:
        return _error(str(exc), 400)

    if not ioc:
        return _error("IOC not found", 404)

    return _success(
        ioc.to_dict(),
        message="IOC status updated successfully",
    )


@threatintel.delete("/iocs/<string:ioc_id>")
def ioc_delete(ioc_id):
    """Delete an IOC."""

    if not delete_ioc(ioc_id):
        return _error("IOC not found", 404)

    return _success(
        message="IOC deleted successfully",
    )


@threatintel.get("/iocs/<string:ioc_id>/enrichment")
def ioc_enrichment(ioc_id):
    """Return enrichment data for an IOC."""

    ioc = get_ioc(ioc_id)

    if not ioc:
        return _error("IOC not found", 404)

    return _success(enrich_ioc(ioc.value))


# ---------------------------------------------------------------------------
# Campaign Routes
# ---------------------------------------------------------------------------

@threatintel.get("/campaigns")
def campaign_list():
    """Return paginated campaigns."""

    page, per_page = _pagination_params()

    result = get_campaigns(
        page=page,
        per_page=per_page,
        search=request.args.get("search"),
        status=request.args.get("status"),
        actor_id=request.args.get("actor_id"),
    )

    return _success(result)


@threatintel.get("/campaigns/<string:campaign_id>")
def campaign_details(campaign_id):
    """Return campaign details."""

    campaign = get_campaign(campaign_id)

    if not campaign:
        return _error("Campaign not found", 404)

    data = campaign.to_dict()
    data["iocs"] = get_campaign_iocs(campaign_id)

    return _success(data)


@threatintel.get("/campaigns/<string:campaign_id>/iocs")
def campaign_iocs(campaign_id):
    """Return IOCs belonging to a campaign."""

    campaign = get_campaign(campaign_id)

    if not campaign:
        return _error("Campaign not found", 404)

    return _success(get_campaign_iocs(campaign_id))


@threatintel.post("/campaigns")
def campaign_create():
    """Create a campaign."""

    data = _json_body()

    try:
        campaign = create_campaign(data)
    except ValueError as exc:
        return _error(str(exc), 400)

    return _success(
        campaign.to_dict(),
        message="Campaign created successfully",
        status=201,
    )


@threatintel.put("/campaigns/<string:campaign_id>")
@threatintel.patch("/campaigns/<string:campaign_id>")
def campaign_update(campaign_id):
    """Update a campaign."""

    data = _json_body()

    try:
        campaign = update_campaign(campaign_id, data)
    except ValueError as exc:
        return _error(str(exc), 400)

    if not campaign:
        return _error("Campaign not found", 404)

    return _success(
        campaign.to_dict(),
        message="Campaign updated successfully",
    )


@threatintel.delete("/campaigns/<string:campaign_id>")
def campaign_delete(campaign_id):
    """Delete a campaign."""

    if not delete_campaign(campaign_id):
        return _error("Campaign not found", 404)

    return _success(
        message="Campaign deleted successfully",
    )


# ---------------------------------------------------------------------------
# Feed Routes
# ---------------------------------------------------------------------------

@threatintel.get("/feeds")
def feed_list():
    """Return paginated threat feeds."""

    page, per_page = _pagination_params()

    result = get_feeds(
        page=page,
        per_page=per_page,
        search=request.args.get("search"),
        status=request.args.get("status"),
        provider=request.args.get("provider"),
    )

    return _success(result)


@threatintel.get("/feeds/<string:feed_id>")
def feed_details(feed_id):
    """Return feed details."""

    feed = get_feed(feed_id)

    if not feed:
        return _error("Feed not found", 404)

    return _success(feed.to_dict())


@threatintel.post("/feeds")
def feed_create():
    """Create a threat feed."""

    data = _json_body()

    try:
        feed = create_feed(data)
    except ValueError as exc:
        return _error(str(exc), 400)

    return _success(
        feed.to_dict(),
        message="Feed created successfully",
        status=201,
    )


@threatintel.put("/feeds/<string:feed_id>")
@threatintel.patch("/feeds/<string:feed_id>")
def feed_update(feed_id):
    """Update a threat feed."""

    data = _json_body()

    try:
        feed = update_feed(feed_id, data)
    except ValueError as exc:
        return _error(str(exc), 400)

    if not feed:
        return _error("Feed not found", 404)

    return _success(
        feed.to_dict(),
        message="Feed updated successfully",
    )


@threatintel.patch("/feeds/<string:feed_id>/status")
def feed_status(feed_id):
    """Update feed status."""

    data = _json_body()
    status = data.get("status")

    if not status:
        return _error("Status is required")

    try:
        feed = update_feed_status(feed_id, status)
    except ValueError as exc:
        return _error(str(exc), 400)

    if not feed:
        return _error("Feed not found", 404)

    return _success(
        feed.to_dict(),
        message="Feed status updated successfully",
    )


@threatintel.delete("/feeds/<string:feed_id>")
def feed_delete(feed_id):
    """Delete a threat feed."""

    if not delete_feed(feed_id):
        return _error("Feed not found", 404)

    return _success(
        message="Feed deleted successfully",
    )


# ---------------------------------------------------------------------------
# Threat Actor Routes
# ---------------------------------------------------------------------------

@threatintel.get("/actors")
def actor_list():
    """Return paginated threat actors."""

    page, per_page = _pagination_params()

    result = get_actors(
        page=page,
        per_page=per_page,
        search=request.args.get("search"),
        origin=request.args.get("origin"),
        sophistication=request.args.get("sophistication"),
    )

    return _success(result)


@threatintel.get("/actors/<string:actor_id>")
def actor_details(actor_id):
    """Return threat actor details."""

    actor = get_actor(actor_id)

    if not actor:
        return _error("Threat actor not found", 404)

    data = actor.to_dict()
    data["campaigns"] = get_actor_campaigns(actor_id)

    return _success(data)


@threatintel.get("/actors/<string:actor_id>/campaigns")
def actor_campaigns(actor_id):
    """Return campaigns associated with a threat actor."""

    actor = get_actor(actor_id)

    if not actor:
        return _error("Threat actor not found", 404)

    return _success(get_actor_campaigns(actor_id))


@threatintel.post("/actors")
def actor_create():
    """Create a threat actor."""

    data = _json_body()

    try:
        actor = create_actor(data)
    except ValueError as exc:
        return _error(str(exc), 400)

    return _success(
        actor.to_dict(),
        message="Threat actor created successfully",
        status=201,
    )


@threatintel.put("/actors/<string:actor_id>")
@threatintel.patch("/actors/<string:actor_id>")
def actor_update(actor_id):
    """Update a threat actor."""

    data = _json_body()

    try:
        actor = update_actor(actor_id, data)
    except ValueError as exc:
        return _error(str(exc), 400)

    if not actor:
        return _error("Threat actor not found", 404)

    return _success(
        actor.to_dict(),
        message="Threat actor updated successfully",
    )


@threatintel.delete("/actors/<string:actor_id>")
def actor_delete(actor_id):
    """Delete a threat actor."""

    if not delete_actor(actor_id):
        return _error("Threat actor not found", 404)

    return _success(
        message="Threat actor deleted successfully",
    )

@threatintel.get("/ioc-feed")
def ioc_feed_page():
    """Render the IOC feed page."""
    return render_template("threatintel/ioc-feed.html")


@threatintel.get("/ioc-details")
def ioc_details_page():
    """Render the IOC details page."""
    return render_template("threatintel/ioc-details.html")


@threatintel.get("/campaigns")
def campaigns_page():
    """Render the campaigns page."""
    return render_template("threatintel/campaigns.html")


@threatintel.get("/feeds")
def feeds_page():
    """Render the threat feeds page."""
    return render_template("threatintel/feeds.html")


@threatintel.get("/actors")
def actors_page():
    """Render the threat actors page."""
    return render_template("threatintel/actors.html")    