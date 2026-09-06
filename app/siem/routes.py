"""
CyberDefense XDR
SIEM & Log Explorer Routes & REST APIs
"""

from flask import (
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
)
from flask_login import current_user

from app.siem import siem
from app.siem import services


# ============================================================
# PAGE ROUTES
# ============================================================

@siem.route("/")
@siem.route("/dashboard")
def index():
    """Renders the main SIEM Dashboard."""
    # Ensure initial data exists if starting with fresh database
    try:
        services.seed_initial_siem_data()
    except Exception:
        pass

    return render_template("siem/siem.html")


@siem.route("/log-explorer")
def log_explorer():
    """Renders the Log Explorer page."""
    try:
        services.seed_initial_siem_data()
    except Exception:
        pass

    return render_template("siem/log_explorer.html")


@siem.route("/log-details")
@siem.route("/log-details/<event_id>")
def log_details(event_id=None):
    """Renders the Log Details page."""
    try:
        services.seed_initial_siem_data()
    except Exception:
        pass

    selected_id = event_id or request.args.get("id")
    return render_template("siem/log_details.html", log_id=selected_id)


@siem.route("/saved-searches")
def saved_searches():
    """Renders the Saved Searches library."""
    try:
        services.seed_initial_siem_data()
    except Exception:
        pass

    return render_template("siem/saved_searches.html")


# ============================================================
# REST API ENDPOINTS
# ============================================================

@siem.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    """Returns aggregated SIEM Dashboard metrics, charts, and stream."""
    try:
        services.seed_initial_siem_data()
        data = services.get_siem_dashboard_stats()
        return jsonify({
            "success": True,
            "data": data,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to compute SIEM dashboard statistics: {str(e)}",
        }), 500


@siem.route("/api/logs", methods=["GET"])
def api_logs():
    """Returns paginated, searchable, and filtered log events."""
    try:
        services.seed_initial_siem_data()

        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", request.args.get("limit", 10, type=int), type=int)
        sort_key = request.args.get("sort_key", "ts")
        sort_dir = request.args.get("sort_dir", "desc")

        filters = {
            "sev": request.args.get("sev") or request.args.get("severity"),
            "source": request.args.get("source"),
            "host": request.args.get("host"),
            "category": request.args.get("category"),
            "tag": request.args.get("tag"),
            "timeRange": request.args.get("timeRange") or request.args.get("time_range"),
            "query": request.args.get("q") or request.args.get("query"),
        }

        result = services.get_logs(
            filters=filters,
            page=page,
            per_page=per_page,
            sort_key=sort_key,
            sort_dir=sort_dir,
        )

        return jsonify({
            "success": True,
            "data": result["items"],
            "pagination": {
                "total": result["total"],
                "page": result["page"],
                "per_page": result["per_page"],
                "pages": result["pages"],
            },
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve log events: {str(e)}",
        }), 500


@siem.route("/api/logs/filter-options", methods=["GET"])
def api_filter_options():
    """Returns unique sources, hosts, categories, and tags for filter dropdowns."""
    try:
        services.seed_initial_siem_data()
        options = services.get_filter_options()
        return jsonify({
            "success": True,
            "data": options,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to load filter options: {str(e)}",
        }), 500


@siem.route("/api/logs/<event_id>", methods=["GET"])
def api_log_detail(event_id):
    """Returns detailed event information and related events for an event_id."""
    try:
        services.seed_initial_siem_data()
        log_data = services.get_log_by_event_id(event_id)
        if not log_data:
            return jsonify({
                "success": False,
                "message": f"Log event '{event_id}' not found.",
            }), 404

        return jsonify({
            "success": True,
            "data": log_data,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to retrieve log detail: {str(e)}",
        }), 500


@siem.route("/api/events", methods=["POST"])
def api_ingest_event():
    """
    Ingests one or more log events into the SIEM pipeline.
    Performs Threat Intel correlation and Detection Engine triggers.
    """
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({
            "success": False,
            "message": "Missing JSON payload.",
        }), 400

    try:
        if isinstance(payload, list):
            events = services.ingest_events_bulk(payload)
            return jsonify({
                "success": True,
                "message": f"Successfully ingested {len(events)} security events.",
                "count": len(events),
            }), 201

        event = services.ingest_event(payload)
        return jsonify({
            "success": True,
            "message": f"Security event '{event.event_id}' ingested successfully.",
            "data": event.to_dict(),
        }), 201
    except ValueError as ve:
        return jsonify({
            "success": False,
            "message": str(ve),
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to ingest security event: {str(e)}",
        }), 500


@siem.route("/api/saved-searches", methods=["GET"])
def api_get_saved_searches():
    """Returns saved searches list with optional filtering."""
    try:
        services.seed_initial_siem_data()
        scope = request.args.get("scope")
        alerting = request.args.get("alerting")
        search = request.args.get("q") or request.args.get("search")

        searches = services.get_saved_searches(scope=scope, alerting=alerting, search=search)
        return jsonify({
            "success": True,
            "data": searches,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to load saved searches: {str(e)}",
        }), 500


@siem.route("/api/saved-searches", methods=["POST"])
def api_create_saved_search():
    """Creates a new saved search."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "success": False,
            "message": "Missing JSON payload.",
        }), 400

    try:
        owner_name = "Analyst"
        if hasattr(current_user, "is_authenticated") and current_user.is_authenticated:
            owner_name = getattr(current_user, "username", "Analyst")

        saved = services.create_saved_search(data, owner=owner_name)
        return jsonify({
            "success": True,
            "message": f"Saved search '{saved.name}' created.",
            "data": saved.to_dict(),
        }), 201
    except ValueError as ve:
        return jsonify({
            "success": False,
            "message": str(ve),
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to create saved search: {str(e)}",
        }), 500


@siem.route("/api/saved-searches/<search_id>/pin", methods=["POST"])
def api_toggle_pin(search_id):
    """Toggles pinned status for a saved search."""
    try:
        updated = services.toggle_pin_saved_search(search_id)
        if not updated:
            return jsonify({
                "success": False,
                "message": f"Saved search '{search_id}' not found.",
            }), 404

        return jsonify({
            "success": True,
            "message": f"Search '{updated.name}' {'pinned to' if updated.pinned else 'unpinned from'} SIEM dashboard.",
            "pinned": updated.pinned,
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to toggle pin: {str(e)}",
        }), 500


@siem.route("/api/saved-searches/<search_id>", methods=["DELETE"])
def api_delete_saved_search(search_id):
    """Deletes a saved search."""
    try:
        deleted = services.delete_saved_search(search_id)
        if not deleted:
            return jsonify({
                "success": False,
                "message": f"Saved search '{search_id}' not found.",
            }), 404

        return jsonify({
            "success": True,
            "message": f"Saved search '{search_id}' deleted successfully.",
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to delete saved search: {str(e)}",
        }), 500

