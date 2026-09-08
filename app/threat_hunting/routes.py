"""
CyberDefense XDR
Threat Hunting Routes & REST APIs
"""

from flask import render_template, request, jsonify
from flask_login import login_required, current_user
import logging

from app.threat_hunting import threat_hunting
from app.threat_hunting.services import (
    execute_hunt,
    get_entity_profile,
    get_hunting_summary,
    record_hunt_query,
    detect_entity_type,
)
from app.threat_hunting.models import ThreatHuntQuery

logger = logging.getLogger("cyberdefense.threat_hunting")


@threat_hunting.route("/")
@threat_hunting.route("/dashboard")
@login_required
def dashboard():
    """Renders the primary Threat Hunting investigation interface."""
    return render_template("threat_hunting/dashboard.html")


@threat_hunting.route("/api/summary", methods=["GET"])
@login_required
def api_summary():
    """Returns overview statistics of searchable XDR telemetry."""
    data = get_hunting_summary()
    summary = {
        "total_assets": data["stats"]["total_assets"],
        "active_alerts": data["stats"]["alerts_24h"],
        "ids_threat_events": data["stats"]["ids_threats_24h"],
        "siem_events_24h": data["stats"]["siem_logs_24h"],
        "active_iocs": data["stats"]["total_iocs"],
        **data["stats"],
    }
    return jsonify({
        "status": "success",
        "success": True,
        "summary": summary,
        "recent_queries": data.get("recent_queries", []),
        "saved_hunts": data.get("saved_hunts", []),
    })


@threat_hunting.route("/api/search", methods=["POST"])
@login_required
def api_search():
    """
    Executes a multi-domain hunt search.
    Body: { query, search_type, time_range, severity, source_module, limit, page, save_query }
    """
    payload = request.get_json(silent=True) or {}
    query_text = payload.get("query", "").strip()

    if not query_text:
        return jsonify({"success": False, "status": "error", "error": "Query string cannot be empty"}), 400

    search_type = payload.get("search_type")
    time_range = payload.get("time_range", "7d")
    start_date = payload.get("start_date")
    end_date = payload.get("end_date")
    severity = payload.get("severity")
    source_module = payload.get("source_module")
    limit = min(max(int(payload.get("limit", 50)), 5), 200)
    page = max(int(payload.get("page", 1)), 1)
    save_query = bool(payload.get("save_query", False) or payload.get("save", False))
    title = payload.get("title") or payload.get("name")

    try:
        results = execute_hunt(
            query_text=query_text,
            search_type=search_type,
            time_range=time_range,
            start_date=start_date,
            end_date=end_date,
            severity=severity,
            source_module=source_module,
            page=page,
            limit=limit,
        )

        results["status"] = "success"
        results["query"] = query_text
        results["results"] = results.get("results_by_module", {})
        results["entity_type"] = results.get("detected_type", "auto")

        user_id = getattr(current_user, "id", None)
        record_hunt_query(
            query_text=query_text,
            entity_type=results["detected_type"],
            result_count=results["total_matches"],
            user_id=user_id,
            filters={
                "time_range": time_range,
                "severity": severity,
                "source_module": source_module,
            },
            title=title,
            is_saved=save_query,
        )

        return jsonify(results)
    except Exception as e:
        logger.error(f"Threat hunting search error: {e}", exc_info=True)
        return jsonify({"success": False, "status": "error", "error": f"Search failed: {str(e)}"}), 500


@threat_hunting.route("/api/timeline", methods=["GET"])
@login_required
def api_timeline():
    """
    Returns unified chronological threat timeline for a query string.
    Query params: q, range, limit
    """
    query_text = request.args.get("q", "").strip()
    time_range = request.args.get("range", "7d")
    limit = min(max(int(request.args.get("limit", 100)), 10), 300)

    if not query_text:
        return jsonify({"success": False, "error": "Query parameter 'q' is required"}), 400

    try:
        results = execute_hunt(
            query_text=query_text,
            time_range=time_range,
            limit=limit,
        )
        return jsonify({
            "success": True,
            "query": query_text,
            "time_range": results["time_range"],
            "total_events": len(results["timeline"]),
            "timeline": results["timeline"],
        })
    except Exception as e:
        logger.error(f"Threat timeline error: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@threat_hunting.route("/api/entity/<entity_type>/<path:entity_id>", methods=["GET"])
@login_required
def api_entity(entity_type, entity_id):
    """
    Returns 360-degree security profile for a given entity.
    """
    try:
        data = get_entity_profile(entity_type, entity_id)
        if not data.get("success"):
            return jsonify(data), 404
        return jsonify(data)
    except Exception as e:
        logger.error(f"Entity profile lookup error for {entity_type}/{entity_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@threat_hunting.route("/api/history", methods=["GET"])
@login_required
def api_history():
    """Returns analyst search history."""
    queries = (
        ThreatHuntQuery.query.order_by(ThreatHuntQuery.created_at.desc())
        .limit(50)
        .all()
    )
    return jsonify({
        "success": True,
        "history": [q.to_dict() for q in queries],
    })


@threat_hunting.route("/api/saved-searches", methods=["GET", "POST"])
@login_required
def api_saved_searches():
    """Returns or saves bookmarked hunting searches."""
    if request.method == "GET":
        saved = (
            ThreatHuntQuery.query.filter_by(is_saved=True)
            .order_by(ThreatHuntQuery.created_at.desc())
            .limit(50)
            .all()
        )
        return jsonify({
            "status": "success",
            "success": True,
            "saved": [s.to_dict() for s in saved],
        })

    payload = request.get_json(silent=True) or {}
    query_text = payload.get("query_text", "").strip() or payload.get("query", "").strip()
    title = payload.get("title", "").strip() or payload.get("name", "").strip() or query_text

    if not query_text:
        return jsonify({"success": False, "status": "error", "error": "query_text is required"}), 400

    entity_type = payload.get("entity_type") or payload.get("search_type") or detect_entity_type(query_text)
    user_id = getattr(current_user, "id", None)

    record = record_hunt_query(
        query_text=query_text,
        entity_type=entity_type,
        result_count=payload.get("result_count", 0),
        user_id=user_id,
        filters=payload.get("filters", {}),
        title=title,
        is_saved=True,
    )

    return jsonify({
        "status": "success",
        "success": True,
        "saved_search": record.to_dict(),
    }), 201
