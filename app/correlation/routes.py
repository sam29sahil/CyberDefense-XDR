"""
CyberDefense XDR
Correlation Engine Routes
"""

from flask import render_template, request, jsonify
from flask_login import login_required
from app.user_management.decorators import permission_required
from app.correlation import correlation
from app.correlation.services import correlate_entity, find_campaigns


@correlation.route("/")
@login_required
@permission_required("correlation.view")
def dashboard():
    return render_template("correlation/dashboard.html")


@correlation.route("/api/entity/<entity_type>/<path:entity_id>", methods=["GET"])
@login_required
@permission_required("correlation.view")
def api_correlate_entity(entity_type, entity_id):
    """
    Returns full correlation data, risk scoring, and graph for a given entity.
    """
    try:
        data = correlate_entity(entity_type, entity_id)
        return jsonify({
            "status": "success",
            "correlation": data
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@correlation.route("/api/search", methods=["POST"])
@login_required
@permission_required("correlation.search")
def api_search_correlation():
    """
    Searches for relationships matching an input query entity.
    """
    payload = request.get_json(silent=True) or {}
    query = (payload.get("query") or "").strip()
    entity_type = (payload.get("entity_type") or "auto").strip()

    if not query:
        return jsonify({
            "status": "error",
            "message": "Query parameter is required"
        }), 400

    # Auto-detect type if auto
    if entity_type == "auto":
        from app.threat_hunting.services import detect_entity_type
        entity_type = detect_entity_type(query)

    try:
        data = correlate_entity(entity_type, query)
        return jsonify({
            "status": "success",
            "correlation": data
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@correlation.route("/api/graph/<entity_type>/<path:entity_id>", methods=["GET"])
@login_required
@permission_required("correlation.view")
def api_graph_data(entity_type, entity_id):
    """
    Returns nodes and links graph visualization payload.
    """
    try:
        data = correlate_entity(entity_type, entity_id)
        return jsonify({
            "status": "success",
            "graph": data.get("graph", {"nodes": [], "links": []})
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@correlation.route("/api/campaigns", methods=["GET"])
@login_required
@permission_required("correlation.view")
def api_campaigns():
    """
    Returns active cross-asset and multi-vector attack campaigns.
    """
    try:
        campaigns = find_campaigns()
        return jsonify({
            "status": "success",
            "campaigns": campaigns,
            "count": len(campaigns)
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

