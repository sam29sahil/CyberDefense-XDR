"""
CyberDefense XDR
Asset Management Blueprint Routes & APIs
Provides Web page views and RESTful APIs for asset inventory, details,
CRUD operations, dynamic risk evaluations, and cross-module correlations.
"""

from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app.assets import assets
from app.assets.services import (
    create_asset,
    update_asset,
    delete_asset,
    get_asset,
    list_assets,
    get_asset_inventory_stats,
    get_asset_security_details,
    refresh_asset_security_summary,
    trigger_asset_scan,
    rescan_inventory,
)


# ==============================================================================
# HTML Page Views
# ==============================================================================

@assets.route("/")
@assets.route("/inventory")
@login_required
def index():
    """Renders the Asset Management inventory page."""
    return render_template("assets/assets.html")


@assets.route("/<asset_id>", methods=["GET"])
@login_required
def asset_details(asset_id):
    """Renders the detailed Asset view."""
    asset = get_asset(asset_id)
    if not asset:
        flash("Asset not found.", "warning")
        return redirect(url_for("assets.index"))

    return render_template(
        "assets/asset_details.html",
        asset=asset,
        asset_id=asset.asset_id,
    )


# ==============================================================================
# REST APIs
# ==============================================================================

@assets.route("/api/stats", methods=["GET"])
@login_required
def api_stats():
    """Returns real-time inventory statistics computed from PostgreSQL."""
    try:
        stats = get_asset_inventory_stats()
        return jsonify({"success": True, **stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@assets.route("/api", methods=["GET"])
@login_required
def api_list_assets():
    """Returns paginated, searchable, filterable list of assets."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        sort_by = request.args.get("sort_by", "created_at")
        sort_dir = request.args.get("sort_dir", "desc")

        filters = {
            "search": request.args.get("search") or request.args.get("q"),
            "asset_type": request.args.get("type") or request.args.get("asset_type"),
            "environment": request.args.get("env") or request.args.get("environment"),
            "criticality": request.args.get("criticality"),
            "status": request.args.get("status"),
            "risk_severity": request.args.get("sev") or request.args.get("risk_severity"),
        }

        res = list_assets(filters=filters, page=page, per_page=per_page, sort_by=sort_by, sort_dir=sort_dir)
        return jsonify({"success": True, **res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@assets.route("/api", methods=["POST"])
@login_required
def api_create_asset():
    """Creates a new asset with server-side validation."""
    data = request.get_json(silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"success": False, "error": "No JSON or form data received."}), 400

    try:
        asset = create_asset(data)
        return jsonify({
            "success": True,
            "message": f"Asset '{asset.name}' created successfully.",
            "asset": asset.to_dict(include_details=True),
        }), 201
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to create asset: {e}"}), 500


@assets.route("/api/<asset_id>", methods=["GET"])
@login_required
def api_get_asset(asset_id):
    """Returns single asset metadata and configuration."""
    asset = get_asset(asset_id)
    if not asset:
        return jsonify({"success": False, "error": f"Asset '{asset_id}' not found."}), 404

    return jsonify({"success": True, "asset": asset.to_dict(include_details=True)})


@assets.route("/api/<asset_id>", methods=["PUT", "PATCH"])
@login_required
def api_update_asset(asset_id):
    """Updates permitted asset attributes."""
    data = request.get_json(silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"success": False, "error": "No data received."}), 400

    try:
        asset = update_asset(asset_id, data)
        return jsonify({
            "success": True,
            "message": f"Asset '{asset.name}' updated successfully.",
            "asset": asset.to_dict(include_details=True),
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to update asset: {e}"}), 500


@assets.route("/api/<asset_id>", methods=["DELETE"])
@login_required
def api_delete_asset(asset_id):
    """Deletes or decommissions an asset."""
    soft = request.args.get("soft", "false").lower() in ("true", "1")
    try:
        delete_asset(asset_id, soft=soft)
        return jsonify({"success": True, "message": "Asset removed successfully."})
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to delete asset: {e}"}), 500


@assets.route("/api/<asset_id>/vulnerabilities", methods=["GET"])
@login_required
def api_asset_vulnerabilities(asset_id):
    """Returns real Vulnerability Scanner findings correlated with this asset."""
    try:
        details = get_asset_security_details(asset_id)
        return jsonify({
            "success": True,
            "asset_id": details["asset"]["asset_id"],
            "vulnerabilities": details["vulnerabilities"],
            "count": len(details["vulnerabilities"]),
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@assets.route("/api/<asset_id>/alerts", methods=["GET"])
@login_required
def api_asset_alerts(asset_id):
    """Returns real Alert Center alerts correlated with this asset."""
    try:
        details = get_asset_security_details(asset_id)
        return jsonify({
            "success": True,
            "asset_id": details["asset"]["asset_id"],
            "alerts": details["alerts"],
            "count": len(details["alerts"]),
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@assets.route("/api/<asset_id>/activity", methods=["GET"])
@login_required
def api_asset_activity(asset_id):
    """Returns correlated Incidents, SIEM events, and security timeline entries."""
    try:
        details = get_asset_security_details(asset_id)
        return jsonify({
            "success": True,
            "asset_id": details["asset"]["asset_id"],
            "incidents": details["incidents"],
            "siem_events": details["siem_events"],
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@assets.route("/api/<asset_id>/network", methods=["GET"])
@login_required
def api_asset_network(asset_id):
    """Returns open ports, services, and IDS traffic for this asset."""
    try:
        details = get_asset_security_details(asset_id)
        asset_dict = details["asset"]
        return jsonify({
            "success": True,
            "asset_id": asset_dict["asset_id"],
            "ip_address": asset_dict["ip_address"],
            "mac_address": asset_dict["mac_address"],
            "discovered_ports": asset_dict.get("discovered_ports", []),
            "discovered_services": asset_dict.get("discovered_services", []),
            "ids_events": details["ids_events"],
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@assets.route("/api/<asset_id>/scan", methods=["POST"])
@login_required
def api_asset_scan(asset_id):
    """Triggers an authorized scan via the existing Vulnerability Scanner."""
    data = request.get_json(silent=True) or {}
    scan_type = data.get("scan_type", "Quick Scan")
    user_id = current_user.id if current_user and current_user.is_authenticated else None

    try:
        scan = trigger_asset_scan(asset_id, scan_type=scan_type, user_id=user_id)
        return jsonify({
            "success": True,
            "message": f"Vulnerability scan started for asset (Scan #{scan.id}).",
            "scan_id": scan.id,
            "scan": scan.to_dict(),
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Scan execution failed: {e}"}), 500


@assets.route("/api/rescan", methods=["POST"])
@login_required
def api_rescan_inventory():
    """Triggers inventory discovery/refresh based on authorized targets."""
    try:
        result = rescan_inventory()
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

