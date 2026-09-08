"""
CyberDefense XDR
Packet Analysis Blueprint Routes & APIs
Provides Web interfaces and RESTful APIs for PCAP uploading, TShark-based analysis,
packet browsing, protocol hierarchies, conversations, and deep dissections.
"""

from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from app.packet_analysis import packet_analysis
from app.packet_analysis.services import (
    save_uploaded_pcap,
    run_pcap_analysis,
    get_analysis_by_id,
    get_packet_analyses,
    delete_analysis,
    get_analysis_packets,
    get_packet_detail,
    get_packet_analysis_dashboard_stats,
    MAX_PCAP_UPLOAD_MB,
)


# ==============================================================================
# HTML Page Views
# ==============================================================================

@packet_analysis.route("/")
@packet_analysis.route("/dashboard")
@login_required
def index():
    """Renders the Packet Analysis Dashboard view."""
    return render_template(
        "packet_analysis/dashboard.html",
        max_upload_mb=MAX_PCAP_UPLOAD_MB,
    )


@packet_analysis.route("/upload", methods=["GET"])
@login_required
def upload_page():
    """Renders the PCAP Upload page."""
    return render_template(
        "packet_analysis/upload.html",
        max_upload_mb=MAX_PCAP_UPLOAD_MB,
    )


@packet_analysis.route("/analyses/<analysis_id>", methods=["GET"])
@login_required
def analysis_details(analysis_id):
    """Renders the detailed Packet Analysis view with protocol charts and Wireshark inspector."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        flash("Packet analysis not found.", "warning")
        return redirect(url_for("packet_analysis.index"))

    return render_template(
        "packet_analysis/analysis_details.html",
        analysis=analysis,
        analysis_id=analysis.id,
        analysis_uuid=analysis.analysis_uuid,
    )


# ==============================================================================
# REST API Endpoints
# ==============================================================================

@packet_analysis.route("/api/dashboard", methods=["GET"])
@login_required
def api_dashboard():
    """Returns real-time KPIs and recent analysis summaries for the dashboard."""
    try:
        stats = get_packet_analysis_dashboard_stats()
        return jsonify({"success": True, **stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@packet_analysis.route("/api/analyses", methods=["GET"])
@login_required
def api_analyses_list():
    """Returns paginated, searchable list of PCAP analyses."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        filters = {
            "status": request.args.get("status"),
            "search": request.args.get("search") or request.args.get("q"),
        }
        res = get_packet_analyses(filters=filters, page=page, per_page=per_page)
        return jsonify({"success": True, **res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@packet_analysis.route("/api/upload", methods=["POST"])
@packet_analysis.route("/upload", methods=["POST"])
@login_required
def api_upload():
    """
    Accepts multipart/form-data upload of .pcap or .pcapng.
    Validates headers and SHA-256, then automatically enqueues/runs initial analysis.
    """
    if "pcap_file" not in request.files and "file" not in request.files:
        return jsonify({"success": False, "error": "No file part in request."}), 400

    uploaded_file = request.files.get("pcap_file") or request.files.get("file")
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"success": False, "error": "No file selected."}), 400

    ids_event_id = request.form.get("ids_event_id", type=int)
    force_reanalyze = request.form.get("force_reanalyze", "").lower() in ("true", "1")
    auto_run = request.form.get("auto_run", "true").lower() in ("true", "1")

    try:
        analysis, is_new = save_uploaded_pcap(
            file_storage=uploaded_file,
            user_id=current_user.id if current_user and current_user.is_authenticated else None,
            ids_event_id=ids_event_id,
            force_reanalyze=force_reanalyze,
        )

        # Trigger analysis if new or if requested
        if auto_run and (is_new or analysis.status in ("uploaded", "failed")):
            try:
                run_pcap_analysis(analysis.id)
            except Exception as run_err:
                return jsonify({
                    "success": True,
                    "is_new": is_new,
                    "analysis": analysis.to_dict(include_details=True),
                    "warning": f"Uploaded successfully, but initial analysis encountered: {run_err}",
                }), 201

        return jsonify({
            "success": True,
            "is_new": is_new,
            "analysis": analysis.to_dict(include_details=True),
            "redirect_url": url_for("packet_analysis.analysis_details", analysis_id=analysis.id),
        }), 201

    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to upload capture: {e}"}), 500


@packet_analysis.route("/api/analyses/<analysis_id>", methods=["GET"])
@login_required
def api_get_analysis(analysis_id):
    """Returns single analysis record with all aggregate statistics."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"success": False, "error": "Analysis not found."}), 404

    return jsonify({"success": True, "analysis": analysis.to_dict(include_details=True)})


@packet_analysis.route("/api/analyses/<analysis_id>/run", methods=["POST"])
@login_required
def api_run_analysis(analysis_id):
    """Triggers or re-runs TShark analysis on an existing PCAP file."""
    try:
        analysis = run_pcap_analysis(analysis_id)
        return jsonify({
            "success": True,
            "message": "Analysis completed successfully.",
            "analysis": analysis.to_dict(include_details=True),
        })
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@packet_analysis.route("/api/analyses/<analysis_id>", methods=["DELETE"])
@login_required
def api_delete_analysis(analysis_id):
    """Deletes analysis record and removes stored PCAP file from disk."""
    try:
        delete_analysis(analysis_id)
        return jsonify({"success": True, "message": "Analysis deleted successfully."})
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@packet_analysis.route("/api/analyses/<analysis_id>/protocols", methods=["GET"])
@login_required
def api_get_protocols(analysis_id):
    """Returns protocol hierarchy statistics."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"success": False, "error": "Analysis not found."}), 404

    return jsonify({
        "success": True,
        "protocol_stats": analysis.protocol_stats or {},
        "protocols": (analysis.protocol_stats or {}).get("protocols", []),
    })


@packet_analysis.route("/api/analyses/<analysis_id>/endpoints", methods=["GET"])
@login_required
def api_get_endpoints(analysis_id):
    """Returns top IP endpoints with packet and byte counts."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"success": False, "error": "Analysis not found."}), 404

    return jsonify({
        "success": True,
        "endpoints": analysis.endpoint_stats or [],
    })


@packet_analysis.route("/api/analyses/<analysis_id>/conversations", methods=["GET"])
@login_required
def api_get_conversations(analysis_id):
    """Returns top IP and transport conversations."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"success": False, "error": "Analysis not found."}), 404

    return jsonify({
        "success": True,
        "conversations": analysis.conversation_stats or [],
    })


@packet_analysis.route("/api/analyses/<analysis_id>/packets", methods=["GET"])
@login_required
def api_get_packets(analysis_id):
    """
    Returns paginated packet listing.
    Supports Wireshark display filters and free-text search.
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    display_filter = request.args.get("filter") or request.args.get("display_filter")
    search = request.args.get("search") or request.args.get("q")

    try:
        data = get_analysis_packets(
            analysis_id=analysis_id,
            page=page,
            per_page=per_page,
            display_filter=display_filter,
            search=search,
        )
        return jsonify({"success": True, **data})
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@packet_analysis.route("/api/analyses/<analysis_id>/packets/<packet_number>", methods=["GET"])
@login_required
def api_get_packet_detail(analysis_id, packet_number):
    """Returns structured dissection layers and formatted hex dump for a single packet."""
    try:
        detail = get_packet_detail(analysis_id, packet_number)
        return jsonify({"success": True, **detail})
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

