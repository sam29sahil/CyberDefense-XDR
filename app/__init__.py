"""
CyberDefense XDR
Application Factory
"""

from flask import Flask, request, jsonify, render_template

from config.config import Config

from app.extensions import (
    db,
    migrate,
    login_manager,
    csrf,
)

from app.routes import main
from app.auth import auth
import app.auth.routes
from app.dashboard import dashboard
from app.settings import settings
from app.detection import detection
from app.incidents import incidents
from app.alerts import alerts
from app.threatintel import threatintel
from app.siem import siem
from app.scanner import scanner
from app.ids import ids
from app.packet_analysis import packet_analysis
from app.assets import assets
from app.soc_dashboard import soc_dashboard
from app.reports import reports
from app.analytics import analytics
from app.threat_hunting import threat_hunting
from app.correlation import correlation
from app.ai_assistant import ai_assistant
from app.soar import soar
from app.user_management import user_management
from app.audit_logs import audit_logs
from app.notifications import notifications

from app.utils.logger import configure_logger


def create_app():
    """
    Create and configure the Flask application.
    """

    app = Flask(__name__)

    # ==========================================================
    # Configuration
    # ==========================================================

    app.config.from_object(Config)

    # ==========================================================
    # Extensions
    # ==========================================================

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    # ==========================================================
    # Logging
    # ==========================================================

    configure_logger()

    # ==========================================================
    # Import models so SQLAlchemy registers them
    # ==========================================================

    from app.users.models import User  # noqa: F401

    from app.settings.models import (
        SecuritySettings,
        NotificationSettings,
        APIKey,
        Integration,
        GeneralSettings,
    )  # noqa: F401
     
    from app.detection.models import (
        DetectionRule,
        DetectionEvent,
    )  # noqa: F401

    from app.incidents.models import Incident  # noqa: F401
    from app.alerts.models import Alert  # noqa: F401
    from app.threatintel.models import (
        IOC,
        ThreatCampaign,
        ThreatFeed,
        ThreatActor,
    )  # noqa: F401
    from app.siem.models import (
        SiemEvent,
        SiemSavedSearch,
    )  # noqa: F401
    from app.scanner.models import (
        Scan,
        VulnerabilityFinding,
        ScanTarget,
    )  # noqa: F401
    from app.ids.models import (
        NetworkIDSEvent,
        IDSSensor,
    )  # noqa: F401
    from app.packet_analysis.models import PacketAnalysis  # noqa: F401
    from app.assets.models import Asset  # noqa: F401
    from app.reports.models import Report  # noqa: F401
    from app.threat_hunting.models import ThreatHuntQuery  # noqa: F401
    from app.ai_assistant.models import AIConversation, AIMessage  # noqa: F401
    from app.soar.models import SoarPlaybookExecution, SoarApproval  # noqa: F401
    from app.audit_logs.models import AuditLog  # noqa: F401
    from app.notifications.models import Notification  # noqa: F401
    # ==========================================================
    # Register Blueprints
    # ==========================================================

    app.register_blueprint(main)

    app.register_blueprint(auth, url_prefix="/auth")

    app.register_blueprint(dashboard)

    app.register_blueprint(settings)

    app.register_blueprint(detection)

    app.register_blueprint(incidents)

    app.register_blueprint(alerts)
    app.register_blueprint(threatintel)
    app.register_blueprint(siem)
    app.register_blueprint(scanner)
    app.register_blueprint(ids)
    app.register_blueprint(packet_analysis)
    app.register_blueprint(assets)
    app.register_blueprint(soc_dashboard)
    app.register_blueprint(reports)
    app.register_blueprint(analytics)
    app.register_blueprint(threat_hunting)
    app.register_blueprint(correlation)
    app.register_blueprint(ai_assistant)
    app.register_blueprint(soar)
    app.register_blueprint(user_management)
    app.register_blueprint(audit_logs)
    app.register_blueprint(notifications)

    # ==========================================================
    # Security Response Headers (OWASP Hardening)
    # ==========================================================
    @app.after_request
    def apply_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
                "font-src 'self' data: https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
                "img-src 'self' data: blob: https:; "
                "connect-src 'self' https:;"
            )
        return response

    # ==========================================================
    # Global Error Handlers (Information Disclosure Defense)
    # ==========================================================
    @app.errorhandler(400)
    def handle_bad_request(e):
        if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
            return jsonify({"success": False, "error": "Bad Request", "message": str(e)}), 400
        return jsonify({"success": False, "error": "Bad Request", "message": "The server could not understand the request."}), 400

    @app.errorhandler(403)
    def handle_forbidden(e):
        if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
            return jsonify({"success": False, "error": "Forbidden", "message": "Access is denied to the requested resource."}), 403
        return jsonify({"success": False, "error": "Forbidden", "message": "Access is denied to the requested resource."}), 403

    @app.errorhandler(404)
    def handle_not_found(e):
        if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
            return jsonify({"success": False, "error": "Not Found", "message": "The requested endpoint does not exist."}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def handle_server_error(e):
        try:
            db.session.rollback()
        except Exception:
            pass
        if request.path.startswith("/api") or "/api/" in request.path or request.is_json:
            return jsonify({"success": False, "error": "Internal Server Error", "message": "An unexpected error occurred."}), 500
        return render_template("errors/500.html"), 500

    return app
