"""
CyberDefense XDR
Unit and Integration Tests for Audit Logs Module
Tests audit model integrity, secret sanitization, CSV formula injection defense,
real DB-backed query filters, statistics calculation, RBAC authorization boundaries,
and cross-module audit trail generation.
"""

import io
import csv
import json
import unittest
from datetime import datetime, timedelta

from app import create_app
from app.extensions import db
from app.users.models import User
from app.audit_logs.models import AuditLog
from app.audit_logs.utils import (
    generate_audit_id,
    sanitize_audit_details,
    sanitize_csv_cell,
)
from app.audit_logs.services import (
    record_audit_event,
    get_audit_log_by_id,
    list_audit_logs,
    get_audit_statistics,
    export_audit_logs_csv,
)


class AuditLogsTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            # Setup Admin User (has audit.view via ADMIN role)
            cls.admin_user = User.query.filter_by(username="audit_test_admin").first()
            if not cls.admin_user:
                cls.admin_user = User(
                    username="audit_test_admin",
                    email="audit_admin@defense.local",
                    first_name="Audit",
                    last_name="Admin",
                    role="ADMIN",
                    status="active",
                    is_active=True,
                )
                cls.admin_user.set_password("AdminSecurePass123!")
                db.session.add(cls.admin_user)
                db.session.commit()

            # Setup Viewer User (does NOT have audit.view)
            cls.viewer_user = User.query.filter_by(username="audit_test_viewer").first()
            if not cls.viewer_user:
                cls.viewer_user = User(
                    username="audit_test_viewer",
                    email="audit_viewer@defense.local",
                    first_name="Audit",
                    last_name="Viewer",
                    role="VIEWER",
                    status="active",
                    is_active=True,
                )
                cls.viewer_user.set_password("ViewerPass123!")
                db.session.add(cls.viewer_user)
                db.session.commit()

            cls.admin_id = cls.admin_user.id
            cls.viewer_id = cls.viewer_user.id

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            admin = db.session.get(User, self.admin_id)
            if admin:
                admin.role = "ADMIN"
                admin.status = "active"
                admin.is_active = True
            viewer = db.session.get(User, self.viewer_id)
            if viewer:
                viewer.role = "VIEWER"
                viewer.status = "active"
                viewer.is_active = True
            db.session.commit()

    def get_auth_client(self, user_id):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(user_id)
            sess["_fresh"] = True
        return self.client

    # =========================================================================
    # 1. Utilities & Secret Sanitization Tests
    # =========================================================================

    def test_generate_audit_id_format(self):
        """Audit IDs must conform to AUD-XXXXXXXXXX format."""
        aid = generate_audit_id()
        self.assertTrue(aid.startswith("AUD-"))
        self.assertEqual(len(aid), 14)

    def test_sanitize_audit_details_redacts_sensitive_keys(self):
        """Sanitization must recursively scrub passwords, tokens, API keys, and hashes."""
        payload = {
            "username": "johndoe",
            "password": "SuperSecretPassword123!",
            "nested": {
                "auth_token": "bearer xyz789",
                "api_key": "xdr-secret-key",
                "public_info": "safe_data",
            },
            "items_list": ["cleartext", {"password_hash": "$2b$12$xyz"}],
        }
        sanitized = sanitize_audit_details(payload)
        self.assertEqual(sanitized["username"], "johndoe")
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["auth_token"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["public_info"], "safe_data")
        self.assertEqual(sanitized["items_list"][1]["password_hash"], "[REDACTED]")

    def test_sanitize_csv_cell_formula_injection_defense(self):
        """Characters starting with =, +, -, @, \\t, \\r must be prefixed with single quote."""
        self.assertEqual(sanitize_csv_cell("=cmd|'/C calc'!A0"), "'=cmd|'/C calc'!A0")
        self.assertEqual(sanitize_csv_cell("+12345"), "'+12345")
        self.assertEqual(sanitize_csv_cell("-12345"), "'-12345")
        self.assertEqual(sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("normal_text"), "normal_text")
        self.assertEqual(sanitize_csv_cell(""), "")
        self.assertEqual(sanitize_csv_cell(None), "")

    # =========================================================================
    # 2. Service Layer & Model Tests
    # =========================================================================

    def test_record_audit_event_and_retrieve(self):
        """Service must persist audit log record with sanitized payload."""
        with self.app.app_context():
            log = record_audit_event(
                action="TEST_ACTION_EXEC",
                category="User Management",
                actor="test_runner",
                actor_id=self.admin_id,
                actor_role="ADMIN",
                resource_type="user",
                resource_id="101",
                severity="medium",
                result="success",
                details={"target": "user101", "password": "leak_prevention_check"},
                source_ip="192.168.10.55",
            )
            self.assertIsNotNone(log.id)
            self.assertTrue(log.audit_id.startswith("AUD-"))
            self.assertEqual(log.details.get("password"), "[REDACTED]")
            self.assertEqual(log.details.get("target"), "user101")

            retrieved = get_audit_log_by_id(log.audit_id)
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved["audit_id"], log.audit_id)
            self.assertEqual(retrieved["action"], "TEST_ACTION_EXEC")

    def test_list_audit_logs_filtering(self):
        """Service must filter by action, actor, category, severity, result, and search query."""
        with self.app.app_context():
            unique_action = f"FILTER_TEST_{datetime.utcnow().timestamp()}"
            record_audit_event(
                action=unique_action,
                category="Incident Response",
                actor="filter_analyst",
                resource_type="incident",
                resource_id="INC-9999",
                severity="high",
                result="failure",
                details={"notes": "Incident escalation failed"},
            )

            res = list_audit_logs(filters={"action": unique_action})
            self.assertGreaterEqual(res["total"], 1)
            self.assertEqual(res["items"][0]["action"], unique_action)
            self.assertEqual(res["items"][0]["severity"], "high")
            self.assertEqual(res["items"][0]["result"], "FAILURE")

            # Search query matching resource_id
            search_res = list_audit_logs(filters={"search": "INC-9999"})
            self.assertTrue(any(item["resource_id"] == "INC-9999" for item in search_res["items"]))

    def test_audit_statistics(self):
        """Service must accurately aggregate total events and breakdown metrics."""
        with self.app.app_context():
            # Seed distinctive test events
            record_audit_event(
                action="LOGIN_FAILURE",
                category="Authentication",
                result="failure",
                severity="medium",
            )
            record_audit_event(
                action="AUTHORIZATION_DENIED",
                category="Authorization",
                result="denied",
                severity="high",
            )

            stats = get_audit_statistics()
            self.assertGreater(stats["total_events"], 0)
            self.assertGreater(stats["events_today"], 0)
            self.assertGreaterEqual(stats["authentication_failures"], 1)
            self.assertGreaterEqual(stats["authorization_denials"], 1)
            self.assertIn("Authentication", stats["by_category"])
            self.assertIn("Authorization", stats["by_category"])

    def test_export_audit_logs_csv(self):
        """Service must stream RFC 4180 compliant CSV."""
        with self.app.app_context():
            generator = export_audit_logs_csv()
            csv_lines = list(generator)
            csv_text = "".join(csv_lines)
            reader = csv.reader(io.StringIO(csv_text))
            header = next(reader)
            self.assertIn("Audit ID", header)
            self.assertIn("Timestamp (UTC)", header)
            self.assertIn("Actor", header)
            self.assertIn("Action", header)
            self.assertIn("Category", header)

    # =========================================================================
    # 3. Web Views & REST API Authorization Tests
    # =========================================================================

    def test_audit_logs_unauthenticated_access(self):
        """Unauthenticated requests must be redirected to login."""
        res = self.client.get("/audit-logs/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/auth/login", res.headers["Location"])

        api_res = self.client.get("/audit-logs/api")
        self.assertEqual(api_res.status_code, 302)

    def test_audit_logs_forbidden_for_non_privileged_user(self):
        """Users without audit.view permission must receive HTTP 403 and be audited."""
        auth_client = self.get_auth_client(self.viewer_id)
        res = auth_client.get("/audit-logs/")
        self.assertEqual(res.status_code, 403)

        api_res = auth_client.get("/audit-logs/api")
        self.assertEqual(api_res.status_code, 403)

        # Confirm AUTHORIZATION_DENIED was logged in the database
        with self.app.app_context():
            denial = AuditLog.query.filter_by(
                actor_id=self.viewer_id,
                action="AUTHORIZATION_DENIED",
            ).order_by(AuditLog.id.desc()).first()
            self.assertIsNotNone(denial)
            self.assertEqual(denial.result, "DENIED")

    def test_audit_logs_admin_dashboard_and_api(self):
        """Admin with audit.view must successfully retrieve dashboard and API data."""
        auth_client = self.get_auth_client(self.admin_id)
        res = auth_client.get("/audit-logs/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Audit Logs", res.data)

        api_res = auth_client.get("/audit-logs/api?page=1&per_page=10")
        self.assertEqual(api_res.status_code, 200)
        data = api_res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("data", data)
        self.assertIn("pagination", data)

    def test_audit_logs_stats_api(self):
        """Admin can access audit statistics API."""
        auth_client = self.get_auth_client(self.admin_id)
        res = auth_client.get("/audit-logs/api/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("total_events", data["data"])

    def test_audit_logs_export_api(self):
        """Admin can download audit CSV export."""
        auth_client = self.get_auth_client(self.admin_id)
        res = auth_client.get("/audit-logs/api/export")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("Content-Type"), "text/csv; charset=utf-8")
        self.assertIn("attachment; filename=cyberdefense_audit_logs_", res.headers.get("Content-Disposition", ""))

    def test_audit_detail_page(self):
        """Admin can view detailed audit record inspection page."""
        with self.app.app_context():
            log = record_audit_event(
                action="INSPECTION_TEST",
                category="Alert Center",
                actor="analyst_test",
                severity="low",
                result="success",
                details={"metric": 42},
            )
            aid = log.audit_id

        auth_client = self.get_auth_client(self.admin_id)
        res = auth_client.get(f"/audit-logs/details/{aid}")
        self.assertEqual(res.status_code, 200)
        self.assertIn(aid.encode(), res.data)
        self.assertIn(b"INSPECTION_TEST", res.data)

    def test_audit_detail_not_found(self):
        """Unknown audit record redirects to index."""
        auth_client = self.get_auth_client(self.admin_id)
        res = auth_client.get("/audit-logs/details/AUD-NONEXISTENT")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/audit-logs/", res.headers["Location"])

    # =========================================================================
    # 4. Immutability Verification (No Mutation Endpoints)
    # =========================================================================

    def test_audit_logs_immutability(self):
        """Audit records cannot be modified or deleted via HTTP APIs (no route exists)."""
        auth_client = self.get_auth_client(self.admin_id)
        put_res = auth_client.put("/audit-logs/api/AUD-1234567890", json={"action": "TAMPERED"})
        self.assertEqual(put_res.status_code, 405)  # Method Not Allowed or 404

        del_res = auth_client.delete("/audit-logs/api/AUD-1234567890")
        self.assertEqual(del_res.status_code, 405)

    # =========================================================================
    # 5. Cross-Module Audit Integration Triggers
    # =========================================================================

    def test_cross_module_auth_failure_triggers_audit(self):
        """Failed login attempts must automatically generate LOGIN_FAILED audit records."""
        self.client.post("/auth/login", json={"email": "nonexistent_hacker@test.com", "password": "WrongPassword123!"})
        with self.app.app_context():
            log = AuditLog.query.filter_by(
                action="LOGIN_FAILED",
                category="Authentication",
            ).order_by(AuditLog.id.desc()).first()
            self.assertIsNotNone(log)
            self.assertEqual(log.result, "FAILURE")
            self.assertEqual(log.actor, "nonexistent_hacker@test.com")

    def test_cross_module_alert_triggers_audit(self):
        """Alert creation must record an ALERT_CREATE audit log."""
        auth_client = self.get_auth_client(self.admin_id)
        alert_payload = {
            "title": "Suspicious PowerShell Invocations",
            "severity": "high",
            "source": "Audit Integration Test",
            "description": "Encoded command detected in pipeline",
        }
        res = auth_client.post("/alert-center/create", json=alert_payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        alert_id = data["data"]["alert_id"]

        with self.app.app_context():
            log = AuditLog.query.filter_by(
                action="ALERT_CREATE",
                resource_id=alert_id,
            ).order_by(AuditLog.id.desc()).first()
            self.assertIsNotNone(log)
            self.assertEqual(log.category, "Alert Center")
            self.assertEqual(log.result, "SUCCESS")

    def test_cross_module_incident_triggers_audit(self):
        """Incident creation must record an INCIDENT_CREATE audit log."""
        auth_client = self.get_auth_client(self.admin_id)
        inc_payload = {
            "title": "Active Lateral Movement via PsExec",
            "severity": "critical",
            "description": "Lateral movement confirmed by SOC",
        }
        res = auth_client.post("/incidents/create", json=inc_payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        incident_id = data["data"]["id"]

        with self.app.app_context():
            log = AuditLog.query.filter_by(
                action="INCIDENT_CREATE",
                resource_id=incident_id,
            ).order_by(AuditLog.id.desc()).first()
            self.assertIsNotNone(log)
            self.assertEqual(log.category, "Incident Response")
            self.assertEqual(log.result, "SUCCESS")


if __name__ == "__main__":
    unittest.main()
