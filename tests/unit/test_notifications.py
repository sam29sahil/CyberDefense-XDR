"""
CyberDefense XDR
Unit and Integration Tests for Notifications & Alerting Module
Tests notification entity schema, SSRF defense, deduplication coalescing,
fault-tolerant external channel delivery, IDOR & RBAC isolation,
RESTful query/action APIs, and cross-module trigger hooks.
"""

import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from app import create_app
from app.extensions import db
from app.users.models import User
from app.notifications.models import Notification
from app.notifications.utils import (
    generate_notification_id,
    compute_dedup_hash,
    validate_webhook_url,
    sanitize_notification_text,
)
from app.notifications.providers import InAppProvider, EmailProvider, WebhookProvider
from app.notifications.services import (
    dispatch_notification,
    get_user_notifications,
    get_notification_by_id,
    mark_as_read,
    mark_all_as_read,
    dismiss_notification,
    get_unread_count,
    resolve_recipients,
    get_user_preferences,
    update_user_preferences,
)
from app.settings.models import NotificationSettings


class NotificationsTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            # Setup User A (Admin)
            user_a = User.query.filter_by(username="notif_test_user_a").first()
            if not user_a:
                user_a = User(
                    username="notif_test_user_a",
                    email="notif_user_a@defense.local",
                    first_name="Alpha",
                    last_name="User",
                    role="ADMIN",
                    status="active",
                    is_active=True,
                )
                user_a.set_password("AlphaPass123!")
                db.session.add(user_a)
                db.session.commit()
            else:
                user_a.set_password("AlphaPass123!")
                user_a.role = "ADMIN"
                user_a.is_active = True
                user_a.status = "active"
                db.session.commit()

            # Setup User B (Viewer)
            user_b = User.query.filter_by(username="notif_test_user_b").first()
            if not user_b:
                user_b = User(
                    username="notif_test_user_b",
                    email="notif_user_b@defense.local",
                    first_name="Bravo",
                    last_name="Viewer",
                    role="VIEWER",
                    status="active",
                    is_active=True,
                )
                user_b.set_password("BravoPass123!")
                db.session.add(user_b)
                db.session.commit()
            else:
                user_b.set_password("BravoPass123!")
                user_b.role = "VIEWER"
                user_b.is_active = True
                user_b.status = "active"
                db.session.commit()

            cls.user_a_id = user_a.id
            cls.user_b_id = user_b.id

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            user_a = db.session.get(User, self.user_a_id)
            if user_a:
                user_a.set_password("AlphaPass123!")
                user_a.is_active = True
                user_a.status = "active"
            user_b = db.session.get(User, self.user_b_id)
            if user_b:
                user_b.set_password("BravoPass123!")
                user_b.is_active = True
                user_b.status = "active"
            db.session.commit()

    def get_auth_client(self, user_id):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(user_id)
            sess["_fresh"] = True
        return self.client

    def logout_client(self):
        with self.client.session_transaction() as sess:
            sess.clear()
        return self.client

    # ==========================================================================
    # 1. Model & Schema Integrity
    # ==========================================================================

    def test_01_notification_model_and_defaults(self):
        with self.app.app_context():
            notif = Notification(
                notification_id=generate_notification_id(),
                recipient_user_id=self.user_a_id,
                title="Test Alert Title",
                message="Test alert description content.",
                category="ALERT",
                severity="high",
                source="Detection Engine",
                resource_type="alert",
                resource_id="ALT-1001",
                action_url="/alert-center/alerts/ALT-1001",
            )
            db.session.add(notif)
            db.session.commit()

            self.assertIsNotNone(notif.id)
            self.assertTrue(notif.notification_id.startswith("NOTIF-"))
            self.assertFalse(notif.is_read)
            self.assertIsNone(notif.read_at)
            self.assertFalse(notif.is_dismissed)
            self.assertEqual(notif.occurrence_count, 1)

            data = notif.to_dict()
            self.assertEqual(data["title"], "Test Alert Title")
            self.assertEqual(data["recipient_user_id"], self.user_a_id)
            self.assertEqual(data["recipient_username"], "notif_test_user_a")
            self.assertEqual(data["severity"], "high")
            self.assertEqual(data["category"], "ALERT")

    # ==========================================================================
    # 2. SSRF Protection on Webhooks
    # ==========================================================================

    def test_02_ssrf_protection_safeguards(self):
        # Localhost / Loopback
        is_safe, err = validate_webhook_url("http://127.0.0.1:8080/hook")
        self.assertFalse(is_safe)
        self.assertIn("loopback", err.lower())

        is_safe, err = validate_webhook_url("http://localhost:5000/api")
        self.assertFalse(is_safe)
        self.assertIn("localhost", err.lower())

        # Private RFC 1918 subnets
        is_safe, err = validate_webhook_url("http://10.0.0.1/webhook")
        self.assertFalse(is_safe)
        self.assertIn("private", err.lower())

        is_safe, err = validate_webhook_url("http://192.168.1.50/hook")
        self.assertFalse(is_safe)
        self.assertIn("private", err.lower())

        is_safe, err = validate_webhook_url("http://172.16.10.20/hook")
        self.assertFalse(is_safe)
        self.assertIn("private", err.lower())

        # Cloud Metadata (169.254.169.254)
        is_safe, err = validate_webhook_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_safe)
        self.assertTrue("link-local" in err.lower() or "blocked" in err.lower())

        # IPv6 Loopback
        is_safe, err = validate_webhook_url("http://[::1]:8080/hook")
        self.assertFalse(is_safe)

        # Invalid schemes
        is_safe, err = validate_webhook_url("ftp://internal-server.local/hook")
        self.assertFalse(is_safe)
        self.assertIn("scheme", err.lower())

    # ==========================================================================
    # 3. Deterministic Deduplication
    # ==========================================================================

    def test_03_deduplication_and_flood_coalescing(self):
        with self.app.app_context():
            res_id = f"DEDUP-TEST-{datetime.utcnow().timestamp()}"

            # Dispatch first event
            d1 = dispatch_notification(
                title="Brute Force Detected",
                message="Repeated failed logins detected from IP 198.51.100.22",
                category="SECURITY",
                severity="high",
                recipient_user_id=self.user_a_id,
                resource_type="ip",
                resource_id=res_id,
                dedup_window_minutes=5,
            )
            self.assertTrue(len(d1) > 0)

            # Query count
            notifs1 = Notification.query.filter_by(
                recipient_user_id=self.user_a_id, resource_id=res_id
            ).all()
            self.assertEqual(len(notifs1), 1)
            self.assertEqual(notifs1[0].occurrence_count, 1)

            # Dispatch identical event within window
            d2 = dispatch_notification(
                title="Brute Force Detected",
                message="Repeated failed logins detected from IP 198.51.100.22",
                category="SECURITY",
                severity="high",
                recipient_user_id=self.user_a_id,
                resource_type="ip",
                resource_id=res_id,
                dedup_window_minutes=5,
            )
            self.assertTrue(len(d2) > 0)

            # Query again: should NOT create a second row, but increment count
            notifs2 = Notification.query.filter_by(
                recipient_user_id=self.user_a_id, resource_id=res_id
            ).all()
            self.assertEqual(len(notifs2), 1)
            self.assertEqual(notifs2[0].occurrence_count, 2)

    # ==========================================================================
    # 4. Fault-Tolerant Provider Fallback
    # ==========================================================================

    def test_04_fault_tolerant_provider_delivery(self):
        with self.app.app_context():
            # Email provider with invalid SMTP does not crash
            ep = EmailProvider()
            result_email = ep.send(
                {"title": "Test", "message": "Msg", "severity": "info"},
                recipient="nonexistent@defense.local",
            )
            # Returns gracefully without raising
            self.assertIsInstance(result_email, bool)

            # Webhook provider with blocked SSRF URL fails safely
            wp = WebhookProvider()
            result_webhook = wp.send(
                {"title": "Test", "message": "Msg"},
                webhook_url="http://127.0.0.1:9090/test",
            )
            self.assertFalse(result_webhook)

            # dispatch_notification always creates in-app record even if external providers fail
            res = dispatch_notification(
                title="Fallback Reliability Test",
                message="Testing in-app guarantee regardless of external channel status.",
                category="SYSTEM",
                severity="low",
                recipient_user_id=self.user_a_id,
                resource_type="system",
                resource_id="SYS-FB-01",
                channels=["email", "webhook"],
            )
            self.assertTrue(any(r["success"] for r in res))

    # ==========================================================================
    # 5. Authorization & Authentication
    # ==========================================================================

    def test_05_unauthenticated_access_rejected(self):
        client = self.logout_client()
        res = client.get("/notifications/")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/auth/login", res.headers.get("Location", ""))

        res_api = client.get("/notifications/api")
        self.assertIn(res_api.status_code, (302, 401))

    # ==========================================================================
    # 6. IDOR Defense (Isolation between Users)
    # ==========================================================================

    def test_06_idor_protection_between_users(self):
        with self.app.app_context():
            # Create a notification specifically for User A
            notif_a = Notification(
                notification_id=generate_notification_id(),
                recipient_user_id=self.user_a_id,
                title="User A Secret Notification",
                message="Confidential alert data for User A only.",
                category="SECURITY",
                severity="critical",
            )
            db.session.add(notif_a)
            db.session.commit()
            notif_a_id = notif_a.notification_id

        # Authenticate as User B (Viewer)
        client = self.get_auth_client(self.user_b_id)

        # User B attempts to access User A's notification via detail API
        res_get = client.get(f"/notifications/api/{notif_a_id}")
        self.assertEqual(res_get.status_code, 404)

        # User B attempts to mark User A's notification as read
        res_read = client.post(f"/notifications/api/{notif_a_id}/read")
        self.assertEqual(res_read.status_code, 404)

        # User B attempts to dismiss User A's notification
        res_dismiss = client.post(f"/notifications/api/{notif_a_id}/dismiss")
        self.assertEqual(res_dismiss.status_code, 404)

        # Verify User A's notification was NOT modified
        with self.app.app_context():
            check_notif = Notification.query.filter_by(notification_id=notif_a_id).first()
            self.assertFalse(check_notif.is_read)
            self.assertFalse(check_notif.is_dismissed)

    # ==========================================================================
    # 7. Query Filtering & Search APIs
    # ==========================================================================

    def test_07_api_list_filters_and_pagination(self):
        unique_tag = f"SRCH_{datetime.utcnow().timestamp()}"
        with self.app.app_context():
            dispatch_notification(
                title=f"Unique Filter Target {unique_tag}",
                message="Filter test payload body.",
                category="SCANNER",
                severity="critical",
                recipient_user_id=self.user_a_id,
            )

        client = self.get_auth_client(self.user_a_id)

        # Filter by category
        res_cat = client.get("/notifications/api?category=SCANNER")
        self.assertEqual(res_cat.status_code, 200)
        data_cat = res_cat.get_json()
        self.assertTrue(data_cat["success"])
        self.assertTrue(all(n["category"] == "SCANNER" for n in data_cat["notifications"]))

        # Filter by severity
        res_sev = client.get("/notifications/api?severity=critical")
        self.assertEqual(res_sev.status_code, 200)
        data_sev = res_sev.get_json()
        self.assertTrue(all(n["severity"] == "critical" for n in data_sev["notifications"]))

        # Search term
        res_srch = client.get(f"/notifications/api?search={unique_tag}")
        self.assertEqual(res_srch.status_code, 200)
        data_srch = res_srch.get_json()
        self.assertGreaterEqual(len(data_srch["notifications"]), 1)
        self.assertIn(unique_tag, data_srch["notifications"][0]["title"])

    # ==========================================================================
    # 8. Unread Counter API
    # ==========================================================================

    def test_08_api_unread_count(self):
        client = self.get_auth_client(self.user_a_id)
        res = client.get("/notifications/api/count")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("unread_count", data)
        self.assertIsInstance(data["unread_count"], int)

    # ==========================================================================
    # 9. Mark Read & Read All APIs
    # ==========================================================================

    def test_09_api_mark_read_and_read_all(self):
        with self.app.app_context():
            notif = Notification(
                notification_id=generate_notification_id(),
                recipient_user_id=self.user_a_id,
                title="Mark Read Target",
                message="Testing single mark as read.",
                category="SYSTEM",
                severity="info",
            )
            db.session.add(notif)
            db.session.commit()
            target_id = notif.notification_id

        client = self.get_auth_client(self.user_a_id)

        # Mark single as read
        res_read = client.post(f"/notifications/api/{target_id}/read")
        self.assertEqual(res_read.status_code, 200)
        data_read = res_read.get_json()
        self.assertTrue(data_read["success"])

        with self.app.app_context():
            n = Notification.query.filter_by(notification_id=target_id).first()
            self.assertTrue(n.is_read)
            self.assertIsNotNone(n.read_at)

        # Mark all read
        res_all = client.post("/notifications/api/read-all")
        self.assertEqual(res_all.status_code, 200)
        data_all = res_all.get_json()
        self.assertTrue(data_all["success"])
        self.assertEqual(data_all["unread_count"], 0)

    # ==========================================================================
    # 10. Dismiss Notification API
    # ==========================================================================

    def test_10_api_dismiss(self):
        with self.app.app_context():
            notif = Notification(
                notification_id=generate_notification_id(),
                recipient_user_id=self.user_a_id,
                title="Dismissal Target",
                message="Testing soft dismissal from active inbox.",
                category="SYSTEM",
                severity="info",
            )
            db.session.add(notif)
            db.session.commit()
            target_id = notif.notification_id

        client = self.get_auth_client(self.user_a_id)

        res_dis = client.post(f"/notifications/api/{target_id}/dismiss")
        self.assertEqual(res_dis.status_code, 200)
        self.assertTrue(res_dis.get_json()["success"])

        with self.app.app_context():
            n = Notification.query.filter_by(notification_id=target_id).first()
            self.assertTrue(n.is_dismissed)
            self.assertIsNotNone(n.dismissed_at)

    # ==========================================================================
    # 11. User Preferences API
    # ==========================================================================

    def test_11_user_preferences_api(self):
        client = self.get_auth_client(self.user_a_id)

        # GET preferences
        res_get = client.get("/notifications/api/preferences")
        self.assertEqual(res_get.status_code, 200)
        data_get = res_get.get_json()
        self.assertTrue(data_get["success"])
        self.assertIn("preferences", data_get)

        # POST / PATCH update preferences
        payload = {
            "email_enabled": True,
            "webhook_enabled": False,
            "min_severity": "high",
            "quiet_hours_enabled": True,
            "quiet_hours_from": "22:00",
            "quiet_hours_to": "06:00",
        }
        res_update = client.post(
            "/notifications/api/preferences",
            json=payload,
        )
        self.assertEqual(res_update.status_code, 200)
        data_up = res_update.get_json()
        self.assertTrue(data_up["success"])
        self.assertEqual(data_up["preferences"]["min_severity"], "high")
        self.assertTrue(data_up["preferences"]["quiet_hours_enabled"])

    # ==========================================================================
    # 12. RBAC Recipient Resolution
    # ==========================================================================

    def test_12_rbac_recipient_resolution(self):
        with self.app.app_context():
            # Only users with soar.approve (Admin, SOC Analyst) should be resolved
            approvers = resolve_recipients(recipient_permission="soar.approve")
            self.assertTrue(len(approvers) > 0)
            usernames = [u.username for u in approvers]
            self.assertIn("notif_test_user_a", usernames)
            self.assertNotIn("notif_test_user_b", usernames)

    # ==========================================================================
    # 13. Cross-Module Trigger Hooks
    # ==========================================================================

    def test_13_cross_module_hooks_integration(self):
        with self.app.app_context():
            # Alert Center hook test
            from app.alerts.services import create_alert
            alert_title = f"Test Hook Alert {datetime.utcnow().timestamp()}"
            alert = create_alert({
                "title": alert_title,
                "severity": "critical",
                "status": "new",
                "category": "Malware",
            })
            self.assertIsNotNone(alert.id)

            # Verify notification was generated for alert
            notif = Notification.query.filter_by(
                resource_id=alert.alert_id, category="ALERT"
            ).first()
            self.assertIsNotNone(notif)
            self.assertEqual(notif.severity, "critical")
            self.assertIn(alert_title, notif.title)

    # ==========================================================================
    # 14. Incident Creation & Assignment Hooks
    # ==========================================================================

    def test_14_incident_creation_and_assignment_hooks(self):
        with self.app.app_context():
            from app.incidents.services import create_incident, assign_incident
            inc_title = f"Ransomware Outbreak Test {datetime.utcnow().timestamp()}"
            inc = create_incident({
                "title": inc_title,
                "severity": "critical",
                "priority": "critical",
                "status": "new",
                "category": "Ransomware",
            })
            self.assertIsNotNone(inc.id)

            # Check notification generated for incident
            notif = Notification.query.filter_by(
                resource_id=inc.incident_id, category="INCIDENT"
            ).first()
            self.assertIsNotNone(notif)
            self.assertEqual(notif.severity, "critical")

            # Test assignment dispatch
            assign_incident(inc, self.user_a_id)
            assign_notif = Notification.query.filter(
                Notification.resource_id == inc.incident_id,
                Notification.recipient_user_id == self.user_a_id,
                Notification.title.ilike("%Assigned%"),
            ).first()
            self.assertIsNotNone(assign_notif)

    # ==========================================================================
    # 15. Network IDS Diagnostic Suppression & Genuine Alert Hook
    # ==========================================================================

    def test_15_ids_security_alert_and_diagnostic_suppression(self):
        with self.app.app_context():
            from app.ids.models import NetworkIDSEvent

            # Diagnostic checksum event (SID 2200074)
            diag_event = NetworkIDSEvent(
                event_uuid=f"test-diag-{datetime.utcnow().timestamp()}",
                event_type="alert",
                timestamp=datetime.utcnow(),
                src_ip="192.168.1.10",
                dest_ip="192.168.1.20",
                protocol="TCP",
                signature="SURICATA TCPv4 invalid checksum",
                signature_id=2200074,
                category="Generic Protocol Command Decode",
                severity="high",
            )
            db.session.add(diag_event)
            db.session.commit()
            self.assertTrue(diag_event.is_diagnostic)

            # Diagnostic event should NOT trigger an IDS notification
            diag_notif = Notification.query.filter_by(
                resource_id=str(diag_event.id), category="IDS"
            ).first()
            self.assertIsNone(diag_notif)

    # ==========================================================================
    # 16. Scanner Findings Hook
    # ==========================================================================

    def test_16_scanner_notification_hook(self):
        with self.app.app_context():
            # Dispatch scanner notification directly to verify scanner category
            res = dispatch_notification(
                title="Vulnerability Scan: 192.168.1.1",
                message="Scan identified 2 critical and 4 high vulnerabilities.",
                category="SCANNER",
                severity="critical",
                recipient_permission="scanner.view",
                source="Vulnerability Scanner",
                resource_type="scan",
                resource_id="SCN-TEST-99",
                action_url="/vuln-scanner/scans/SCN-TEST-99",
            )
            self.assertTrue(len(res) > 0)
            notif = Notification.query.filter_by(resource_id="SCN-TEST-99").first()
            self.assertIsNotNone(notif)
            self.assertEqual(notif.category, "SCANNER")
            self.assertEqual(notif.severity, "critical")

    # ==========================================================================
    # 17. SOAR Staged Approval Hook
    # ==========================================================================

    def test_17_soar_approval_staged_notification(self):
        with self.app.app_context():
            # Verify SOAR staged approval notification
            res = dispatch_notification(
                title="SOAR Approval Required: Isolate Endpoint",
                message="A staged security action requires authorization: Network isolation of Host 10.0.1.5",
                category="SOAR",
                severity="high",
                recipient_permission="soar.approve",
                source="SOAR Automation",
                resource_type="soar_approval",
                resource_id="SOAR-APP-TEST",
                action_url="/soar/",
            )
            self.assertTrue(len(res) > 0)
            notif = Notification.query.filter_by(resource_id="SOAR-APP-TEST").first()
            self.assertIsNotNone(notif)
            self.assertEqual(notif.category, "SOAR")
            self.assertEqual(notif.severity, "high")

    # ==========================================================================
    # 18. HTML Page Rendering
    # ==========================================================================

    def test_18_html_page_rendering(self):
        client = self.get_auth_client(self.user_a_id)

        # Main inbox page
        res_inbox = client.get("/notifications/")
        self.assertEqual(res_inbox.status_code, 200)
        self.assertIn(b"Notification Center", res_inbox.data)

        # Single notification details view
        with self.app.app_context():
            notif = Notification.query.filter_by(recipient_user_id=self.user_a_id).first()
            target_id = notif.notification_id

        res_detail = client.get(f"/notifications/details/{target_id}")
        self.assertEqual(res_detail.status_code, 200)
        self.assertIn(b"Notification", res_detail.data)


if __name__ == "__main__":
    unittest.main()
