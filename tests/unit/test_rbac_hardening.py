"""
CyberDefense XDR
Unit Test Suite for RBAC & Authentication Hardening
Tests the 8 Final QA authentication & permission requirements:
1. Threat Intel unauthenticated access fails (302/401)
2. Threat Intel read operations succeed with threatintel.view
3. Threat Intel create/update/delete operations fail without threatintel.modify
4. Scanner unauthenticated access fails (302/401)
5. Scanner read/target viewing operations succeed with scanner.view
6. Scanner scan launch fails without scanner.run and succeeds with scanner.run
7. Scanner scan deletion fails without scanner.delete and succeeds with scanner.delete
8. Dashboard root route requires authentication and dashboard.view
"""

import unittest
import json
from app import create_app
from app.extensions import db
from app.users.models import User
from app.scanner.models import Scan, ScanTarget
from app.threatintel.models import IOC


class RBACRouteHardeningTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            # 1. Admin User (all permissions)
            admin = User.query.filter_by(username="rbac_h_admin").first()
            if not admin:
                admin = User(
                    username="rbac_h_admin",
                    email="rbac_h_admin@defense.local",
                    first_name="RBAC",
                    last_name="Admin",
                    role="ADMIN",
                    status="active",
                    is_active=True,
                )
                admin.set_password("AdminSecure123!")
                db.session.add(admin)

            # 2. SOC Analyst User (threatintel.*, scanner.view, scanner.run, scanner.delete, dashboard.view)
            soc_analyst = User.query.filter_by(username="rbac_h_soc_analyst").first()
            if not soc_analyst:
                soc_analyst = User(
                    username="rbac_h_soc_analyst",
                    email="rbac_h_soc@defense.local",
                    first_name="RBAC",
                    last_name="SOCAnalyst",
                    role="SOC_ANALYST",
                    status="active",
                    is_active=True,
                )
                soc_analyst.set_password("SocPass123!")
                db.session.add(soc_analyst)

            # 3. Security Analyst User (threatintel.*, scanner.view, scanner.run, dashboard.view - NO scanner.delete)
            sec_analyst = User.query.filter_by(username="rbac_h_sec_analyst").first()
            if not sec_analyst:
                sec_analyst = User(
                    username="rbac_h_sec_analyst",
                    email="rbac_h_sec@defense.local",
                    first_name="RBAC",
                    last_name="SecAnalyst",
                    role="SECURITY_ANALYST",
                    status="active",
                    is_active=True,
                )
                sec_analyst.set_password("SecPass123!")
                db.session.add(sec_analyst)

            # 4. Viewer User (threatintel.view, scanner.view, dashboard.view - NO modify/run/delete)
            viewer = User.query.filter_by(username="rbac_h_viewer").first()
            if not viewer:
                viewer = User(
                    username="rbac_h_viewer",
                    email="rbac_h_viewer@defense.local",
                    first_name="RBAC",
                    last_name="Viewer",
                    role="VIEWER",
                    status="active",
                    is_active=True,
                )
                viewer.set_password("ViewerPass123!")
                db.session.add(viewer)

            # 5. Guest User (No operational permissions)
            guest = User.query.filter_by(username="rbac_h_guest").first()
            if not guest:
                guest = User(
                    username="rbac_h_guest",
                    email="rbac_h_guest@defense.local",
                    first_name="RBAC",
                    last_name="Guest",
                    role="GUEST",
                    status="active",
                    is_active=True,
                )
                guest.set_password("GuestPass123!")
                db.session.add(guest)

            db.session.commit()

            cls.admin_id = admin.id
            cls.soc_analyst_id = soc_analyst.id
            cls.sec_analyst_id = sec_analyst.id
            cls.viewer_id = viewer.id
            cls.guest_id = guest.id

    def get_auth_client(self, user_id):
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["_user_id"] = str(user_id)
            sess["_fresh"] = True
        return client

    # =========================================================================
    # 1. Threat Intel unauthenticated access fails
    # =========================================================================
    def test_threatintel_unauthenticated_access_fails(self):
        client = self.app.test_client()

        # HTML / View routes must redirect to login (302)
        res_root = client.get("/threat-intelligence/")
        self.assertIn(res_root.status_code, [302, 401])

        res_dash = client.get("/threat-intelligence/dashboard")
        self.assertIn(res_dash.status_code, [302, 401])

        res_iocs_page = client.get("/threat-intelligence/ioc-feed")
        self.assertIn(res_iocs_page.status_code, [302, 401])

        # API routes / JSON endpoints must return 302 or 401
        res_iocs = client.get("/threat-intelligence/iocs")
        self.assertIn(res_iocs.status_code, [302, 401])

        res_post = client.post(
            "/threat-intelligence/iocs",
            data=json.dumps({"value": "1.2.3.4", "type": "ip"}),
            content_type="application/json",
        )
        self.assertIn(res_post.status_code, [302, 401])

    # =========================================================================
    # 2. Threat Intel read operations succeed with threatintel.view
    # =========================================================================
    def test_threatintel_read_operations_succeed_with_view_permission(self):
        client = self.get_auth_client(self.viewer_id)

        # Viewer has threatintel.view
        res_root = client.get("/threat-intelligence/")
        self.assertEqual(res_root.status_code, 200)
        self.assertTrue(res_root.get_json()["success"])

        res_data = client.get("/threat-intelligence/dashboard/data")
        self.assertEqual(res_data.status_code, 200)
        self.assertTrue(res_data.get_json()["success"])

        res_iocs = client.get("/threat-intelligence/iocs")
        self.assertEqual(res_iocs.status_code, 200)
        self.assertTrue(res_iocs.get_json()["success"])

        res_stats = client.get("/threat-intelligence/iocs/statistics")
        self.assertEqual(res_stats.status_code, 200)
        self.assertTrue(res_stats.get_json()["success"])

        res_campaigns = client.get("/threat-intelligence/campaigns")
        self.assertEqual(res_campaigns.status_code, 200)

        res_feeds = client.get("/threat-intelligence/feeds")
        self.assertEqual(res_feeds.status_code, 200)

        res_actors = client.get("/threat-intelligence/actors")
        self.assertEqual(res_actors.status_code, 200)

    # =========================================================================
    # 3. Threat Intel create/update/delete operations fail without threatintel.modify
    # =========================================================================
    def test_threatintel_modify_operations_require_modify_permission(self):
        viewer_client = self.get_auth_client(self.viewer_id)

        # Viewer lacks threatintel.modify -> must receive 403 Forbidden
        res_create_ioc = viewer_client.post(
            "/threat-intelligence/iocs",
            data=json.dumps({"value": "198.51.100.22", "type": "ip", "threat_level": "medium"}),
            content_type="application/json",
        )
        self.assertEqual(res_create_ioc.status_code, 403)

        res_update_ioc = viewer_client.put(
            "/threat-intelligence/iocs/IOC-NONEXISTENT",
            data=json.dumps({"threat_level": "high"}),
            content_type="application/json",
        )
        self.assertEqual(res_update_ioc.status_code, 403)

        res_delete_ioc = viewer_client.delete("/threat-intelligence/iocs/IOC-NONEXISTENT")
        self.assertEqual(res_delete_ioc.status_code, 403)

        res_create_campaign = viewer_client.post(
            "/threat-intelligence/campaigns",
            data=json.dumps({"name": "Forbidden Campaign"}),
            content_type="application/json",
        )
        self.assertEqual(res_create_campaign.status_code, 403)

        res_create_feed = viewer_client.post(
            "/threat-intelligence/feeds",
            data=json.dumps({"name": "Forbidden Feed", "url": "https://example.com/feed"}),
            content_type="application/json",
        )
        self.assertEqual(res_create_feed.status_code, 403)

        res_create_actor = viewer_client.post(
            "/threat-intelligence/actors",
            data=json.dumps({"name": "Forbidden Actor"}),
            content_type="application/json",
        )
        self.assertEqual(res_create_actor.status_code, 403)

        # SOC Analyst HAS threatintel.modify -> create operation succeeds (201)
        test_ip = "240.240.240.240"
        with self.app.app_context():
            IOC.query.filter_by(value=test_ip).delete()
            db.session.commit()

        soc_client = self.get_auth_client(self.soc_analyst_id)
        res_soc_create = soc_client.post(
            "/threat-intelligence/iocs",
            data=json.dumps({
                "value": test_ip,
                "type": "ip",
                "threat_level": "high",
                "confidence": "High",
                "status": "active",
                "source": "SOC Unit Test",
            }),
            content_type="application/json",
        )
        self.assertEqual(res_soc_create.status_code, 201, f"Failed with {res_soc_create.get_json()}")
        self.assertTrue(res_soc_create.get_json()["success"])

        # Immediately cleanup the test IOC so it does not affect SIEM/IDS tests
        created_data = res_soc_create.get_json().get("data", {})
        created_ioc_id = created_data.get("id") or created_data.get("ioc_id")
        if created_ioc_id:
            soc_client.delete(f"/threat-intelligence/iocs/{created_ioc_id}")
        with self.app.app_context():
            IOC.query.filter_by(value=test_ip).delete()
            db.session.commit()

    # =========================================================================
    # 4. Scanner unauthenticated access fails
    # =========================================================================
    def test_scanner_unauthenticated_access_fails(self):
        client = self.app.test_client()

        # HTML / View routes must redirect to login (302)
        res_root = client.get("/scanner/")
        self.assertIn(res_root.status_code, [302, 401])

        res_dash = client.get("/scanner/dashboard")
        self.assertIn(res_dash.status_code, [302, 401])

        res_history = client.get("/scanner/history")
        self.assertIn(res_history.status_code, [302, 401])

        res_targets = client.get("/scanner/targets")
        self.assertIn(res_targets.status_code, [302, 401])

        # API routes must return 401 or redirect 302
        res_api_dash = client.get("/scanner/api/dashboard")
        self.assertIn(res_api_dash.status_code, [302, 401])

        res_api_scans = client.get("/scanner/api/scans")
        self.assertIn(res_api_scans.status_code, [302, 401])

        res_api_tools = client.get("/scanner/api/tools")
        self.assertIn(res_api_tools.status_code, [302, 401])

        res_api_create = client.post(
            "/scanner/api/scans",
            data=json.dumps({"name": "Unauth Scan", "targets": ["127.0.0.1"]}),
            content_type="application/json",
        )
        self.assertIn(res_api_create.status_code, [302, 401])

    # =========================================================================
    # 5. Scanner read/target viewing operations succeed with scanner.view
    # =========================================================================
    def test_scanner_read_operations_succeed_with_view_permission(self):
        client = self.get_auth_client(self.viewer_id)

        res_dash = client.get("/scanner/api/dashboard")
        self.assertEqual(res_dash.status_code, 200)
        self.assertTrue(res_dash.get_json()["success"])

        res_scans = client.get("/scanner/api/scans")
        self.assertEqual(res_scans.status_code, 200)
        self.assertTrue(res_scans.get_json()["success"])

        res_tools = client.get("/scanner/api/tools")
        self.assertEqual(res_tools.status_code, 200)
        self.assertTrue(res_tools.get_json()["success"])

        res_targets = client.get("/scanner/api/targets")
        self.assertEqual(res_targets.status_code, 200)
        self.assertTrue(res_targets.get_json()["success"])

        res_vulns = client.get("/scanner/api/vulnerabilities")
        self.assertEqual(res_vulns.status_code, 200)
        self.assertTrue(res_vulns.get_json()["success"])

    # =========================================================================
    # 6. Scanner scan launch fails without scanner.run and succeeds with scanner.run
    # =========================================================================
    def test_scanner_launch_requires_scanner_run(self):
        viewer_client = self.get_auth_client(self.viewer_id)

        # Viewer lacks scanner.run -> 403 Forbidden
        scan_payload = {
            "name": "Forbidden Launch Scan",
            "scan_type": "Quick Scan",
            "profile": "QUICK",
            "targets": ["127.0.0.1"],
            "schedule_mode": "scheduled",
        }
        res_fail = viewer_client.post(
            "/scanner/api/scans",
            data=json.dumps(scan_payload),
            content_type="application/json",
        )
        self.assertEqual(res_fail.status_code, 403)

        # Security Analyst HAS scanner.run -> Scan launch succeeds (201)
        sec_client = self.get_auth_client(self.sec_analyst_id)
        res_success = sec_client.post(
            "/scanner/api/scans",
            data=json.dumps(scan_payload),
            content_type="application/json",
        )
        self.assertEqual(res_success.status_code, 201)
        self.assertTrue(res_success.get_json()["success"])

        # Cleanup created scan
        created_scan_id = res_success.get_json().get("data", {}).get("scan_id")
        if created_scan_id:
            admin_client = self.get_auth_client(self.admin_id)
            admin_client.delete(f"/scanner/api/scans/{created_scan_id}")

    # =========================================================================
    # 7. Scanner scan deletion fails without scanner.delete and succeeds with scanner.delete
    # =========================================================================
    def test_scanner_deletion_requires_scanner_delete(self):
        with self.app.app_context():
            test_scan = Scan(
                name="Scan To Delete",
                scan_type="Quick Scan",
                targets=["127.0.0.1"],
            )
            db.session.add(test_scan)
            db.session.commit()
            scan_id = test_scan.scan_id

        # Security Analyst has scanner.run and scanner.view, but NOT scanner.delete -> 403
        sec_client = self.get_auth_client(self.sec_analyst_id)
        res_fail = sec_client.delete(f"/scanner/api/scans/{scan_id}")
        self.assertEqual(res_fail.status_code, 403)

        # SOC Analyst HAS scanner.delete -> 200
        soc_client = self.get_auth_client(self.soc_analyst_id)
        res_success = soc_client.delete(f"/scanner/api/scans/{scan_id}")
        self.assertEqual(res_success.status_code, 200)
        self.assertTrue(res_success.get_json()["success"])

    # =========================================================================
    # 8. Dashboard root route requires authentication and dashboard.view
    # =========================================================================
    def test_dashboard_root_requires_auth_and_permission(self):
        # 8a. Unauthenticated access to dashboard root -> redirects to login (302)
        anon_client = self.app.test_client()
        res_anon = anon_client.get("/dashboard/")
        self.assertEqual(res_anon.status_code, 302)
        self.assertIn("/auth/login", res_anon.headers.get("Location", ""))

        # 8b. Authenticated with dashboard.view (Viewer) -> 200 OK
        viewer_client = self.get_auth_client(self.viewer_id)
        res_viewer = viewer_client.get("/dashboard/")
        self.assertEqual(res_viewer.status_code, 200)

        # 8c. Authenticated WITHOUT dashboard.view (Guest) -> 403 Forbidden
        guest_client = self.get_auth_client(self.guest_id)
        res_guest = guest_client.get("/dashboard/")
        self.assertEqual(res_guest.status_code, 403)


if __name__ == "__main__":
    unittest.main()
