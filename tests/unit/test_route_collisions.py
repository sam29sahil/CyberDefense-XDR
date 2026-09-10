"""
CyberDefense XDR
Unit Test Suite for Route Collision Resolution
Verifies the 10 requirements:
1. Threat Intel campaign API returns JSON
2. Threat Intel campaign HTML page renders
3. Threat Intel feed API returns JSON
4. Threat Intel feed HTML page renders
5. Threat Intelligence actor API returns JSON
6. Threat Intelligence actor HTML page renders
7. Alert Center /stats resolves to the intended endpoint and response
8. Alert escalation resolves to the intended endpoint and preserves existing behavior
9. Existing url_for() references continue working
10. Authentication/RBAC behavior remains intact
"""

import unittest
from flask import url_for
from app import create_app
from app.extensions import db
from app.users.models import User
from app.alerts.models import Alert
from app.alerts.services import create_alert


class RouteCollisionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            # 1. Admin / Analyst user (has full permissions including alerts.modify)
            analyst = User.query.filter_by(username="collision_analyst").first()
            if not analyst:
                analyst = User(
                    username="collision_analyst",
                    email="collision_analyst@defense.local",
                    first_name="Collision",
                    last_name="Analyst",
                    role="ANALYST",
                    status="active",
                    is_active=True,
                )
                analyst.set_password("AnalystPass123!")
                db.session.add(analyst)

            # 2. Viewer user (has view permissions, lacks alerts.modify)
            viewer = User.query.filter_by(username="collision_viewer").first()
            if not viewer:
                viewer = User(
                    username="collision_viewer",
                    email="collision_viewer@defense.local",
                    first_name="Collision",
                    last_name="Viewer",
                    role="VIEWER",
                    status="active",
                    is_active=True,
                )
                viewer.set_password("ViewerPass123!")
                db.session.add(viewer)

            db.session.commit()
            cls.analyst_id = analyst.id
            cls.viewer_id = viewer.id

    def get_auth_client(self, user_id):
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["_user_id"] = str(user_id)
            sess["_fresh"] = True
        return client

    # =========================================================================
    # 1. Threat Intel campaign API returns JSON
    # =========================================================================
    def test_01_threat_intel_campaign_api_returns_json(self):
        client = self.get_auth_client(self.analyst_id)

        # Standard API request (no accept header)
        res = client.get("/threat-intelligence/campaigns")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("items", data["data"])

        # Explicit Accept: application/json
        res_json = client.get(
            "/threat-intelligence/campaigns",
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res_json.status_code, 200)
        self.assertTrue(res_json.is_json)

        # Dedicated /api/campaigns
        res_api = client.get("/threat-intelligence/api/campaigns")
        self.assertEqual(res_api.status_code, 200)
        self.assertTrue(res_api.is_json)

    # =========================================================================
    # 2. Threat Intel campaign HTML page renders
    # =========================================================================
    def test_02_threat_intel_campaign_html_page_renders(self):
        client = self.get_auth_client(self.analyst_id)

        # Dedicated page URL /campaigns-page
        res_page = client.get("/threat-intelligence/campaigns-page")
        self.assertEqual(res_page.status_code, 200)
        self.assertIn(b"Threat Campaigns", res_page.data)

        # Dedicated view alias /campaigns/view
        res_view = client.get("/threat-intelligence/campaigns/view")
        self.assertEqual(res_view.status_code, 200)
        self.assertIn(b"Threat Campaigns", res_view.data)

        # Browser navigation with Accept: text/html
        res_browser = client.get(
            "/threat-intelligence/campaigns",
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        self.assertEqual(res_browser.status_code, 200)
        self.assertIn(b"Threat Campaigns", res_browser.data)

    # =========================================================================
    # 3. Threat Intel feed API returns JSON
    # =========================================================================
    def test_03_threat_intel_feed_api_returns_json(self):
        client = self.get_auth_client(self.analyst_id)

        res = client.get("/threat-intelligence/feeds")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("items", data["data"])

        res_api = client.get("/threat-intelligence/api/feeds")
        self.assertEqual(res_api.status_code, 200)
        self.assertTrue(res_api.is_json)

    # =========================================================================
    # 4. Threat Intel feed HTML page renders
    # =========================================================================
    def test_04_threat_intel_feed_html_page_renders(self):
        client = self.get_auth_client(self.analyst_id)

        res_page = client.get("/threat-intelligence/feeds-page")
        self.assertEqual(res_page.status_code, 200)
        self.assertIn(b"Feed Sources", res_page.data)

        res_view = client.get("/threat-intelligence/feeds/view")
        self.assertEqual(res_view.status_code, 200)
        self.assertIn(b"Feed Sources", res_view.data)

        res_browser = client.get(
            "/threat-intelligence/feeds",
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        self.assertEqual(res_browser.status_code, 200)
        self.assertIn(b"Feed Sources", res_browser.data)

    # =========================================================================
    # 5. Threat Intelligence actor API returns JSON
    # =========================================================================
    def test_05_threat_intel_actor_api_returns_json(self):
        client = self.get_auth_client(self.analyst_id)

        res = client.get("/threat-intelligence/actors")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("items", data["data"])

        res_api = client.get("/threat-intelligence/api/actors")
        self.assertEqual(res_api.status_code, 200)
        self.assertTrue(res_api.is_json)

    # =========================================================================
    # 6. Threat Intelligence actor HTML page renders
    # =========================================================================
    def test_06_threat_intel_actor_html_page_renders(self):
        client = self.get_auth_client(self.analyst_id)

        res_page = client.get("/threat-intelligence/actors-page")
        self.assertEqual(res_page.status_code, 200)
        self.assertIn(b"Threat Actors", res_page.data)

        res_view = client.get("/threat-intelligence/actors/view")
        self.assertEqual(res_view.status_code, 200)
        self.assertIn(b"Threat Actors", res_view.data)

        res_browser = client.get(
            "/threat-intelligence/actors",
            headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        )
        self.assertEqual(res_browser.status_code, 200)
        self.assertIn(b"Threat Actors", res_browser.data)

    # =========================================================================
    # 7. Alert Center /stats resolves to intended endpoint and response
    # =========================================================================
    def test_07_alert_center_stats_resolves_correctly(self):
        client = self.get_auth_client(self.analyst_id)

        # /alert-center/stats must NOT return 404 (not shadowed by /<string:alert_id>)
        res = client.get("/alert-center/stats")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertTrue(data["success"])
        stats = data["data"]
        self.assertIn("total", stats)
        self.assertIn("critical", stats)
        self.assertIn("high", stats)

        # /alert-center/api/stats
        res_api = client.get("/alert-center/api/stats")
        self.assertEqual(res_api.status_code, 200)
        self.assertTrue(res_api.is_json)
        self.assertEqual(res_api.get_json()["data"]["total"], stats["total"])

    # =========================================================================
    # 8. Alert escalation resolves to intended endpoint and preserves behavior
    # =========================================================================
    def test_08_alert_escalation_endpoint_resolves_and_functions(self):
        client = self.get_auth_client(self.analyst_id)

        with self.app.app_context():
            alert = create_alert({
                "title": "Escalation Route Test Alert",
                "severity": "high",
                "status": "new",
            })
            alert_id = alert.alert_id

        # POST to /alert-center/<alert_id>/escalate
        res = client.post(
            f"/alert-center/{alert_id}/escalate",
            json={"title": "Escalated Incident From Test Route"},
        )
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.is_json)
        payload = res.get_json()
        self.assertTrue(payload["success"])
        self.assertIn("incident", payload["data"])
        self.assertIn("alert", payload["data"])
        self.assertEqual(payload["data"]["alert"]["alert_id"], alert_id)
        self.assertEqual(payload["data"]["incident"]["title"], "Escalated Incident From Test Route")

        # Existing link-incident endpoint continues to work
        with self.app.app_context():
            alert2 = create_alert({
                "title": "Link Incident Route Test Alert",
                "severity": "medium",
                "status": "new",
            })
            alert2_id = alert2.alert_id

        res_link = client.post(
            f"/alert-center/{alert2_id}/link-incident",
            json={"create_new": True, "title": "Linked Incident From Old Route"},
        )
        self.assertEqual(res_link.status_code, 201)
        self.assertTrue(res_link.get_json()["success"])

    # =========================================================================
    # 9. Existing url_for() references continue working
    # =========================================================================
    def test_09_existing_url_for_references_work(self):
        with self.app.test_request_context():
            # Page route url_for
            url_camp_page = url_for("threatintel.campaigns_page")
            self.assertIn("/threat-intelligence/campaigns", url_camp_page)

            url_feed_page = url_for("threatintel.feeds_page")
            self.assertIn("/threat-intelligence/feeds", url_feed_page)

            url_act_page = url_for("threatintel.actors_page")
            self.assertIn("/threat-intelligence/actors", url_act_page)

            # API route url_for
            url_camp_list = url_for("threatintel.campaign_list")
            self.assertIn("/threat-intelligence/campaigns", url_camp_list)

            url_feed_list = url_for("threatintel.feed_list")
            self.assertIn("/threat-intelligence/feeds", url_feed_list)

            url_act_list = url_for("threatintel.actor_list")
            self.assertIn("/threat-intelligence/actors", url_act_list)

            # Alert stats and escalate url_for
            url_alert_stats = url_for("alerts.alert_stats")
            self.assertIn("/alert-center/stats", url_alert_stats)

            url_alert_esc = url_for("alerts.link_incident_route", alert_id="ALT-123")
            self.assertIn("/alert-center/ALT-123/", url_alert_esc)

    # =========================================================================
    # 10. Authentication/RBAC behavior remains intact
    # =========================================================================
    def test_10_authentication_and_rbac_intact(self):
        anon_client = self.app.test_client()

        # Unauthenticated calls must redirect (302) or reject (401)
        unauth_routes = [
            ("/threat-intelligence/campaigns-page", "GET"),
            ("/threat-intelligence/feeds-page", "GET"),
            ("/threat-intelligence/actors-page", "GET"),
            ("/alert-center/stats", "GET"),
            ("/alert-center/ALT-NONEXISTENT/escalate", "POST"),
        ]
        for path, method in unauth_routes:
            if method == "GET":
                res = anon_client.get(path)
            else:
                res = anon_client.post(path, json={})
            self.assertIn(
                res.status_code,
                (302, 401),
                f"Expected 302 or 401 for unauthenticated {method} {path}, got {res.status_code}",
            )

        # Viewer role can access stats, campaigns, feeds, actors
        viewer_client = self.get_auth_client(self.viewer_id)
        res_stats_v = viewer_client.get("/alert-center/stats")
        self.assertEqual(res_stats_v.status_code, 200)

        res_camp_v = viewer_client.get("/threat-intelligence/campaigns-page")
        self.assertEqual(res_camp_v.status_code, 200)

        # Viewer role cannot escalate alert (requires alerts.modify -> 403)
        res_esc_v = viewer_client.post(
            "/alert-center/ALT-12345/escalate",
            json={"title": "Unauthorized Escalation"},
        )
        self.assertEqual(
            res_esc_v.status_code,
            403,
            f"Viewer must receive 403 on alert escalation, got {res_esc_v.status_code}",
        )


if __name__ == "__main__":
    unittest.main()
