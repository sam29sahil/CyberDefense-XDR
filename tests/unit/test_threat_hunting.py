"""
CyberDefense XDR
Unit Tests for Threat Hunting Module
Tests entity detection, cross-module telemetry hunting, chronological timeline,
and query history persistence.
"""

import unittest
import json
from datetime import datetime, timezone
from app import create_app
from app.extensions import db
from app.users.models import User
from app.assets.models import Asset
from app.alerts.models import Alert
from app.ids.models import NetworkIDSEvent
from app.threat_hunting.services import detect_entity_type, execute_hunt, get_hunting_summary
from app.threat_hunting.models import ThreatHuntQuery


class ThreatHuntingTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="test_hunter_analyst").first()
            if not user:
                user = User(
                    username="test_hunter_analyst",
                    email="hunter@cyberdefense.local",
                    first_name="Threat",
                    last_name="Hunter",
                    role="analyst",
                    is_active=True,
                )
                user.set_password("HunterPass123!")
                db.session.add(user)
                db.session.commit()
            cls.test_user_id = user.id

    def setUp(self):
        self.client = self.app.test_client()

    def get_auth_client(self):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.test_user_id)
            sess["_fresh"] = True
        return self.client

    # 1. Authentication
    def test_unauthenticated_redirects(self):
        res = self.client.get("/threat-hunting/")
        self.assertIn(res.status_code, [302, 401])

        res_api = self.client.get("/threat-hunting/api/summary")
        self.assertIn(res_api.status_code, [302, 401])

    def test_authenticated_dashboard_page(self):
        client = self.get_auth_client()
        res = client.get("/threat-hunting/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Threat Hunting", res.data)

    # 2. Entity Detection
    def test_entity_type_detection(self):
        self.assertEqual(detect_entity_type("192.168.1.100"), "ip")
        self.assertEqual(detect_entity_type("CVE-2026-1234"), "cve")
        self.assertEqual(detect_entity_type("ALT-987654"), "alert_id")
        self.assertEqual(detect_entity_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "hash")
        self.assertEqual(detect_entity_type("https://evil-phish.com/login"), "url")
        self.assertEqual(detect_entity_type("malicious-c2.net"), "domain")

    # 3. Summary API
    def test_summary_api(self):
        client = self.get_auth_client()
        res = client.get("/threat-hunting/api/summary")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("total_assets", data["summary"])
        self.assertIn("active_alerts", data["summary"])
        self.assertIn("ids_threat_events", data["summary"])

    # 4. Search API
    def test_search_api_ip(self):
        client = self.get_auth_client()
        res = client.post("/threat-hunting/api/search", json={
            "query": "192.168.1.1",
            "search_type": "auto"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["query"], "192.168.1.1")
        self.assertIn("timeline", data)
        self.assertIn("results", data)
        self.assertIn("alerts", data["results"])
        self.assertIn("ids_events", data["results"])

    # 5. History & Bookmarks API
    def test_history_and_bookmarks(self):
        client = self.get_auth_client()
        # Save a hunt
        save_res = client.post("/threat-hunting/api/search", json={
            "query": "10.0.0.50",
            "search_type": "ip",
            "save": True,
            "name": "Audit Gateway 10.0.0.50"
        })
        self.assertEqual(save_res.status_code, 200)

        # Retrieve saved searches
        saved_res = client.get("/threat-hunting/api/saved-searches")
        self.assertEqual(saved_res.status_code, 200)
        data = saved_res.get_json()
        self.assertTrue(any(s["query_text"] == "10.0.0.50" for s in data["saved"]))

        # Retrieve recent history
        hist_res = client.get("/threat-hunting/api/history")
        self.assertEqual(hist_res.status_code, 200)
        hist_data = hist_res.get_json()
        self.assertGreaterEqual(len(hist_data["history"]), 1)


if __name__ == "__main__":
    unittest.main()
