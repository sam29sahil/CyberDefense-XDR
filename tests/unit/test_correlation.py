"""
CyberDefense XDR
Unit Tests for Correlation Engine
Tests relationship discovery, deterministic risk scoring, graph generation,
and campaign detection.
"""

import unittest
from app import create_app
from app.extensions import db
from app.users.models import User
from app.alerts.models import Alert
from app.ids.models import NetworkIDSEvent as IDSEvent
from app.correlation.services import calculate_risk_score, correlate_entity, find_campaigns


class CorrelationEngineTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="test_corr_analyst").first()
            if not user:
                user = User(
                    username="test_corr_analyst",
                    email="corr@cyberdefense.local",
                    first_name="Correlation",
                    last_name="Analyst",
                    role="analyst",
                    is_active=True,
                )
                user.set_password("CorrPass123!")
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

    # 1. Auth & Routes
    def test_unauthenticated_redirects(self):
        res = self.client.get("/correlation/")
        self.assertIn(res.status_code, [302, 401])

        res_api = self.client.get("/correlation/api/campaigns")
        self.assertIn(res_api.status_code, [302, 401])

    def test_authenticated_dashboard(self):
        client = self.get_auth_client()
        res = client.get("/correlation/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Multi-Layer Correlation Engine", res.data)

    # 2. Deterministic Risk Scoring
    def test_risk_score_clean(self):
        res = calculate_risk_score()
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["level"], "CLEAN")
        self.assertTrue(len(res["reasons"]) >= 1)

    def test_risk_score_diagnostic_ids_ignored(self):
        # Create a mock diagnostic event with SID 2200074
        diag_event = IDSEvent(signature_id=2200074, signature="SURICATA TCPv4 invalid checksum")
        res = calculate_risk_score(ids_events=[diag_event])
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["level"], "CLEAN")

    def test_risk_score_with_threats(self):
        alert1 = Alert(title="Ransomware Activity", severity="CRITICAL", status="new")
        alert2 = Alert(title="Command and Control", severity="HIGH", status="new")
        res = calculate_risk_score(alerts=[alert1, alert2])
        self.assertGreater(res["score"], 0)
        self.assertIn("CRITICAL", str(res["reasons"]))

    # 3. Correlation & Graph API
    def test_api_search_correlation(self):
        client = self.get_auth_client()
        res = client.post("/correlation/api/search", json={
            "query": "10.0.0.1",
            "entity_type": "ip"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        corr = data["correlation"]
        self.assertIn("risk", corr)
        self.assertIn("graph", corr)
        self.assertIn("nodes", corr["graph"])
        self.assertIn("links", corr["graph"])

    def test_api_graph_endpoint(self):
        client = self.get_auth_client()
        res = client.get("/correlation/api/graph/ip/10.0.0.1")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("nodes", data["graph"])
        self.assertIn("links", data["graph"])

    def test_api_campaigns(self):
        client = self.get_auth_client()
        res = client.get("/correlation/api/campaigns")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIsInstance(data["campaigns"], list)


if __name__ == "__main__":
    unittest.main()
