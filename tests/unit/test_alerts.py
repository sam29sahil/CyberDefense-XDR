"""
Unit and Integration Tests for Alert Center Module
CyberDefense XDR
Uses standard library unittest.
"""

import unittest
import json
from datetime import datetime

from app import create_app
from app.extensions import db
from app.users.models import User
from app.alerts.models import Alert
from app.detection.models import DetectionRule, DetectionEvent
from app.incidents.models import Incident
from app.alerts.services import (
    create_alert,
    get_alert,
    get_alert_by_id,
    get_alerts,
    get_alert_statistics,
    acknowledge_alert,
    change_alert_status,
    assign_alert,
    resolve_alert,
    link_alert_to_incident,
    create_incident_from_alert,
    create_alert_from_detection_event,
)
from app.detection.services import create_detection_event, create_rule


class AlertCenterTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            # Ensure test user exists
            user = User.query.filter_by(username="test_analyst").first()
            if not user:
                user = User(
                    username="test_analyst",
                    email="analyst@cyberdefense.local",
                    first_name="Test",
                    last_name="Analyst",
                    role="analyst",
                    is_active=True,
                )
                user.set_password("SecurePassword123!")
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

    # ============================================================
    # SERVICE & MODEL TESTS
    # ============================================================

    def test_01_create_alert(self):
        with self.app.app_context():
            user = User.query.get(self.test_user_id)
            alert = create_alert({
                "title": "Suspicious PowerShell Execution",
                "description": "powershell.exe -enc ... executed by user",
                "severity": "high",
                "category": "Execution",
                "source": "Endpoint Agent",
                "affected_host": "WIN-SRV-01",
                "mitre_id": "T1059.001",
                "assigned_to": user.id,
            })

            self.assertIsNotNone(alert.id)
            self.assertTrue(alert.alert_id.startswith("ALT-"))
            self.assertEqual(alert.title, "Suspicious PowerShell Execution")
            self.assertEqual(alert.severity, "high")
            self.assertEqual(alert.status, "new")
            self.assertEqual(alert.assigned_to, user.id)

            # Verify to_dict serialization
            d = alert.to_dict()
            self.assertEqual(d["alert_id"], alert.alert_id)
            self.assertEqual(d["severity"], "high")
            self.assertEqual(d["category"], "Execution")

    def test_02_create_alert_validations(self):
        with self.app.app_context():
            # Missing title
            with self.assertRaises(ValueError):
                create_alert({"title": ""})

            # Invalid severity
            with self.assertRaises(ValueError):
                create_alert({"title": "Test", "severity": "super-critical"})

            # Invalid status
            with self.assertRaises(ValueError):
                create_alert({"title": "Test", "status": "unknown_status"})

            # Invalid assignee
            with self.assertRaises(ValueError):
                create_alert({"title": "Test", "assigned_to": 999999})

    def test_03_alert_lifecycle(self):
        with self.app.app_context():
            user = User.query.get(self.test_user_id)
            alert = create_alert({
                "title": "Lifecycle Test Alert",
                "severity": "medium",
                "status": "new",
            })

            # 1. Acknowledge
            alert = acknowledge_alert(alert, user=user)
            self.assertEqual(alert.status, "acknowledged")
            self.assertIsNotNone(alert.acknowledged_at)

            # 2. Transition to Investigating
            alert = change_alert_status(alert, "investigating", notes="Analyst reviewing memory dump", user=user)
            self.assertEqual(alert.status, "investigating")
            self.assertIn("Analyst reviewing memory dump", alert.investigation_notes)

            # 3. Resolve
            alert = resolve_alert(alert, "Remediated - process terminated and binary quarantined", user=user)
            self.assertEqual(alert.status, "resolved")
            self.assertIsNotNone(alert.resolved_at)
            self.assertIn("Remediated", alert.resolution_notes)

            # 4. Invalid direct transition from resolved to escalated
            with self.assertRaises(ValueError):
                change_alert_status(alert, "escalated", user=user)

    def test_04_assign_alert(self):
        with self.app.app_context():
            user = User.query.get(self.test_user_id)
            alert = create_alert({"title": "Assignment Test Alert", "severity": "low"})

            # Assign to user
            alert = assign_alert(alert, user_id=user.id, notes="Assigned for triage", current_user=user)
            self.assertEqual(alert.assigned_to, user.id)
            self.assertEqual(alert.status, "acknowledged")  # auto-acknowledges when assigned from new

            # Unassign
            alert = assign_alert(alert, user_id=None, current_user=user)
            self.assertIsNone(alert.assigned_to)

    def test_05_get_alerts_filtering_and_stats(self):
        with self.app.app_context():
            a1 = create_alert({"title": "Filter Test Alpha", "severity": "critical", "category": "Ransomware", "affected_host": "ALPHA-01"})
            a2 = create_alert({"title": "Filter Test Beta", "severity": "low", "category": "Audit", "affected_host": "BETA-02"})

            # Filter by severity
            crit_res = get_alerts({"severity": "critical"}, page=1, per_page=10)
            self.assertTrue(any(x.alert_id == a1.alert_id for x in crit_res["items"]))
            self.assertFalse(any(x.alert_id == a2.alert_id for x in crit_res["items"]))

            # Filter by search
            search_res = get_alerts({"search": "ALPHA-01"})
            self.assertTrue(any(x.alert_id == a1.alert_id for x in search_res["items"]))

            # Stats
            stats = get_alert_statistics()
            self.assertGreaterEqual(stats["total"], 2)
            self.assertGreaterEqual(stats["critical"], 1)
            self.assertGreaterEqual(stats["low"], 1)

    # ============================================================
    # INTEGRATION TESTS: DETECTION -> ALERT -> INCIDENT
    # ============================================================

    def test_06_detection_to_alert_integration(self):
        with self.app.app_context():
            rule = DetectionRule.query.filter_by(name="Test Detection Rule").first()
            if not rule:
                rule = create_rule({
                    "name": "Test Detection Rule",
                    "severity": "high",
                    "category": "Credential Access",
                    "mitreId": "T1003",
                    "mitreName": "OS Credential Dumping",
                    "status": "active",
                    "source": "Host Sensor",
                })

            # Create DetectionEvent
            event = create_detection_event(
                rule=rule,
                source="Host Sensor",
                host="DC-PRIMARY-01",
                severity="high",
                raw_event={"cmd": "mimikatz.exe sekurlsa::logonpasswords"},
            )

            # Check that Alert was automatically generated
            alert = Alert.query.filter_by(detection_event_id=event.id).first()
            self.assertIsNotNone(alert)
            self.assertEqual(alert.severity, "high")
            self.assertEqual(alert.category, "Credential Access")
            self.assertEqual(alert.affected_host, "DC-PRIMARY-01")
            self.assertEqual(alert.mitre_id, "T1003")
            self.assertEqual(alert.mitre_name, "OS Credential Dumping")

            # Deduplication check: calling again returns existing alert
            dup_alert = create_alert_from_detection_event(event)
            self.assertEqual(dup_alert.id, alert.id)

    def test_07_alert_to_incident_integration(self):
        with self.app.app_context():
            user = User.query.get(self.test_user_id)
            alert = create_alert({
                "title": "Active Cobalt Strike Beacon",
                "severity": "critical",
                "category": "Command and Control",
                "affected_host": "WEB-SRV-01",
                "mitre_id": "T1071",
            })

            # Escalate alert to incident
            incident = create_incident_from_alert(alert, current_user=user)
            self.assertIsNotNone(incident)
            self.assertTrue(incident.incident_id.startswith("INC-"))
            self.assertEqual(incident.severity, "critical")

            # Check that alert now has incident_id linked and status advanced
            refreshed_alert = get_alert(alert.alert_id)
            self.assertEqual(refreshed_alert.incident_id, incident.incident_id)
            self.assertEqual(refreshed_alert.status, "investigating")

    # ============================================================
    # API ROUTE TESTS
    # ============================================================

    def test_08_unauthenticated_access(self):
        res = self.client.get("/alert-center/")
        self.assertIn(res.status_code, (302, 401))

        res_data = self.client.get("/alert-center/data")
        self.assertIn(res_data.status_code, (302, 401))

    def test_09_authenticated_routes(self):
        auth_client = self.get_auth_client()

        with self.app.app_context():
            alert = create_alert({
                "title": "API Route Test Alert",
                "severity": "medium",
                "status": "new",
            })
            aid = alert.alert_id

        # 1. GET /alert-center/
        res = auth_client.get("/alert-center/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Alert Center", res.data)

        # 2. GET /alert-center/data
        res = auth_client.get("/alert-center/data")
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertTrue(json_data["success"])
        self.assertIn("data", json_data)
        self.assertIn("stats", json_data)

        # 3. GET /alert-center/<alert_id>
        res = auth_client.get(f"/alert-center/{aid}")
        self.assertEqual(res.status_code, 200)

        # 4. GET /alert-center/<alert_id>/data
        res = auth_client.get(f"/alert-center/{aid}/data")
        self.assertEqual(res.status_code, 200)
        single_json = res.get_json()
        self.assertTrue(single_json["success"])
        self.assertEqual(single_json["data"]["alert_id"], aid)

        # 5. POST /alert-center/<alert_id>/acknowledge
        res = auth_client.post(f"/alert-center/{aid}/acknowledge")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["data"]["status"], "acknowledged")

        # 6. POST /alert-center/<alert_id>/assign
        res = auth_client.post(
            f"/alert-center/{aid}/assign",
            json={"assigned_to": self.test_user_id, "notes": "Route test assignment"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["data"]["assigned_to"], self.test_user_id)

        # 7. POST /alert-center/<alert_id>/status
        res = auth_client.post(
            f"/alert-center/{aid}/status",
            json={"status": "investigating", "notes": "Investigating via API"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["data"]["status"], "investigating")

        # 8. POST /alert-center/<alert_id>/link-incident (Create Incident)
        res = auth_client.post(
            f"/alert-center/{aid}/link-incident",
            json={"create_new": True, "title": "API Created Incident"},
        )
        self.assertEqual(res.status_code, 201)
        self.assertIn("incident", res.get_json()["data"])

        # 9. POST /alert-center/<alert_id>/resolve
        res = auth_client.post(
            f"/alert-center/{aid}/resolve",
            json={"resolution_notes": "Resolved via automated test"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["data"]["status"], "resolved")

        # 10. 404 for nonexistent alert
        res = auth_client.get("/alert-center/ALT-NONEXISTENT/data")
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main()

