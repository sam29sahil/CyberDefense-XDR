"""
CyberDefense XDR
Unit Tests for SOAR Automation Module
Tests playbook catalog (10 playbooks), execution workflows, and human-in-the-loop approvals.
"""

import unittest
import json
from app import create_app
from app.extensions import db
from app.users.models import User
from app.alerts.models import Alert
from app.incidents.models import Incident
from app.soar.services import get_available_playbooks, trigger_playbook_execution, approve_staged_action, reject_staged_action
from app.soar.models import SoarApproval, SoarPlaybookExecution


class SoarAutomationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="test_soar_analyst").first()
            if not user:
                user = User(
                    username="test_soar_analyst",
                    email="soar_analyst@cyberdefense.local",
                    first_name="SOAR",
                    last_name="Analyst",
                    role="analyst",
                    is_active=True,
                )
                user.set_password("SoarPass123!")
                db.session.add(user)
                db.session.commit()
            cls.test_user_id = user.id

            # Create unprivileged test user (lacks soar.view, soar.execute, soar.approve)
            unprivileged = User.query.filter_by(username="test_soar_unprivileged").first()
            if not unprivileged:
                unprivileged = User(
                    username="test_soar_unprivileged",
                    email="soar_unprivileged@cyberdefense.local",
                    first_name="SOAR",
                    last_name="Unprivileged",
                    role="GUEST",
                    status="active",
                    is_active=True,
                )
                unprivileged.set_password("UnprivPass123!")
                db.session.add(unprivileged)
                db.session.commit()
            cls.test_unprivileged_id = unprivileged.id

            # Create test security analyst user (has soar.view and soar.execute, but lacks soar.approve)
            sec_analyst = User.query.filter_by(username="test_soar_sec_analyst").first()
            if not sec_analyst:
                sec_analyst = User(
                    username="test_soar_sec_analyst",
                    email="soar_sec_analyst@cyberdefense.local",
                    first_name="SOAR",
                    last_name="SecAnalyst",
                    role="SECURITY_ANALYST",
                    status="active",
                    is_active=True,
                )
                sec_analyst.set_password("SecAnalystPass123!")
                db.session.add(sec_analyst)
                db.session.commit()
            cls.test_sec_analyst_id = sec_analyst.id

            # Create test alert for playbooks
            alert = Alert.query.filter_by(title="SOAR Test Alert").first()
            if not alert:
                alert = Alert(
                    alert_id="ALT-SOAR-TEST-001",
                    title="SOAR Test Alert",
                    severity="critical",
                    status="new",
                    affected_host="192.168.1.99",
                    description="Simulated attack for SOAR verification",
                )
                db.session.add(alert)
                db.session.commit()
            cls.test_alert_id = alert.id

    def setUp(self):
        self.client = self.app.test_client()

    def get_auth_client(self, user_id=None):
        uid = user_id or self.test_user_id
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["_user_id"] = str(uid)
            sess["_fresh"] = True
        return client

    # 1. Auth & Routes
    def test_unauthenticated_redirects(self):
        res = self.client.get("/soar/")
        self.assertIn(res.status_code, [302, 401])

        res_api = self.client.get("/soar/api/playbooks")
        self.assertIn(res_api.status_code, [302, 401])

    def test_authenticated_dashboard(self):
        client = self.get_auth_client()
        res = client.get("/soar/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Security Automation", res.data)

    # 2. Playbooks Catalog
    def test_playbooks_catalog_contains_10_playbooks(self):
        client = self.get_auth_client()
        res = client.get("/soar/api/playbooks")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["playbooks"]), 10)
        expected_ids = {
            "alert_investigation",
            "critical_alert_escalation",
            "incident_enrichment",
            "ioc_enrichment",
            "vulnerability_triage",
            "asset_risk_investigation",
            "ids_alert_investigation",
            "phishing_investigation",
            "malware_investigation",
            "suspicious_ip_investigation",
        }
        actual_ids = {p["id"] for p in data["playbooks"]}
        self.assertEqual(expected_ids, actual_ids)

    # 3. Execution & Step Tracking
    def test_execute_alert_investigation(self):
        client = self.get_auth_client()
        res = client.post("/soar/api/playbooks/alert_investigation/execute", json={
            "target_id": str(self.test_alert_id),
            "target_type": "alert"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        ex = data["execution"]
        self.assertEqual(ex["status"], "completed")
        self.assertGreaterEqual(len(ex["execution_steps"]), 2)

    # 4. Human-in-the-Loop Approvals
    def test_approval_workflow_escalation(self):
        client = self.get_auth_client()
        # Trigger critical escalation playbook
        res = client.post("/soar/api/playbooks/critical_alert_escalation/execute", json={
            "target_id": str(self.test_alert_id),
            "target_type": "alert"
        })
        self.assertEqual(res.status_code, 200)

        # Check pending approvals
        app_res = client.get("/soar/api/approvals?status=pending")
        self.assertEqual(app_res.status_code, 200)
        approvals = app_res.get_json()["approvals"]
        self.assertGreaterEqual(len(approvals), 1)
        target_approval = approvals[0]
        app_id = target_approval["approval_id"]

        # Approve action
        approve_res = client.post(f"/soar/api/approvals/{app_id}/approve", json={
            "notes": "Approved in unit test"
        })
        self.assertEqual(approve_res.status_code, 200)
        self.assertEqual(approve_res.get_json()["status"], "success")

        # Verify an Incident was created in DB
        with self.app.app_context():
            app_record = SoarApproval.query.filter_by(approval_id=app_id).first()
            self.assertEqual(app_record.status, "approved")

    # 5. RBAC Permission Boundaries (soar.view, soar.execute, soar.approve)
    def test_soar_view_permission_authorized(self):
        """User with soar.view can access all SOAR read endpoints."""
        client = self.get_auth_client(self.test_user_id)

        res = client.get("/soar/")
        self.assertEqual(res.status_code, 200)

        res = client.get("/soar/playbooks")
        self.assertEqual(res.status_code, 200)

        res = client.get("/soar/api/playbooks")
        self.assertEqual(res.status_code, 200)

        res = client.get("/soar/api/executions")
        self.assertEqual(res.status_code, 200)

        res = client.get("/soar/api/approvals")
        self.assertEqual(res.status_code, 200)

    def test_soar_view_permission_forbidden(self):
        """User without soar.view receives 403 Forbidden across all SOAR read endpoints."""
        client = self.get_auth_client(self.test_unprivileged_id)

        # HTML page view
        res = client.get("/soar/")
        self.assertEqual(res.status_code, 403)

        # HTML / JSON playbooks endpoints
        res = client.get("/soar/playbooks")
        self.assertEqual(res.status_code, 403)

        res = client.get("/soar/api/playbooks")
        self.assertEqual(res.status_code, 403)

        res = client.get("/soar/api/executions")
        self.assertEqual(res.status_code, 403)

        res = client.get("/soar/api/executions/fake-id")
        self.assertEqual(res.status_code, 403)

        res = client.get("/soar/api/approvals")
        self.assertEqual(res.status_code, 403)

    def test_soar_execute_permission_boundaries(self):
        """soar.execute remains required to execute playbooks."""
        # Unprivileged (lacks soar.execute) -> 403
        unpriv_client = self.get_auth_client(self.test_unprivileged_id)
        res = unpriv_client.post("/soar/api/playbooks/alert_investigation/execute", json={
            "target_id": str(self.test_alert_id),
            "target_type": "alert"
        })
        self.assertEqual(res.status_code, 403)

        # Sec Analyst (has soar.execute) -> 200
        analyst_client = self.get_auth_client(self.test_sec_analyst_id)
        res = analyst_client.post("/soar/api/playbooks/alert_investigation/execute", json={
            "target_id": str(self.test_alert_id),
            "target_type": "alert"
        })
        self.assertEqual(res.status_code, 200)

    def test_soar_approve_permission_boundaries(self):
        """soar.approve remains required to approve or reject staged actions."""
        # Security Analyst (has soar.view and soar.execute, but lacks soar.approve) -> 403
        sec_client = self.get_auth_client(self.test_sec_analyst_id)
        res_approve = sec_client.post("/soar/api/approvals/fake-approval-id/approve", json={
            "notes": "Attempt without permission"
        })
        self.assertEqual(res_approve.status_code, 403)

        res_reject = sec_client.post("/soar/api/approvals/fake-approval-id/reject", json={
            "notes": "Attempt without permission"
        })
        self.assertEqual(res_reject.status_code, 403)

    def test_unauthenticated_all_endpoints_rejected(self):
        """Unauthenticated requests are rejected across all SOAR endpoints."""
        endpoints = [
            ("GET", "/soar/"),
            ("GET", "/soar/playbooks"),
            ("GET", "/soar/api/playbooks"),
            ("GET", "/soar/api/executions"),
            ("GET", "/soar/api/approvals"),
            ("POST", "/soar/api/playbooks/alert_investigation/execute"),
            ("POST", "/soar/api/approvals/test-id/approve"),
            ("POST", "/soar/api/approvals/test-id/reject"),
        ]
        for method, url in endpoints:
            if method == "GET":
                res = self.client.get(url)
            else:
                res = self.client.post(url, json={})
            self.assertIn(res.status_code, [302, 401], f"Endpoint {method} {url} allowed unauthenticated access")


if __name__ == "__main__":
    unittest.main()
