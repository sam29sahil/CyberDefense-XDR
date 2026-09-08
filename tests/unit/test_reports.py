"""
Unit Tests for Security Reports Module
CyberDefense XDR
Tests real telemetry report generation, PDF/CSV creation,
the 8 canonical report types, Suricata checksum exclusion,
REST APIs, authorization, download security, and lifecycle management.
"""

import io
import json
import os
import unittest
import uuid
from datetime import datetime, timedelta

from app import create_app
from app.extensions import db
from app.users.models import User
from app.reports.models import Report, generate_report_id
from app.reports.services import (
    REPORT_TYPES,
    build_report_telemetry,
    collect_network_ids,
    create_report,
    delete_report,
    get_report_by_id,
    get_safe_report_path,
    list_reports,
)
from app.ids.models import NetworkIDSEvent


class ReportsTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="test_reports_analyst").first()
            if not user:
                user = User(
                    username="test_reports_analyst",
                    email="reports_analyst@cyberdefense.local",
                    first_name="Reports",
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
        self.created_reports = []

    def tearDown(self):
        with self.app.app_context():
            for rid in self.created_reports:
                try:
                    delete_report(rid)
                except Exception:
                    pass

    def get_auth_client(self):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.test_user_id)
            sess["_fresh"] = True
        return self.client

    # ============================================================
    # 1. MODEL & UNIT SERVICE TESTS
    # ============================================================

    def test_01_report_model_properties_and_to_dict(self):
        """Test Report model attributes, JSON serialization, and to_dict method."""
        with self.app.app_context():
            rep = Report(
                report_type="executive_summary",
                title="Q3 Security Posture",
                description="Executive Briefing",
                format="pdf",
                status="completed",
                generated_by="test_reports_analyst",
            )
            rep.filters = {"severity": "critical"}
            rep.summary = {"posture_score": 92}
            db.session.add(rep)
            db.session.commit()
            self.created_reports.append(rep.report_id)

            fetched = Report.query.filter_by(report_id=rep.report_id).first()
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched.filters["severity"], "critical")
            self.assertEqual(fetched.summary["posture_score"], 92)

            d = fetched.to_dict()
            self.assertEqual(d["report_id"], fetched.report_id)
            self.assertEqual(d["report_type"], "executive_summary")
            self.assertEqual(d["format"], "pdf")
            self.assertEqual(d["status"], "completed")

    def test_02_catalog_contains_all_8_canonical_types(self):
        """Verify the 8 canonical report types exist with valid configurations."""
        expected_types = [
            "executive_summary",
            "soc_operations",
            "vulnerability_assessment",
            "incident_response",
            "alert_detection",
            "network_ids",
            "asset_risk",
            "threat_intel",
        ]
        self.assertEqual(len(REPORT_TYPES), 8)
        for t in expected_types:
            self.assertIn(t, REPORT_TYPES)
            self.assertIn("name", REPORT_TYPES[t])
            self.assertIn("pdf", REPORT_TYPES[t]["supported_formats"])
            self.assertIn("csv", REPORT_TYPES[t]["supported_formats"])

    # ============================================================
    # 2. AUTHENTICATION & ACCESS CONTROL TESTS
    # ============================================================

    def test_03_unauthenticated_access_denied(self):
        """Unauthenticated requests to reports views and APIs must redirect to login."""
        res_view = self.client.get("/reports/")
        self.assertEqual(res_view.status_code, 302)
        self.assertIn("/auth/login", res_view.headers.get("Location", ""))

        res_api = self.client.get("/reports/api/history")
        self.assertEqual(res_api.status_code, 302)

        res_gen = self.client.post("/reports/api/generate", json={"report_type": "executive_summary"})
        self.assertEqual(res_gen.status_code, 302)

    def test_04_authenticated_page_access(self):
        """Authenticated analyst can access the Reports main page."""
        client = self.get_auth_client()
        res = client.get("/reports/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Security Reports", res.data)
        self.assertIn(b"Available Report Types", res.data)
        self.assertIn(b"Report History", res.data)

    def test_05_api_types_endpoint(self):
        """GET /reports/api/types returns 8 types with metadata."""
        client = self.get_auth_client()
        res = client.get("/reports/api/types")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["types"]), 8)

    # ============================================================
    # 3. REPORT GENERATION TESTS (PDF & CSV)
    # ============================================================

    def test_06_generate_executive_summary_pdf(self):
        """Generate Executive Security Summary in PDF format."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "executive_summary",
            "format": "pdf",
            "title": "Executive Summary Test PDF",
            "date_range_preset": "7d",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        report = data["report"]
        self.created_reports.append(report["report_id"])
        self.assertEqual(report["format"], "pdf")
        self.assertGreater(report["file_size_bytes"], 0)

        # Check physical file header
        with self.app.app_context():
            rep_obj = get_report_by_id(report["report_id"])
            self.assertTrue(os.path.isfile(rep_obj.file_path))
            with open(rep_obj.file_path, "rb") as f:
                self.assertTrue(f.read(5).startswith(b"%PDF-"))

    def test_07_generate_executive_summary_csv(self):
        """Generate Executive Security Summary in CSV format."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "executive_summary",
            "format": "csv",
            "title": "Executive Summary Test CSV",
            "date_range_preset": "30d",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        report = data["report"]
        self.created_reports.append(report["report_id"])
        self.assertEqual(report["format"], "csv")

        with self.app.app_context():
            rep_obj = get_report_by_id(report["report_id"])
            self.assertTrue(os.path.isfile(rep_obj.file_path))
            with open(rep_obj.file_path, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("# CyberDefense XDR Security Report", content)
                self.assertIn("--- KPI METRICS SUMMARY ---", content)

    def test_08_generate_soc_operations_report(self):
        """Generate SOC Operations Report."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "soc_operations",
            "format": "pdf",
            "date_range_preset": "24h",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.created_reports.append(data["report"]["report_id"])
        self.assertEqual(data["report"]["status"], "completed")

    def test_09_generate_vulnerability_assessment_report(self):
        """Generate Vulnerability Assessment Report."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "vulnerability_assessment",
            "format": "csv",
            "filters": {"severity": "critical"},
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.created_reports.append(data["report"]["report_id"])
        self.assertEqual(data["report"]["status"], "completed")

    def test_10_generate_incident_response_report(self):
        """Generate Incident Response Report."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "incident_response",
            "format": "pdf",
            "date_range_preset": "all",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.created_reports.append(data["report"]["report_id"])
        self.assertEqual(data["report"]["status"], "completed")

    def test_11_generate_alert_detection_report(self):
        """Generate Alert & Detection Report."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "alert_detection",
            "format": "pdf",
            "date_range_preset": "7d",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.created_reports.append(data["report"]["report_id"])
        self.assertEqual(data["report"]["status"], "completed")

    def test_12_generate_network_ids_report(self):
        """Generate Network IDS Report."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "network_ids",
            "format": "pdf",
            "date_range_preset": "7d",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.created_reports.append(data["report"]["report_id"])
        self.assertEqual(data["report"]["status"], "completed")

    def test_13_generate_asset_risk_report(self):
        """Generate Asset Risk Report."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "asset_risk",
            "format": "csv",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.created_reports.append(data["report"]["report_id"])
        self.assertEqual(data["report"]["status"], "completed")

    def test_14_generate_threat_intel_report(self):
        """Generate Threat Intelligence Report."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "threat_intel",
            "format": "pdf",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.created_reports.append(data["report"]["report_id"])
        self.assertEqual(data["report"]["status"], "completed")

    # ============================================================
    # 4. SURICATA CHECKSUM DIAGNOSTIC EXCLUSION VERIFICATION
    # ============================================================

    def test_15_network_ids_report_strictly_excludes_checksum_noise(self):
        """
        Verify that Network IDS report telemetry strictly excludes Suricata
        SID 2200074 checksum noise.
        """
        with self.app.app_context():
            noise_event = NetworkIDSEvent(
                event_uuid=f"test-noise-{uuid.uuid4()}",
                timestamp=datetime.utcnow(),
                event_type="alert",
                sensor_name="suricata-test",
                interface="eth0",
                signature_id=2200074,
                signature="SURICATA TCPv4 invalid checksum",
                severity="info",
                action="allowed",
                raw_event_json="{}",
            )
            db.session.add(noise_event)
            db.session.commit()

            try:
                telemetry = collect_network_ids(None, None, {})
                for section in telemetry.get("sections", []):
                    for row in section.get("rows", []):
                        for cell in row:
                            self.assertNotIn("SURICATA TCPv4 invalid checksum", str(cell))
            finally:
                db.session.delete(noise_event)
                db.session.commit()

    # ============================================================
    # 5. REPORT HISTORY, DETAILS, DOWNLOAD & DELETION APIS
    # ============================================================

    def test_16_report_history_api(self):
        """GET /reports/api/history returns paginated results."""
        client = self.get_auth_client()
        res_gen = client.post("/reports/api/generate", json={"report_type": "executive_summary", "format": "pdf"})
        rep_id = res_gen.get_json()["report"]["report_id"]
        self.created_reports.append(rep_id)

        res = client.get("/reports/api/history?page=1&per_page=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["total"], 1)
        self.assertIn("reports", data)

    def test_17_report_details_page_and_api(self):
        """GET /reports/<id> and GET /reports/api/<id> return full report telemetry."""
        client = self.get_auth_client()
        res_gen = client.post("/reports/api/generate", json={"report_type": "soc_operations", "format": "pdf"})
        rep_id = res_gen.get_json()["report"]["report_id"]
        self.created_reports.append(rep_id)

        # API
        res_api = client.get(f"/reports/api/{rep_id}")
        self.assertEqual(res_api.status_code, 200)
        api_data = res_api.get_json()
        self.assertTrue(api_data["success"])
        self.assertEqual(api_data["report"]["report_id"], rep_id)

        # HTML View
        res_view = client.get(f"/reports/{rep_id}")
        self.assertEqual(res_view.status_code, 200)
        self.assertIn(rep_id.encode(), res_view.data)

    def test_18_report_download_api(self):
        """GET /reports/api/<id>/download streams the file with correct headers."""
        client = self.get_auth_client()
        res_gen = client.post("/reports/api/generate", json={"report_type": "executive_summary", "format": "pdf"})
        rep_id = res_gen.get_json()["report"]["report_id"]
        self.created_reports.append(rep_id)

        res_dl = client.get(f"/reports/api/{rep_id}/download")
        self.assertEqual(res_dl.status_code, 200)
        self.assertEqual(res_dl.headers.get("Content-Type"), "application/pdf")
        self.assertIn(f"filename={rep_id}.pdf", res_dl.headers.get("Content-Disposition", ""))
        self.assertTrue(res_dl.data.startswith(b"%PDF-"))

    def test_19_report_download_security_path_traversal(self):
        """Verify that directory traversal attempts in download endpoint are blocked."""
        client = self.get_auth_client()
        res_bad = client.get("/reports/api/nonexistent-report/download")
        self.assertEqual(res_bad.status_code, 404)

        res_trav = client.get("/reports/api/..%2F..%2Fetc%2Fpasswd/download")
        self.assertIn(res_trav.status_code, [400, 404])

    def test_20_report_deletion(self):
        """DELETE /reports/api/<id> permanently deletes database record and disk file."""
        client = self.get_auth_client()
        res_gen = client.post("/reports/api/generate", json={"report_type": "asset_risk", "format": "csv"})
        rep_id = res_gen.get_json()["report"]["report_id"]

        with self.app.app_context():
            rep_obj = get_report_by_id(rep_id)
            fpath = rep_obj.file_path
            self.assertTrue(os.path.isfile(fpath))

        res_del = client.delete(f"/reports/api/{rep_id}")
        self.assertEqual(res_del.status_code, 200)
        self.assertTrue(res_del.get_json()["success"])

        with self.app.app_context():
            self.assertIsNone(get_report_by_id(rep_id))
            self.assertFalse(os.path.isfile(fpath))

    # ============================================================
    # 6. INPUT VALIDATION & ERROR HANDLING TESTS
    # ============================================================

    def test_21_invalid_report_type_rejection(self):
        """Reject generation requests with unsupported report_type."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={"report_type": "unsupported_fake_type"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Invalid report_type", data["error"])

    def test_22_invalid_format_rejection(self):
        """Reject generation requests with unsupported file format."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "executive_summary",
            "format": "docx",
        })
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Invalid format", data["error"])

    def test_23_custom_date_range_filtering(self):
        """Generate report with explicit custom date range."""
        client = self.get_auth_client()
        res = client.post("/reports/api/generate", json={
            "report_type": "soc_operations",
            "format": "csv",
            "date_range_preset": "custom",
            "date_from": "2026-08-01T00:00:00Z",
            "date_to": "2026-08-31T23:59:59Z",
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.created_reports.append(data["report"]["report_id"])
        self.assertIsNotNone(data["report"]["date_from"])
        self.assertIsNotNone(data["report"]["date_to"])


if __name__ == "__main__":
    unittest.main()
