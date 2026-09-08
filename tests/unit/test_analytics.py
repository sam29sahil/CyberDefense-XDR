"""
Unit Tests for Security Analytics Module
CyberDefense XDR

Tests the real, database-backed analytical intelligence layer:
- Route authentication and authorization
- Time-range validation (24h, 7d, 30d, 90d, custom)
- Aggregation across all 8 security domains
- Exclusion of Suricata SID 2200074 checksum noise from security alert metrics
- MTTR (Mean Time to Resolution) calculation
- Cross-module threat correlations and dual-risk asset identification
- Dedicated sub-endpoints
"""

import unittest
import json
import uuid
from datetime import datetime, timedelta

from app import create_app
from app.extensions import db
from app.users.models import User
from app.assets.models import Asset
from app.alerts.models import Alert
from app.incidents.models import Incident
from app.scanner.models import Scan, VulnerabilityFinding
from app.ids.models import NetworkIDSEvent
from app.siem.models import SiemEvent
from app.detection.models import DetectionRule, DetectionEvent
from app.threatintel.models import IOC, ThreatCampaign, ThreatActor, ThreatFeed
from app.analytics.services import (
    parse_time_range,
    get_analytics_dashboard_data,
    get_analytics_overview,
    get_alert_analytics,
    get_incident_analytics,
    get_vulnerability_analytics,
    get_ids_analytics,
    get_siem_analytics,
    get_detection_analytics,
    get_threat_intel_analytics,
    get_asset_analytics,
    get_trend_analytics,
    get_correlation_analytics,
)


class AnalyticsModuleTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="test_analytics_analyst").first()
            if not user:
                user = User(
                    username="test_analytics_analyst",
                    email="analytics_analyst@cyberdefense.local",
                    first_name="Analytics",
                    last_name="Analyst",
                    role="analyst",
                    is_active=True,
                )
                user.set_password("AnalyticsPass123!")
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
    # 1. AUTHENTICATION & ROUTE ACCESS TESTS
    # ============================================================

    def test_01_unauthenticated_page_redirects(self):
        """Unauthenticated GET /analytics/ must redirect to login."""
        res = self.client.get("/analytics/")
        self.assertIn(res.status_code, [302, 401])

        res2 = self.client.get("/analytics/dashboard")
        self.assertIn(res2.status_code, [302, 401])

    def test_02_unauthenticated_api_redirects_or_denies(self):
        """Unauthenticated API calls must be blocked."""
        endpoints = [
            "/analytics/api/dashboard",
            "/analytics/api/overview",
            "/analytics/api/alerts",
            "/analytics/api/incidents",
            "/analytics/api/vulnerabilities",
            "/analytics/api/assets",
            "/analytics/api/ids",
            "/analytics/api/siem",
            "/analytics/api/detection",
            "/analytics/api/threat-intelligence",
            "/analytics/api/trends",
            "/analytics/api/correlations",
        ]
        for ep in endpoints:
            res = self.client.get(ep)
            self.assertIn(res.status_code, [302, 401], f"Endpoint {ep} was accessible unauthenticated")

    def test_03_authenticated_page_renders(self):
        """Authenticated GET /analytics/ returns 200 with dashboard shell."""
        auth_client = self.get_auth_client()
        res = auth_client.get("/analytics/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Security Analytics", res.data)
        self.assertIn(b"chartMultiTrend", res.data)

    # ============================================================
    # 2. TIME-RANGE PARSING & SAFE FILTERING TESTS
    # ============================================================

    def test_04_time_range_parser_defaults_to_7d(self):
        """No parameters defaults safely to 7 days with daily interval."""
        start_dt, end_dt, effective_range, interval = parse_time_range()
        self.assertEqual(effective_range, "7d")
        self.assertEqual(interval, "day")
        diff = end_dt - start_dt
        self.assertAlmostEqual(diff.total_seconds(), 7 * 86400, delta=10)

    def test_05_time_range_parser_24h(self):
        """24h range sets hourly interval."""
        start_dt, end_dt, effective_range, interval = parse_time_range("24h")
        self.assertEqual(effective_range, "24h")
        self.assertEqual(interval, "hour")
        diff = end_dt - start_dt
        self.assertAlmostEqual(diff.total_seconds(), 86400, delta=10)

    def test_06_time_range_parser_30d_and_90d(self):
        """30d and 90d ranges parse with daily interval."""
        start30, end30, eff30, int30 = parse_time_range("30d")
        self.assertEqual(eff30, "30d")
        self.assertEqual(int30, "day")
        self.assertAlmostEqual((end30 - start30).total_seconds(), 30 * 86400, delta=10)

        start90, end90, eff90, int90 = parse_time_range("90d")
        self.assertEqual(eff90, "90d")
        self.assertEqual(int90, "day")
        self.assertAlmostEqual((end90 - start90).total_seconds(), 90 * 86400, delta=10)

    def test_07_custom_range_valid(self):
        """Valid custom range YYYY-MM-DD parses properly."""
        start_param = "2026-01-01"
        end_param = "2026-01-15"
        start_dt, end_dt, effective_range, interval = parse_time_range("custom", start_param, end_param)
        self.assertEqual(effective_range, "custom")
        self.assertEqual(start_dt.year, 2026)
        self.assertEqual(start_dt.month, 1)
        self.assertEqual(start_dt.day, 1)
        self.assertEqual(end_dt.year, 2026)
        self.assertEqual(end_dt.month, 1)
        self.assertEqual(end_dt.day, 15)

    def test_08_custom_range_invalid_raises_value_error(self):
        """Malformed or reversed dates strictly raise ValueError and API returns 400."""
        # 1. Reversed: start > end
        with self.assertRaises(ValueError):
            parse_time_range("custom", "2026-02-10", "2026-02-01")

        # 2. Corrupt string
        with self.assertRaises(ValueError):
            parse_time_range("custom", "not-a-date", "2026-02-01")

        # 3. Missing end
        with self.assertRaises(ValueError):
            parse_time_range("custom", "2026-02-01", None)

        # 4. API handles it gracefully with 400 response
        auth_client = self.get_auth_client()
        res = auth_client.get("/analytics/api/dashboard?range=custom&start=2026-02-10&end=2026-02-01")
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()["success"])

    # ============================================================
    # 3. FULL API PAYLOAD STRUCTURE TESTS
    # ============================================================

    def test_09_api_dashboard_payload_structure(self):
        """GET /analytics/api/dashboard returns complete schema."""
        auth_client = self.get_auth_client()
        res = auth_client.get("/analytics/api/dashboard")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data.get("success"))
        self.assertIn("filters", data)
        self.assertIn("overview", data)
        self.assertIn("trends", data)
        self.assertIn("alerts", data)
        self.assertIn("incidents", data)
        self.assertIn("vulnerabilities", data)
        self.assertIn("ids", data)
        self.assertIn("siem", data)
        self.assertIn("detection", data)
        self.assertIn("threat_intel", data)
        self.assertIn("assets", data)
        self.assertIn("correlations", data)

    # ============================================================
    # 4. REAL TELEMETRY AGGREGATION TESTS
    # ============================================================

    def test_10_asset_telemetry_aggregation(self):
        """Asset analytics reflects database records without mock numbers."""
        with self.app.app_context():
            asset = Asset(
                asset_id="AST-ANALYTICS-01",
                name="ANALYTICS-DB-SERVER",
                ip_address="10.200.1.50",
                asset_type="Database",
                environment="Production",
                criticality="critical",
                status="online",
                risk_score=92,
                risk_severity="critical",
                open_alerts_count=3,
                open_vulnerabilities_count=4,
            )
            db.session.add(asset)
            db.session.commit()

            try:
                res = get_asset_analytics()
                self.assertGreaterEqual(res["total"], 1)
                self.assertGreaterEqual(res["online"], 1)

                tiers = res["risk_score_tiers"]
                self.assertGreaterEqual(tiers["critical"], 1)

                top_names = [a["name"] for a in res["top_risk_assets"]]
                self.assertIn("ANALYTICS-DB-SERVER", top_names)
            finally:
                db.session.delete(asset)
                db.session.commit()

    def test_11_alert_telemetry_aggregation(self):
        """Alert analytics aggregates severity and status within time window."""
        with self.app.app_context():
            from app.alerts.services import create_alert
            alert = create_alert({
                "title": "Analytics Critical Test Alert",
                "severity": "critical",
                "status": "new",
                "category": "Credential Access",
                "source": "Auditd",
                "affected_host": "10.200.1.50",
            })

            try:
                start_dt = datetime.utcnow() - timedelta(hours=1)
                end_dt = datetime.utcnow() + timedelta(hours=1)
                res = get_alert_analytics(start_dt, end_dt)

                self.assertGreaterEqual(res["total"], 1)
                self.assertGreaterEqual(res["by_severity"]["critical"], 1)
                self.assertGreaterEqual(res["by_status"]["new"], 1)
            finally:
                db.session.delete(alert)
                db.session.commit()

    def test_12_incident_analytics_and_mttr(self):
        """Incident analytics computes active counts and MTTR correctly."""
        with self.app.app_context():
            created = datetime.utcnow() - timedelta(hours=5)
            resolved = datetime.utcnow() - timedelta(hours=1)

            inc_closed = Incident(
                incident_id="INC-ANALYTICS-MTTR",
                title="Analytics Resolved Incident",
                severity="high",
                priority="p2_high",
                status="resolved",
                category="Malware",
                created_at=created,
                resolved_at=resolved,
            )
            db.session.add(inc_closed)
            db.session.commit()

            try:
                start_dt = datetime.utcnow() - timedelta(days=1)
                end_dt = datetime.utcnow() + timedelta(days=1)
                res = get_incident_analytics(start_dt, end_dt)

                self.assertGreaterEqual(res["total"], 1)
                self.assertGreaterEqual(res["resolved"], 1)
                # Resolved took 4.0 hours
                self.assertIsNotNone(res["mttr_hours"])
                self.assertAlmostEqual(res["mttr_hours"], 4.0, delta=0.5)
            finally:
                db.session.delete(inc_closed)
                db.session.commit()

    def test_13_vulnerability_analytics(self):
        """Vulnerability analytics aggregates finding counts and severity."""
        with self.app.app_context():
            scan = Scan(name="Analytics Vuln Scan", scan_type="Port Scan", status="completed", targets=["10.0.0.10"])
            db.session.add(scan)
            db.session.commit()

            finding = VulnerabilityFinding(
                scan_id=scan.id,
                cve="CVE-2026-9999",
                title="Analytics Critical Finding",
                severity="critical",
                cvss_score=9.9,
                host="10.0.0.10",
                status="open",
            )
            db.session.add(finding)
            db.session.commit()

            try:
                start_dt = datetime.utcnow() - timedelta(days=1)
                end_dt = datetime.utcnow() + timedelta(days=1)
                res = get_vulnerability_analytics(start_dt, end_dt)

                self.assertGreaterEqual(res["total"], 1)
                self.assertGreaterEqual(res["by_severity"]["critical"], 1)
                top_cves = [c["cve_id"] for c in res["top_cves"]]
                self.assertIn("CVE-2026-9999", top_cves)
            finally:
                db.session.delete(finding)
                db.session.delete(scan)
                db.session.commit()

    def test_14_ids_analytics_excludes_checksum_noise(self):
        """
        Critical rule verification:
        Suricata SID 2200074 checksum noise is excluded from security alerts
        and tracked separately as diagnostic events.
        """
        with self.app.app_context():
            now = datetime.utcnow()
            # Genuine security threat
            sec_event = NetworkIDSEvent(
                event_uuid="analytics-ids-sec",
                timestamp=now,
                sensor_name="suricata-primary",
                event_type="alert",
                signature="ET SCAN Nmap Scripting Engine",
                signature_id=2009582,
                severity="high",
                category="Attempted Information Leak",
                src_ip="192.168.1.50",
                dest_ip="192.168.1.1",
            )
            # Checksum diagnostic noise (SID 2200074)
            diag_event = NetworkIDSEvent(
                event_uuid="analytics-ids-diag",
                timestamp=now,
                sensor_name="suricata-primary",
                event_type="alert",
                signature="SURICATA TCPv4 invalid checksum",
                signature_id=2200074,
                severity="low",
                category="Generic Protocol Command Decode",
                src_ip="192.168.1.50",
                dest_ip="142.250.190.46",
            )
            db.session.add(sec_event)
            db.session.add(diag_event)
            db.session.commit()

            try:
                start_dt = now - timedelta(hours=1)
                end_dt = now + timedelta(hours=1)
                res = get_ids_analytics(start_dt, end_dt)

                # Security threats must exclude SID 2200074
                self.assertGreaterEqual(res["security_alerts"], 1)
                self.assertGreaterEqual(res["diagnostic_events"], 1)
                self.assertGreaterEqual(res["total_events"], 2)

                # Signature list for threats should contain Nmap and NOT checksum noise
                sig_names = [s["signature"] for s in res["top_signatures"]]
                self.assertIn("ET SCAN Nmap Scripting Engine", sig_names)
                self.assertNotIn("SURICATA TCPv4 invalid checksum", sig_names)
            finally:
                db.session.delete(sec_event)
                db.session.delete(diag_event)
                db.session.commit()

    def test_15_siem_and_detection_telemetry(self):
        """SIEM and Detection events aggregate accurately."""
        with self.app.app_context():
            now = datetime.utcnow()
            rule_id = f"ANALYTICS-RULE-{uuid.uuid4().hex[:6]}"
            rule = DetectionRule(
                rule_id=rule_id,
                name="Analytics Test Rule",
                category="Suspicious Activity",
                severity="high",
            )
            db.session.add(rule)
            db.session.commit()

            det_id = f"DET-ANA-{uuid.uuid4().hex[:8]}"
            det_event = DetectionEvent(
                event_id=det_id,
                rule_id=rule.id,
                severity="high",
                source="Auditd",
                host="10.0.0.25",
                timestamp=now,
            )
            db.session.add(det_event)
            db.session.commit()

            siem_id = f"SIEM-ANA-{uuid.uuid4().hex[:8]}"
            siem_event = SiemEvent(
                event_id=siem_id,
                timestamp=now,
                source="auditd",
                severity="warning",
                category="Authentication",
                host="10.0.0.25",
                message="User failed authentication",
                raw_log="User failed authentication",
                detection_event_id=det_event.id,
            )
            db.session.add(siem_event)
            db.session.commit()

            try:
                start_dt = now - timedelta(hours=1)
                end_dt = now + timedelta(hours=1)

                siem_res = get_siem_analytics(start_dt, end_dt)
                self.assertGreaterEqual(siem_res["total"], 1)

                det_res = get_detection_analytics(start_dt, end_dt)
                self.assertGreaterEqual(det_res["total"], 1)
            finally:
                db.session.delete(siem_event)
                db.session.delete(det_event)
                db.session.delete(rule)
                db.session.commit()

    def test_16_threat_intelligence_metrics(self):
        """Threat intelligence analytics returns IOC and campaign statistics."""
        with self.app.app_context():
            ioc = IOC(
                ioc_id="IOC-ANALYTICS-01",
                value="198.51.100.22",
                type="ip",
                threat_level="high",
                confidence="High",
                source="AbuseCH",
            )
            db.session.add(ioc)
            db.session.commit()

            try:
                res = get_threat_intel_analytics()
                self.assertGreaterEqual(res["total_iocs"], 1)
                types = [t["type"] for t in res["by_type"]]
                self.assertIn("ip", types)
            finally:
                db.session.delete(ioc)
                db.session.commit()

    def test_17_cross_module_correlations(self):
        """Cross-module correlation accurately calculates dual-risk assets."""
        with self.app.app_context():
            asset = Asset(
                asset_id="AST-CORR-01",
                name="DUAL-RISK-SERVER",
                ip_address="10.50.50.50",
                asset_type="Server",
                status="online",
                risk_score=95,
                open_alerts_count=2,
                open_vulnerabilities_count=3,
            )
            db.session.add(asset)
            db.session.commit()

            try:
                start_dt = datetime.utcnow() - timedelta(days=7)
                end_dt = datetime.utcnow() + timedelta(days=1)
                res = get_correlation_analytics(start_dt, end_dt)

                self.assertGreaterEqual(res["dual_risk_count"], 1)
                dual_names = [a["name"] for a in res["dual_risk_assets"]]
                self.assertIn("DUAL-RISK-SERVER", dual_names)
            finally:
                db.session.delete(asset)
                db.session.commit()

    # ============================================================
    # 5. SUB-ENDPOINTS ACCESSIBILITY TESTS
    # ============================================================

    def test_18_sub_endpoints_return_200(self):
        """All sub-domain REST API endpoints respond with JSON."""
        auth_client = self.get_auth_client()
        sub_endpoints = [
            "/analytics/api/overview",
            "/analytics/api/alerts",
            "/analytics/api/incidents",
            "/analytics/api/vulnerabilities",
            "/analytics/api/assets",
            "/analytics/api/ids",
            "/analytics/api/siem",
            "/analytics/api/detection",
            "/analytics/api/threat-intelligence",
            "/analytics/api/trends",
            "/analytics/api/correlations",
        ]
        for ep in sub_endpoints:
            res = auth_client.get(ep)
            self.assertEqual(res.status_code, 200, f"Sub-endpoint {ep} returned status {res.status_code}")
            json_data = res.get_json()
            self.assertTrue(json_data.get("success"), f"Sub-endpoint {ep} did not return success=True")


if __name__ == "__main__":
    unittest.main()
