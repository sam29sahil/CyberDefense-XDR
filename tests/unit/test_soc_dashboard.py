"""
Unit Tests for SOC Dashboard Module
CyberDefense XDR
Tests real telemetry aggregation across Assets, Alerts, Incidents,
Vulnerabilities, Network IDS, SIEM, Detection, and Threat Intelligence.
"""

import unittest
import json
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
from app.soc_dashboard.services import get_soc_dashboard_data


class SOCDashboardTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            # Ensure test analyst user exists
            user = User.query.filter_by(username="test_soc_analyst").first()
            if not user:
                user = User(
                    username="test_soc_analyst",
                    email="soc_analyst@cyberdefense.local",
                    first_name="SOC",
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
    # 1. AUTHENTICATION & ROUTE TESTS
    # ============================================================

    def test_01_auth_required_page(self):
        """Unauthenticated GET /soc-dashboard/ must redirect to login."""
        res = self.client.get("/soc-dashboard/")
        self.assertIn(res.status_code, [302, 401])

    def test_02_auth_required_api(self):
        """Unauthenticated GET /soc-dashboard/api/dashboard must redirect or return 401."""
        res = self.client.get("/soc-dashboard/api/dashboard")
        self.assertIn(res.status_code, [302, 401])

    def test_03_dashboard_page_renders(self):
        """Authenticated GET /soc-dashboard/ must return 200 HTML page."""
        auth_client = self.get_auth_client()
        res = auth_client.get("/soc-dashboard/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"SOC Operations Dashboard", res.data)

    def test_04_api_dashboard_structure(self):
        """Authenticated GET /soc-dashboard/api/dashboard returns structured JSON."""
        auth_client = self.get_auth_client()
        res = auth_client.get("/soc-dashboard/api/dashboard")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data.get("success"))
        self.assertIn("generatedAt", data)
        self.assertIn("summary", data)
        self.assertIn("alertOverview", data)
        self.assertIn("incidentOverview", data)
        self.assertIn("assetRiskOverview", data)
        self.assertIn("vulnerabilityOverview", data)
        self.assertIn("idsOverview", data)
        self.assertIn("siemOverview", data)
        self.assertIn("detectionOverview", data)
        self.assertIn("threatIntelOverview", data)
        self.assertIn("activityFeed", data)
        self.assertIn("trendTimeline", data)

    # ============================================================
    # 2. REAL TELEMETRY AGGREGATION TESTS
    # ============================================================

    def test_05_asset_metrics_real_data(self):
        """Asset summary reflects actual Asset records in PostgreSQL."""
        with self.app.app_context():
            # Create a test asset
            asset = Asset(
                asset_id="AST-SOCTEST1",
                name="SOC-TEST-HOST-01",
                ip_address="192.168.99.10",
                asset_type="Server",
                environment="Production",
                criticality="critical",
                status="online",
                risk_score=85,
                risk_severity="critical",
            )
            db.session.add(asset)
            db.session.commit()

            try:
                data = get_soc_dashboard_data()
                summary = data["summary"]
                self.assertGreaterEqual(summary["totalAssets"], 1)
                self.assertGreaterEqual(summary["onlineAssets"], 1)
                self.assertGreaterEqual(summary["criticalAssets"], 1)

                # Verify in top risk assets
                top_assets = data["assetRiskOverview"]["topRiskAssets"]
                names = [a["name"] for a in top_assets]
                self.assertIn("SOC-TEST-HOST-01", names)
            finally:
                db.session.delete(asset)
                db.session.commit()

    def test_06_alert_metrics_real_data(self):
        """Alert overview derives counts from actual Alert records."""
        with self.app.app_context():
            from app.alerts.services import create_alert
            alert = create_alert({
                "title": "SOC Test Critical Alert",
                "severity": "critical",
                "status": "new",
                "category": "Malware",
                "source": "Endpoint Agent",
                "affected_host": "SOC-WIN-01",
            })

            try:
                data = get_soc_dashboard_data()
                summary = data["summary"]
                self.assertGreaterEqual(summary["openAlerts"], 1)
                self.assertGreaterEqual(summary["criticalAlerts"], 1)

                alert_ov = data["alertOverview"]
                self.assertGreaterEqual(alert_ov["bySeverity"]["critical"], 1)
                self.assertGreaterEqual(alert_ov["byStatus"]["new"], 1)

                recent_titles = [a["title"] for a in alert_ov["recentAlerts"]]
                self.assertIn("SOC Test Critical Alert", recent_titles)
            finally:
                db.session.delete(alert)
                db.session.commit()

    def test_07_incident_metrics_real_data(self):
        """Incident overview reflects actual Incident records."""
        with self.app.app_context():
            inc = Incident(
                incident_id="INC-SOCTEST",
                title="SOC Active Ransomware Investigation",
                severity="critical",
                priority="p1_critical",
                status="investigating",
                category="Ransomware",
                source="Detection Engine",
            )
            db.session.add(inc)
            db.session.commit()

            try:
                data = get_soc_dashboard_data()
                summary = data["summary"]
                self.assertGreaterEqual(summary["activeIncidents"], 1)
                self.assertGreaterEqual(summary["criticalIncidents"], 1)

                inc_ov = data["incidentOverview"]
                self.assertGreaterEqual(inc_ov["activeCount"], 1)
                self.assertGreaterEqual(inc_ov["byStatus"]["investigating"], 1)

                titles = [i["title"] for i in inc_ov["recentIncidents"]]
                self.assertIn("SOC Active Ransomware Investigation", titles)
            finally:
                db.session.delete(inc)
                db.session.commit()

    def test_08_vulnerability_metrics_real_data(self):
        """Vulnerability overview reflects unpatched findings from scanner."""
        with self.app.app_context():
            scan = Scan(name="SOC Vuln Scan", scan_type="Quick Scan", status="completed", targets=["192.168.1.1"])
            db.session.add(scan)
            db.session.commit()

            finding = VulnerabilityFinding(
                scan_id=scan.id,
                cve="CVE-2026-0001",
                title="SOC Unauthenticated RCE",
                severity="critical",
                cvss_score=9.8,
                host="192.168.1.1",
                status="open",
            )
            db.session.add(finding)
            db.session.commit()

            try:
                data = get_soc_dashboard_data()
                summary = data["summary"]
                self.assertGreaterEqual(summary["openVulnerabilities"], 1)
                self.assertGreaterEqual(summary["criticalVulnerabilities"], 1)

                vuln_ov = data["vulnerabilityOverview"]
                self.assertGreaterEqual(vuln_ov["bySeverity"]["critical"], 1)
                cves = [f["cve"] for f in vuln_ov["recentFindings"]]
                self.assertIn("CVE-2026-0001", cves)
            finally:
                db.session.delete(finding)
                db.session.delete(scan)
                db.session.commit()

    def test_09_ids_diagnostics_excluded(self):
        """Suricata SID 2200074 checksum noise is excluded from security alert KPIs."""
        with self.app.app_context():
            now = datetime.utcnow()
            # 1. Genuine security alerts (batch of 100 to guarantee appearance in top signatures)
            sec_events = [
                NetworkIDSEvent(
                    event_uuid=f"soc-ids-sec-{i}",
                    timestamp=now,
                    sensor_name="suricata-primary",
                    event_type="alert",
                    signature="ET SCAN Potential SSH Scan",
                    signature_id=2001219,
                    severity="high",
                    category="Attempted Information Leak",
                    src_ip="10.0.0.99",
                    dest_ip="10.0.0.1",
                )
                for i in range(100)
            ]
            # 2. Known diagnostic checksum noise (SID 2200074)
            diag_event = NetworkIDSEvent(
                event_uuid="soc-ids-diag-1",
                timestamp=now,
                sensor_name="suricata-primary",
                event_type="alert",
                signature="SURICATA TCPv4 invalid checksum",
                signature_id=2200074,
                severity="medium",
                category="Generic Protocol Command Decode",
                src_ip="10.0.0.99",
                dest_ip="10.0.0.1",
            )
            for ev in sec_events:
                db.session.add(ev)
            db.session.add(diag_event)
            db.session.commit()

            try:
                data = get_soc_dashboard_data()
                ids_ov = data["idsOverview"]
                # Total events includes diagnostic
                self.assertGreaterEqual(ids_ov["eventsToday"], 2)

                # Genuine security alerts today should NOT include the checksum diagnostic
                top_sigs = [s["signature"] for s in ids_ov["topSignatures"]]
                self.assertIn("ET SCAN Potential SSH Scan", top_sigs)
                self.assertNotIn("SURICATA TCPv4 invalid checksum", top_sigs)
            finally:
                for ev in sec_events:
                    db.session.delete(ev)
                db.session.delete(diag_event)
                db.session.commit()

    def test_10_siem_metrics_real_data(self):
        """SIEM telemetry reflects actual SiemEvent records."""
        with self.app.app_context():
            now = datetime.utcnow()
            evt = SiemEvent(
                event_id="soc-siem-test-1",
                timestamp=now,
                source="Firewall-Edge",
                severity="critical",
                category="Network",
                host="FW-01",
                message="Inbound SYN flood dropped from 203.0.113.5",
                raw_log="Inbound SYN flood dropped from 203.0.113.5",
            )
            db.session.add(evt)
            db.session.commit()

            try:
                data = get_soc_dashboard_data()
                summary = data["summary"]
                self.assertGreaterEqual(summary["siemEventsToday"], 1)

                siem_ov = data["siemOverview"]
                self.assertGreaterEqual(siem_ov["bySeverity"]["critical"], 1)
                recent_sources = [s["source"] for s in siem_ov["recentEvents"]]
                self.assertIn("Firewall-Edge", recent_sources)
            finally:
                db.session.delete(evt)
                db.session.commit()

    def test_11_detection_metrics_real_data(self):
        """Detection overview counts active rules and today's events."""
        with self.app.app_context():
            rule = DetectionRule(
                rule_id="R-SOCTEST",
                name="Suspicious WMI Execution",
                category="Execution",
                severity="high",
                status="active",
            )
            db.session.add(rule)
            db.session.flush()

            evt = DetectionEvent(
                event_id="DET-SOCTEST-1",
                rule_id=rule.id,
                source="WMI Provider",
                host="SRV-APP-01",
                severity="high",
                timestamp=datetime.utcnow(),
            )
            db.session.add(evt)
            db.session.commit()

            try:
                data = get_soc_dashboard_data()
                det_ov = data["detectionOverview"]
                self.assertGreaterEqual(det_ov["activeRules"], 1)
                self.assertGreaterEqual(det_ov["eventsToday"], 1)
                self.assertGreaterEqual(det_ov["criticalHighEvents"], 1)

                recent_ids = [d["eventId"] for d in det_ov["recentDetections"]]
                self.assertIn("DET-SOCTEST-1", recent_ids)
            finally:
                db.session.delete(evt)
                db.session.delete(rule)
                db.session.commit()

    def test_12_threat_intel_metrics(self):
        """Threat intelligence summary counts actual IOC and Campaign records."""
        with self.app.app_context():
            ioc = IOC(
                ioc_id="IOC-SOCTEST",
                type="ip",
                value="198.51.100.77",
                threat_level="critical",
                confidence="high",
            )
            db.session.add(ioc)
            db.session.commit()

            try:
                data = get_soc_dashboard_data()
                ti = data["threatIntelOverview"]
                self.assertGreaterEqual(ti["totalIocs"], 1)
            finally:
                db.session.delete(ioc)
                db.session.commit()

    def test_13_activity_feed_format(self):
        """Activity feed contains chronological records with source and entity ID."""
        with self.app.app_context():
            from app.alerts.services import create_alert
            alert = create_alert({
                "title": "Activity Feed Verification Alert",
                "severity": "high",
                "status": "new",
                "category": "Credential Access",
                "source": "Audit Log",
                "affected_host": "AUTH-SRV-02",
            })

            try:
                data = get_soc_dashboard_data()
                feed = data["activityFeed"]
                self.assertIsInstance(feed, list)
                self.assertGreaterEqual(len(feed), 1)

                item = next((x for x in feed if x["title"] == "Activity Feed Verification Alert"), None)
                self.assertIsNotNone(item)
                self.assertEqual(item["source"], "Alert Center")
                self.assertEqual(item["severity"], "high")
                self.assertEqual(item["entityId"], alert.alert_id)
                self.assertIn("/alert-center/", item["url"])
            finally:
                db.session.delete(alert)
                db.session.commit()

    def test_14_trend_timeline_24h(self):
        """Trend timeline returns exactly 24 hourly buckets with aligned counts."""
        with self.app.app_context():
            data = get_soc_dashboard_data()
            timeline = data["trendTimeline"]

            self.assertEqual(len(timeline["hours"]), 24)
            self.assertEqual(len(timeline["alerts"]), 24)
            self.assertEqual(len(timeline["idsAlerts"]), 24)
            self.assertEqual(len(timeline["detections"]), 24)

    def test_15_empty_database_graceful_handling(self):
        """Empty tables or zero records do not crash the service."""
        with self.app.app_context():
            data = get_soc_dashboard_data()
            self.assertTrue(data["success"])
            self.assertIsInstance(data["summary"]["totalAssets"], int)
            self.assertIsInstance(data["summary"]["openAlerts"], int)
            self.assertIsInstance(data["summary"]["idsAlertsToday"], int)
            self.assertIsInstance(data["summary"]["siemEventsToday"], int)


if __name__ == "__main__":
    unittest.main()
