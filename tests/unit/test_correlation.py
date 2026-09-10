"""
CyberDefense XDR
Unit Tests for Correlation Engine
Tests relationship discovery, deterministic risk scoring, graph generation,
campaign detection, diagnostic event exclusion, and RBAC.
"""

import unittest
from app import create_app
from app.extensions import db
from app.users.models import User
from app.alerts.models import Alert
from app.ids.models import NetworkIDSEvent as IDSEvent
from app.incidents.models import Incident
from app.assets.models import Asset
from app.scanner.models import Scan, VulnerabilityFinding
from app.threatintel.models import IOC
from app.correlation.services import calculate_risk_score, correlate_entity, find_campaigns


class CorrelationEngineTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        @cls.app.before_request
        def _clear_cached_login():
            from flask import g
            if hasattr(g, "_login_user"):
                delattr(g, "_login_user")

        with cls.app.app_context():
            # 1. Analyst user (has correlation.view and correlation.search)
            analyst = User.query.filter_by(username="test_corr_analyst").first()
            if not analyst:
                analyst = User(
                    username="test_corr_analyst",
                    email="corr@cyberdefense.local",
                    first_name="Correlation",
                    last_name="Analyst",
                    role="analyst",
                    is_active=True,
                )
                analyst.set_password("CorrPass123!")
                db.session.add(analyst)
                db.session.commit()
            cls.analyst_user_id = analyst.id

            # 2. Viewer user (has correlation.view, but lacks correlation.search)
            viewer = User.query.filter_by(username="test_corr_viewer").first()
            if not viewer:
                viewer = User(
                    username="test_corr_viewer",
                    email="corr_viewer@cyberdefense.local",
                    first_name="Correlation",
                    last_name="Viewer",
                    role="viewer",
                    is_active=True,
                )
                viewer.set_password("ViewerPass123!")
                db.session.add(viewer)
                db.session.commit()
            cls.viewer_user_id = viewer.id

            # 3. Unprivileged user (no correlation permissions)
            unprivileged = User.query.filter_by(username="test_corr_unprivileged").first()
            if not unprivileged:
                unprivileged = User(
                    username="test_corr_unprivileged",
                    email="corr_unprivileged@cyberdefense.local",
                    first_name="Unprivileged",
                    last_name="User",
                    role="unprivileged",
                    is_active=True,
                )
                unprivileged.set_password("UnprivPass123!")
                db.session.add(unprivileged)
                db.session.commit()
            cls.unprivileged_user_id = unprivileged.id

    def setUp(self):
        self.client = self.app.test_client()

    def get_auth_client(self, user_id=None):
        uid = user_id or self.analyst_user_id
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(uid)
            sess["_fresh"] = True
        return self.client

    # 1. Auth & RBAC Routes
    def test_unauthenticated_redirects(self):
        res = self.client.get("/correlation/")
        self.assertIn(res.status_code, [302, 401])

        res_api = self.client.get("/correlation/api/campaigns")
        self.assertIn(res_api.status_code, [302, 401])

        res_search = self.client.post("/correlation/api/search", json={"query": "10.0.0.1"})
        self.assertIn(res_search.status_code, [302, 401])

    def test_rbac_unprivileged_denied(self):
        client = self.get_auth_client(self.unprivileged_user_id)
        res_view = client.get("/correlation/")
        self.assertEqual(res_view.status_code, 403)

        res_api = client.get("/correlation/api/campaigns")
        self.assertEqual(res_api.status_code, 403)

        res_search = client.post("/correlation/api/search", json={"query": "10.0.0.1"})
        self.assertEqual(res_search.status_code, 403)

    def test_rbac_viewer_can_view_but_cannot_search(self):
        client = self.get_auth_client(self.viewer_user_id)
        res_dash = client.get("/correlation/")
        self.assertEqual(res_dash.status_code, 200)

        res_camp = client.get("/correlation/api/campaigns")
        self.assertEqual(res_camp.status_code, 200)

        res_search = client.post("/correlation/api/search", json={"query": "10.0.0.1"})
        self.assertEqual(res_search.status_code, 403)

    def test_authenticated_dashboard(self):
        client = self.get_auth_client(self.analyst_user_id)
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

    # 4. Incident Entity Resolution & Propagation Tests
    def test_correlate_incident_public_id(self):
        """Test resolving incident by human-readable string ID (e.g. INC-369043) without integer cast errors."""
        with self.app.app_context():
            inc = Incident.query.filter_by(incident_id="INC-369043").first()
            if not inc:
                inc = Incident(
                    incident_id="INC-369043",
                    title="Unauthorized Access Incident INC-369043",
                    description="Investigation of unauthorized access attempt",
                    severity="high",
                    priority="high",
                    status="in_progress",
                    affected_host="10.10.20.50",
                    affected_asset="Core-DB-01",
                )
                db.session.add(inc)
                db.session.commit()

            corr = correlate_entity("incident", "INC-369043")
            self.assertIsNotNone(corr)
            self.assertEqual(corr["entity"]["type"], "incident")
            self.assertEqual(corr["entity"]["id"], "INC-369043")
            self.assertEqual(corr["counts"]["incidents"], 1)
            self.assertEqual(corr["entity"]["resolved_ip"], inc.affected_host or inc.affected_asset)

            # Also verify via API endpoint
            client = self.get_auth_client()
            res = client.get("/correlation/api/entity/incident/INC-369043")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["correlation"]["counts"]["incidents"], 1)

    def test_correlate_incident_numeric_id(self):
        """Test resolving incident by internal integer primary key (as int and as numeric str)."""
        with self.app.app_context():
            inc = Incident.query.filter_by(incident_id="INC-NUM-101").first()
            if not inc:
                inc = Incident(
                    incident_id="INC-NUM-101",
                    title="Malware Infection INC-NUM-101",
                    description="Malware outbreak investigation",
                    severity="critical",
                    priority="critical",
                    status="new",
                    affected_host="10.10.20.60",
                )
                db.session.add(inc)
                db.session.commit()

            # Test integer
            corr_int = correlate_entity("incident", inc.id)
            self.assertIsNotNone(corr_int)
            self.assertEqual(corr_int["counts"]["incidents"], 1)
            self.assertEqual(corr_int["details"]["incidents"][0]["id"], inc.id)

            # Test numeric string
            corr_str = correlate_entity("incident", str(inc.id))
            self.assertIsNotNone(corr_str)
            self.assertEqual(corr_str["counts"]["incidents"], 1)
            self.assertEqual(corr_str["details"]["incidents"][0]["id"], inc.id)

    def test_correlate_incident_nonexistent(self):
        """Test correlating a nonexistent incident ID gracefully returns zero matches without errors."""
        with self.app.app_context():
            corr = correlate_entity("incident", "INC-NONEXISTENT-999")
            self.assertIsNotNone(corr)
            self.assertEqual(corr["counts"]["incidents"], 0)
            self.assertEqual(corr["details"]["incidents"], [])
            self.assertIsNone(corr["entity"]["resolved_ip"])
            self.assertIsNone(corr["details"]["asset"])
            self.assertEqual(corr["risk"]["level"], "CLEAN")

            corr_num = correlate_entity("incident", 999999999)
            self.assertIsNotNone(corr_num)
            self.assertEqual(corr_num["counts"]["incidents"], 0)

    def test_correlate_incident_propagates_affected_host_and_asset(self):
        """Test that resolved incident correctly propagates affected_host / affected_asset to resolve matching Asset and related telemetry."""
        with self.app.app_context():
            asset_ip = "10.10.30.70"
            asset_name = "Finance-Server-01"

            asset = Asset.query.filter_by(ip_address=asset_ip).first()
            if not asset:
                asset = Asset(
                    name=asset_name,
                    ip_address=asset_ip,
                    asset_type="Server",
                    criticality="CRITICAL",
                    status="Active",
                )
                db.session.add(asset)
                db.session.commit()

            inc = Incident.query.filter_by(incident_id="INC-PROP-202").first()
            if not inc:
                inc = Incident(
                    incident_id="INC-PROP-202",
                    title="Finance Data Exfiltration Investigation",
                    description="Investigating finance server traffic",
                    severity="high",
                    priority="high",
                    status="investigating",
                    affected_host=asset_ip,
                    affected_asset=asset_name,
                )
                db.session.add(inc)
                db.session.commit()

            alert = Alert.query.filter_by(affected_host=asset_ip).first()
            if not alert:
                alert = Alert(
                    title="Anomalous Outbound Transfer",
                    severity="HIGH",
                    status="new",
                    affected_host=asset_ip,
                    affected_asset=asset_name,
                )
                db.session.add(alert)
                db.session.commit()

            corr = correlate_entity("incident", "INC-PROP-202")
            self.assertIsNotNone(corr)
            # Incident resolved
            self.assertEqual(corr["counts"]["incidents"], 1)
            # Asset resolved via affected_host
            self.assertIsNotNone(corr["details"]["asset"])
            self.assertEqual(corr["details"]["asset"]["ip_address"], asset_ip)
            self.assertEqual(corr["details"]["asset"]["name"], asset_name)
            # Telemetry linked via target_ip
            self.assertGreaterEqual(corr["counts"]["alerts"], 1)
            # Graph contains nodes for incident, asset, and alert
            graph_types = [n["type"] for n in corr["graph"]["nodes"]]
            self.assertIn("incident", graph_types)
            self.assertIn("asset", graph_types)

    # 5. Alert Entity Resolution & Cross-Module Linking
    def test_correlate_alert_public_id(self):
        """Test resolving alert by public string ID ALT-679563."""
        with self.app.app_context():
            corr = correlate_entity("alert", "ALT-679563")
            self.assertIsNotNone(corr)
            self.assertEqual(corr["entity"]["type"], "alert")
            self.assertEqual(corr["entity"]["id"], "ALT-679563")
            self.assertGreaterEqual(corr["counts"]["alerts"], 1)
            # ALT-679563 links to INC-369043
            inc_ids = [i.get("incident_id") for i in corr["details"]["incidents"]]
            self.assertIn("INC-369043", inc_ids)

    def test_correlate_alert_numeric_id(self):
        """Test resolving alert by integer ID."""
        with self.app.app_context():
            alt = Alert.query.first()
            if alt:
                corr = correlate_entity("alert", alt.id)
                self.assertIsNotNone(corr)
                self.assertGreaterEqual(corr["counts"]["alerts"], 1)
                self.assertEqual(corr["details"]["alerts"][0]["id"], alt.id)

    # 6. Asset Resolution (Numeric ID, Asset ID, Name, IP)
    def test_correlate_asset_resolvers(self):
        """Test resolving asset by numeric id, string asset_id, hostname, and ip."""
        with self.app.app_context():
            asset = Asset.query.filter_by(ip_address="192.168.139.254").first()
            if not asset:
                asset = Asset(
                    name="Security-Sensor-01",
                    hostname="sensor.corp.local",
                    ip_address="192.168.139.254",
                    asset_type="Sensor",
                    criticality="HIGH",
                    operating_system="Linux",
                )
                db.session.add(asset)
                db.session.commit()

            # By numeric ID
            c1 = correlate_entity("asset", asset.id)
            self.assertIsNotNone(c1["details"]["asset"])
            self.assertEqual(c1["details"]["asset"]["id"], asset.id)

            # By asset_id (e.g. AST-XXXX)
            c2 = correlate_entity("asset", asset.asset_id)
            self.assertIsNotNone(c2["details"]["asset"])
            self.assertEqual(c2["details"]["asset"]["name"], asset.name)

            # By name
            c3 = correlate_entity("asset", asset.name)
            self.assertIsNotNone(c3["details"]["asset"])

            # By IP
            c4 = correlate_entity("ip", asset.ip_address)
            self.assertIsNotNone(c4["details"]["asset"])

    # 7. CVE and Threat Intel IOC Resolution
    def test_correlate_cve_entity(self):
        """Test correlating CVE identifiers."""
        with self.app.app_context():
            cve_id = "CVE-2024-TEST-99"
            vf = VulnerabilityFinding.query.filter_by(cve=cve_id).first()
            if not vf:
                scan = Scan.query.first()
                if not scan:
                    scan = Scan(name="Test Scan", targets_json='["10.0.0.50"]')
                    db.session.add(scan)
                    db.session.commit()
                vf = VulnerabilityFinding(
                    scan_id=scan.id,
                    cve=cve_id,
                    title="Test Remote Code Execution",
                    severity="critical",
                    cvss_score=9.8,
                    host="10.0.0.50",
                )
                db.session.add(vf)
                db.session.commit()

            corr = correlate_entity("cve", cve_id)
            self.assertGreaterEqual(corr["counts"]["vulnerabilities"], 1)
            self.assertEqual(corr["details"]["vulnerabilities"][0]["cve_id"], cve_id)
            self.assertEqual(corr["entity"]["resolved_ip"], "10.0.0.50")

    def test_correlate_ioc_entity(self):
        """Test correlating threat intelligence IOCs."""
        with self.app.app_context():
            ioc_val = "bad-malware-domain.evil"
            ioc = IOC.query.filter_by(value=ioc_val).first()
            if not ioc:
                ioc = IOC(
                    ioc_id="IOC-TEST-DOMAIN",
                    value=ioc_val,
                    type="domain",
                    threat_level="high",
                    status="active",
                )
                db.session.add(ioc)
                db.session.commit()

            corr = correlate_entity("ioc", ioc_val)
            self.assertGreaterEqual(corr["counts"]["threat_intel"], 1)
            self.assertEqual(corr["details"]["threat_intel"][0]["ioc_value"], ioc_val)

    # 8. Diagnostic Event Exclusion & Safety
    def test_diagnostic_ids_events_strictly_excluded(self):
        """Ensure SID 2200074 and TCPv4 invalid checksum are never in correlation or graph."""
        with self.app.app_context():
            # INC-369043 has 21 diagnostic events in real database
            corr = correlate_entity("incident", "INC-369043")
            for ev in corr["details"]["ids_events"]:
                self.assertNotEqual(ev.get("signature_id"), 2200074)
                self.assertNotIn("invalid checksum", (ev.get("signature") or "").lower())

            # Verify in graph
            for node in corr["graph"]["nodes"]:
                if node.get("type") == "ids":
                    self.assertNotEqual(node.get("metadata", {}).get("sid"), 2200074)

    # 9. API Validation & SQL Injection Safety
    def test_api_search_validation(self):
        client = self.get_auth_client()
        # Empty query
        res = client.post("/correlation/api/search", json={"query": ""})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["status"], "error")

        # Whitespace query
        res2 = client.post("/correlation/api/search", json={"query": "   "})
        self.assertEqual(res2.status_code, 400)

    def test_special_characters_sql_safety(self):
        """Ensure special characters and injection vectors do not cause 500 errors."""
        client = self.get_auth_client()
        payloads = [
            "' OR '1'='1",
            "../../etc/passwd",
            "%",
            "<script>alert(1)</script>",
            "127.0.0.1; DROP TABLE assets;--",
        ]
        for p in payloads:
            res = client.post("/correlation/api/search", json={"query": p, "entity_type": "auto"})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["status"], "success")

    # 10. Risk Score Levels and Graph Structure
    def test_risk_score_levels_and_bounds(self):
        # LOW (1-34)
        med_alert = Alert(title="Minor Notice", severity="MEDIUM", status="new")
        r_low = calculate_risk_score(alerts=[med_alert])
        self.assertEqual(r_low["level"], "LOW")
        self.assertGreater(r_low["score"], 0)
        self.assertLess(r_low["score"], 35)

        # CRITICAL and bounded at 100
        crit_alerts = [Alert(title=f"Crit {i}", severity="CRITICAL", status="new") for i in range(10)]
        vulns = [VulnerabilityFinding(cve=f"CVE-2026-000{i}", severity="CRITICAL") for i in range(5)]
        incs = [Incident(status="in_progress")]
        r_crit = calculate_risk_score(alerts=crit_alerts, vulns=vulns, incidents=incs)
        self.assertEqual(r_crit["score"], 100)
        self.assertEqual(r_crit["level"], "CRITICAL")

    def test_graph_deduplication_and_structure(self):
        """Graph links and nodes must not have duplicate keys."""
        with self.app.app_context():
            corr = correlate_entity("incident", "INC-369043")
            graph = corr["graph"]
            node_ids = [n["id"] for n in graph["nodes"]]
            self.assertEqual(len(node_ids), len(set(node_ids)))

            link_keys = [(l["source"], l["target"], l["relationship"]) for l in graph["links"]]
            self.assertEqual(len(link_keys), len(set(link_keys)))


if __name__ == "__main__":
    unittest.main()
