"""
Unit and Integration Tests for Asset Management Module
CyberDefense XDR
Standard library unittest.
"""

import unittest
import json
from datetime import datetime

from app import create_app
from app.extensions import db
from app.users.models import User
from app.assets.models import Asset
from app.alerts.models import Alert
from app.scanner.models import Scan, VulnerabilityFinding
from app.assets.services import (
    validate_ip_address,
    validate_mac_address,
    create_asset,
    get_asset,
    update_asset,
    delete_asset,
    list_assets,
    update_last_seen,
    calculate_asset_risk,
    refresh_asset_security_summary,
    get_asset_security_details,
    get_asset_inventory_stats,
    trigger_asset_scan,
)


class AssetManagementTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            # Ensure test user exists
            user = User.query.filter_by(username="test_asset_analyst").first()
            if not user:
                user = User(
                    username="test_asset_analyst",
                    email="asset_analyst@cyberdefense.local",
                    first_name="Asset",
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
        with self.app.app_context():
            # Clean up any leftover test assets
            test_patterns = [
                "DC-PRIMARY-TEST", "UNIQUE-HOST-TEST", "TEST-UPDATE-HOST",
                "SEARCH-PROD-DB", "SEARCH-DEV-WEB", "RISK-TARGET-HOST",
                "STATS-VERIFY-HOST", "API-TEST-HOST", "NO-TARGET-HOST-TEST"
            ]
            for pat in test_patterns:
                assets = Asset.query.filter(Asset.name.ilike(f"%{pat}%")).all()
                for a in assets:
                    db.session.delete(a)

            # Clean up test findings, alerts, and scans
            findings = VulnerabilityFinding.query.filter_by(host="192.0.2.100").all()
            for f in findings:
                db.session.delete(f)
            alerts = Alert.query.filter(db.or_(Alert.affected_host == "192.0.2.100", Alert.title == "Simulated Lateral Movement Attempt")).all()
            for a in alerts:
                db.session.delete(a)
            scans = Scan.query.filter(Scan.name == "Test Posture Scan").all()
            for s in scans:
                db.session.delete(s)

            db.session.commit()

    def get_auth_client(self):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.test_user_id)
            sess["_fresh"] = True
        return self.client

    # ============================================================
    # VALIDATION TESTS
    # ============================================================

    def test_01_ip_and_mac_validation(self):
        # Valid IPv4
        self.assertIsNotNone(validate_ip_address("192.168.1.100"))
        self.assertIsNotNone(validate_ip_address("10.0.0.1"))
        self.assertIsNotNone(validate_ip_address("127.0.0.1"))

        # Valid IPv6
        self.assertIsNotNone(validate_ip_address("::1"))
        self.assertIsNotNone(validate_ip_address("2001:db8::1"))

        # Invalid IP
        self.assertIsNone(validate_ip_address("256.256.256.256"))
        self.assertIsNone(validate_ip_address("not_an_ip"))
        self.assertIsNone(validate_ip_address(""))

        # Valid MAC
        self.assertIsNotNone(validate_mac_address("00:1A:2B:3C:4D:5E"))
        self.assertIsNotNone(validate_mac_address("00-1a-2b-3c-4d-5e"))

        # Invalid MAC
        self.assertIsNone(validate_mac_address("00:1A:2B:3C:4D"))
        self.assertIsNone(validate_mac_address("invalid_mac"))

    # ============================================================
    # MODEL & SERVICE CRUD TESTS
    # ============================================================

    def test_02_create_asset_service(self):
        with self.app.app_context():
            asset = create_asset({
                "name": "DC-PRIMARY-TEST",
                "hostname": "dc-primary.corp.local",
                "ip_address": "10.0.0.10",
                "asset_type": "Domain Controller",
                "environment": "Production",
                "criticality": "critical",
                "owner": "sysadmin@corp.local",
                "owner_team": "Infrastructure",
                "operating_system": "Windows Server 2022",
                "tags": ["identity", "active-directory"],
            })

            self.assertIsNotNone(asset.id)
            self.assertTrue(asset.asset_id.startswith("AST-"))
            self.assertEqual(asset.name, "DC-PRIMARY-TEST")
            self.assertEqual(asset.ip_address, "10.0.0.10")
            self.assertEqual(asset.criticality, "critical")
            self.assertEqual(asset.status, "online")

            # Verify serialization
            d = asset.to_dict()
            self.assertEqual(d["asset_id"], asset.asset_id)
            self.assertEqual(d["name"], "DC-PRIMARY-TEST")
            self.assertEqual(d["ip_address"], "10.0.0.10")
            self.assertIn("identity", d["tags"])

            # Clean up
            delete_asset(asset.id)

    def test_03_create_asset_validations(self):
        with self.app.app_context():
            # Missing name
            with self.assertRaises(ValueError):
                create_asset({"name": ""})

            # Invalid IP
            with self.assertRaises(ValueError):
                create_asset({"name": "Test Asset", "ip_address": "999.999.999.999"})

            # Invalid MAC
            with self.assertRaises(ValueError):
                create_asset({"name": "Test Asset", "mac_address": "bad-mac"})

            # Duplicate name check
            a1 = create_asset({"name": "UNIQUE-HOST-TEST"})
            try:
                with self.assertRaises(ValueError):
                    create_asset({"name": "UNIQUE-HOST-TEST"})
            finally:
                delete_asset(a1.id)

    def test_04_get_update_delete_asset(self):
        with self.app.app_context():
            asset = create_asset({
                "name": "TEST-UPDATE-HOST",
                "ip_address": "10.10.10.50",
                "environment": "Staging",
                "criticality": "medium"
            })
            asset_id_str = asset.asset_id

            # Retrieve by id & asset_id
            fetched = get_asset(asset.id)
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched.name, "TEST-UPDATE-HOST")

            fetched_by_str = get_asset(asset_id_str)
            self.assertIsNotNone(fetched_by_str)
            self.assertEqual(fetched_by_str.id, asset.id)

            # Update
            updated = update_asset(asset_id_str, {
                "environment": "Production",
                "criticality": "high",
                "owner": "secops",
                "tags": ["updated", "tier1"]
            })
            self.assertEqual(updated.environment, "Production")
            self.assertEqual(updated.criticality, "high")
            self.assertEqual(updated.owner, "secops")
            self.assertIn("tier1", updated.tags)

            # Delete
            del_result = delete_asset(asset_id_str)
            self.assertTrue(del_result)
            self.assertIsNone(get_asset(asset_id_str))

    def test_05_list_and_search_assets(self):
        with self.app.app_context():
            a1 = create_asset({"name": "SEARCH-PROD-DB", "asset_type": "Database", "environment": "Production", "criticality": "critical"})
            a2 = create_asset({"name": "SEARCH-DEV-WEB", "asset_type": "Server", "environment": "Development", "criticality": "low"})

            try:
                # Search by query
                res_search = list_assets(search_query="SEARCH-PROD")
                self.assertGreaterEqual(res_search["total"], 1)
                names = [item["name"] for item in res_search["assets"]]
                self.assertIn("SEARCH-PROD-DB", names)
                self.assertNotIn("SEARCH-DEV-WEB", names)

                # Filter by environment
                res_env = list_assets(environment="Development")
                names_env = [item["name"] for item in res_env["assets"]]
                self.assertIn("SEARCH-DEV-WEB", names_env)
                self.assertNotIn("SEARCH-PROD-DB", names_env)

                # Filter by asset_type
                res_type = list_assets(asset_type="Database")
                names_type = [item["name"] for item in res_type["assets"]]
                self.assertIn("SEARCH-PROD-DB", names_type)
            finally:
                delete_asset(a1.id)
                delete_asset(a2.id)

    # ============================================================
    # RISK CALCULATION & CORRELATION TESTS
    # ============================================================

    def test_06_dynamic_risk_calculation(self):
        with self.app.app_context():
            # Create isolated test asset
            asset = create_asset({
                "name": "RISK-TARGET-HOST",
                "ip_address": "192.0.2.100",
                "criticality": "high"
            })

            try:
                # Baseline risk with 0 findings/alerts
                score, severity = calculate_asset_risk(asset)
                self.assertEqual(score, 0)
                self.assertEqual(severity, "low")
                self.assertEqual(asset.open_vulnerabilities_count, 0)
                self.assertEqual(asset.open_alerts_count, 0)

                # Create a parent scan record
                scan = Scan(
                    name="Test Posture Scan",
                    scan_type="Quick Scan",
                    status="completed",
                    targets=["192.0.2.100"]
                )
                db.session.add(scan)
                db.session.commit()

                # Add a simulated vulnerability finding matching this host
                finding = VulnerabilityFinding(
                    scan_id=scan.id,
                    tool="nmap",
                    severity="critical",
                    cvss_score=9.8,
                    title="Simulated Remote Code Execution",
                    host="192.0.2.100",
                    port=445,
                    protocol="tcp",
                    cve="CVE-2024-99999",
                    status="open"
                )
                db.session.add(finding)

                # Add a simulated alert matching this host
                from app.alerts.services import create_alert
                alert = create_alert({
                    "title": "Simulated Lateral Movement Attempt",
                    "severity": "high",
                    "status": "new",
                    "category": "Threat",
                    "source": "Network IDS",
                    "affected_host": "192.0.2.100",
                })

                # Recompute dynamic risk: (25 critical vuln + 12 high alert) * 1.10 = 40.7 -> 41 (medium severity)
                score_updated, sev_updated = calculate_asset_risk(asset)
                self.assertEqual(score_updated, 41)
                self.assertEqual(asset.open_vulnerabilities_count, 1)
                self.assertEqual(asset.open_alerts_count, 1)
                self.assertEqual(sev_updated, "medium")

                # Clean up findings, alerts, and scan
                db.session.delete(finding)
                db.session.delete(alert)
                db.session.delete(scan)
                db.session.commit()
            except Exception:
                db.session.rollback()
                raise
            finally:
                delete_asset(asset.id)

    def test_07_inventory_statistics(self):
        with self.app.app_context():
            stats_initial = get_asset_inventory_stats()
            self.assertIn("total", stats_initial)
            self.assertIn("online", stats_initial)
            self.assertIn("by_type", stats_initial)
            self.assertIn("by_environment", stats_initial)

            # Create an asset and assert stats reflect the change
            asset = create_asset({
                "name": "STATS-VERIFY-HOST",
                "asset_type": "Firewall",
                "environment": "DMZ",
                "status": "online"
            })
            try:
                stats_after = get_asset_inventory_stats()
                self.assertEqual(stats_after["total"], stats_initial["total"] + 1)
                self.assertEqual(stats_after["online"], stats_initial["online"] + 1)
                self.assertEqual(stats_after["by_environment"].get("DMZ", 0), stats_initial["by_environment"].get("DMZ", 0) + 1)
            finally:
                delete_asset(asset.id)

    # ============================================================
    # REST API & AUTHENTICATION TESTS
    # ============================================================

    def test_08_authentication_required(self):
        # Unauthenticated calls should be rejected or redirected
        res_page = self.client.get("/assets/")
        self.assertIn(res_page.status_code, [302, 401])

        res_api = self.client.get("/assets/api")
        self.assertIn(res_api.status_code, [302, 401])

        res_stats = self.client.get("/assets/api/stats")
        self.assertIn(res_stats.status_code, [302, 401])

    def test_09_api_crud_endpoints(self):
        auth_client = self.get_auth_client()

        # 1. Create asset via POST /assets/api
        payload = {
            "name": "API-TEST-HOST",
            "hostname": "api-host.corp.local",
            "ip_address": "10.50.0.25",
            "asset_type": "Server",
            "environment": "Production",
            "criticality": "high",
            "owner": "devops@corp.local",
            "tags": "api, automation"
        }
        res_create = auth_client.post("/assets/api", json=payload)
        self.assertEqual(res_create.status_code, 201)
        data = res_create.get_json()
        self.assertIn("asset", data)
        created_id = data["asset"]["asset_id"]

        try:
            # 2. Get asset via GET /assets/api/<asset_id>
            res_get = auth_client.get(f"/assets/api/{created_id}")
            self.assertEqual(res_get.status_code, 200)
            asset_data = res_get.get_json()["asset"]
            self.assertEqual(asset_data["name"], "API-TEST-HOST")
            self.assertEqual(asset_data["ip_address"], "10.50.0.25")

            # 3. Update asset via PUT /assets/api/<asset_id>
            res_put = auth_client.put(f"/assets/api/{created_id}", json={
                "criticality": "critical",
                "status": "offline"
            })
            self.assertEqual(res_put.status_code, 200)
            updated_data = res_put.get_json()["asset"]
            self.assertEqual(updated_data["criticality"], "critical")
            self.assertEqual(updated_data["status"], "offline")

            # 4. Correlated sub-endpoints
            res_vulns = auth_client.get(f"/assets/api/{created_id}/vulnerabilities")
            self.assertEqual(res_vulns.status_code, 200)
            self.assertIn("vulnerabilities", res_vulns.get_json())

            res_alerts = auth_client.get(f"/assets/api/{created_id}/alerts")
            self.assertEqual(res_alerts.status_code, 200)
            self.assertIn("alerts", res_alerts.get_json())

            res_network = auth_client.get(f"/assets/api/{created_id}/network")
            self.assertEqual(res_network.status_code, 200)
            self.assertIn("discovered_ports", res_network.get_json())

            res_activity = auth_client.get(f"/assets/api/{created_id}/activity")
            self.assertEqual(res_activity.status_code, 200)
            self.assertIn("incidents", res_activity.get_json())

            # 5. Inventory stats API
            res_stats = auth_client.get("/assets/api/stats")
            self.assertEqual(res_stats.status_code, 200)
            self.assertIn("total", res_stats.get_json())

            # 6. Delete asset via DELETE /assets/api/<asset_id>
            res_del = auth_client.delete(f"/assets/api/{created_id}")
            self.assertEqual(res_del.status_code, 200)

            # Verify deleted
            res_verify = auth_client.get(f"/assets/api/{created_id}")
            self.assertEqual(res_verify.status_code, 404)
        finally:
            with self.app.app_context():
                existing = Asset.query.filter_by(name="API-TEST-HOST").first()
                if existing:
                    db.session.delete(existing)
                    db.session.commit()

    def test_10_scan_trigger_validation(self):
        auth_client = self.get_auth_client()

        with self.app.app_context():
            # Asset with no target (neither IP nor hostname)
            asset = create_asset({
                "name": "NO-TARGET-HOST-TEST",
            })
            target_id = asset.asset_id

        try:
            # Triggering scan without target IP or hostname should return 400
            res_scan = auth_client.post(f"/assets/api/{target_id}/scan")
            self.assertEqual(res_scan.status_code, 400)
            data = res_scan.get_json()
            self.assertIn("error", data)
        finally:
            with self.app.app_context():
                delete_asset(target_id)


if __name__ == "__main__":
    unittest.main()
