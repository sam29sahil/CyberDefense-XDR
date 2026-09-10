"""
Unit and Integration Tests for SIEM & Log Explorer Module
CyberDefense XDR
Uses standard library unittest.
"""

import unittest
import json
from datetime import datetime

from app import create_app
from app.extensions import db
from app.users.models import User
from app.siem.models import SiemEvent, SiemSavedSearch
from app.threatintel.models import IOC
from app.detection.models import DetectionRule, DetectionEvent
from app.alerts.models import Alert
from app.siem.services import (
    generate_log_id,
    generate_search_id,
    ingest_event,
    ingest_events_bulk,
    get_logs,
    get_filter_options,
    get_log_by_event_id,
    get_siem_dashboard_stats,
    get_saved_searches,
    create_saved_search,
    toggle_pin_saved_search,
    delete_saved_search,
    seed_initial_siem_data,
)


class SiemTestCase(unittest.TestCase):
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
            # Seed initial dataset if needed
            seed_initial_siem_data()

            # Ensure test users exist for authenticated flows
            users_to_create = [
                ("siem_analyst", "siem_analyst@cyberdefense.local", "SOC_ANALYST"),
                ("siem_other_analyst", "siem_other@cyberdefense.local", "SOC_ANALYST"),
                ("siem_unprivileged", "siem_unprivileged@cyberdefense.local", "GUEST"),
                ("siem_admin", "siem_admin@cyberdefense.local", "ADMIN"),
                ("siem_viewer", "siem_viewer@cyberdefense.local", "VIEWER"),
            ]
            for uname, email, role in users_to_create:
                user = User.query.filter_by(username=uname).first()
                if not user:
                    user = User(
                        username=uname,
                        email=email,
                        first_name="Siem",
                        last_name=role.capitalize(),
                        role=role,
                        is_active=True,
                    )
                    user.set_password("SecurePassword123!")
                    db.session.add(user)
                    db.session.commit()
                setattr(cls, f"{uname}_id", user.id)
            cls.test_user_id = cls.siem_analyst_id

    def get_auth_client(self, user_id=None):
        uid = user_id or self.test_user_id
        from flask import has_app_context, g
        if has_app_context() and hasattr(g, "_login_user"):
            delattr(g, "_login_user")
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["_user_id"] = str(uid)
            sess["_fresh"] = True
        return client

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.client = self.get_auth_client(self.test_user_id)

    def tearDown(self):
        from flask import has_app_context, g
        if has_app_context() and hasattr(g, "_login_user"):
            delattr(g, "_login_user")
        self.ctx.pop()

    # ========================================================
    # MODEL TESTS
    # ========================================================

    def test_siem_event_model(self):
        """Test SiemEvent model creation, properties, and to_dict serialization."""
        event_id = generate_log_id()
        event = SiemEvent(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            severity="high",
            category="Network",
            source="Firewall-Unit-Test",
            host="TEST-HOST-01",
            message="Unit test firewall drop",
            raw_log="raw log message here",
            fields_json=json.dumps({"src_ip": "10.0.0.1", "action": "drop"}),
            tags_json=json.dumps(["test", "firewall"]),
        )
        db.session.add(event)
        db.session.commit()

        queried = SiemEvent.query.filter_by(event_id=event_id).first()
        self.assertIsNotNone(queried)
        self.assertEqual(queried.severity, "high")
        self.assertEqual(queried.fields.get("src_ip"), "10.0.0.1")
        self.assertIn("firewall", queried.tags)

        d = queried.to_dict()
        self.assertEqual(d["id"], event_id)
        self.assertEqual(d["sev"], "high")
        self.assertEqual(d["host"], "TEST-HOST-01")

        # Cleanup
        db.session.delete(queried)
        db.session.commit()

    def test_siem_saved_search_model(self):
        """Test SiemSavedSearch model and to_dict serialization."""
        search_id = generate_search_id()
        search = SiemSavedSearch(
            search_id=search_id,
            name="Test Search Model",
            query="sev:high",
            owner="Siem Analyst",
            scope="Team",
            pinned=True,
            alerting=True,
            hits=15,
        )
        db.session.add(search)
        db.session.commit()

        queried = SiemSavedSearch.query.filter_by(search_id=search_id).first()
        self.assertIsNotNone(queried)
        self.assertTrue(queried.pinned)
        self.assertEqual(queried.hits, 15)

        d = queried.to_dict()
        self.assertEqual(d["id"], search_id)
        self.assertEqual(d["query"], "sev:high")
        self.assertTrue(d["pinned"])

        # Cleanup
        db.session.delete(queried)
        db.session.commit()

    # ========================================================
    # INGESTION & CORRELATION TESTS
    # ========================================================

    def test_ingest_event_service(self):
        """Test basic log ingestion service."""
        payload = {
            "source": "CrowdStrike EDR",
            "host": "ENDPOINT-SRV-99",
            "severity": "medium",
            "category": "Endpoint",
            "message": "Powershell invoked with unusual arguments",
            "raw": "EDR: powershell.exe -enc ...",
            "fields": {"process": "powershell.exe", "pid": 1234},
            "tags": ["powershell", "endpoint"],
        }
        event = ingest_event(payload)
        self.assertIsNotNone(event)
        self.assertTrue(event.event_id.startswith("LOG-"))
        self.assertEqual(event.severity, "medium")
        self.assertEqual(event.fields.get("pid"), 1234)

        # Cleanup
        db.session.delete(event)
        db.session.commit()

    def test_threat_intel_correlation_on_ingest(self):
        """Test that log ingestion correlates with IOC database and adds threat tags."""
        test_ip = "198.51.100.77"
        # Ensure test IOC exists
        ioc = IOC.query.filter_by(value=test_ip).first()
        if not ioc:
            ioc = IOC(
                ioc_id=f"IOC-TEST-{secrets_id()}",
                value=test_ip,
                type="ip",
                threat_level="high",
                confidence="High",
                source="Unit Test TI Feed",
            )
            db.session.add(ioc)
            db.session.commit()

        # Ingest log containing this IP in fields
        payload = {
            "source": "PAN-OS Firewall",
            "host": "FW-PERIMETER-01",
            "severity": "low",
            "category": "Network",
            "message": f"Connection established to {test_ip}",
            "fields": {"src_ip": "10.0.1.5", "dst_ip": test_ip},
            "tags": ["network"],
        }
        event = ingest_event(payload)
        self.assertIsNotNone(event.ioc_match_id)
        self.assertEqual(event.ioc_match_id, ioc.ioc_id)
        self.assertIn("threat-intel-match", event.tags)
        # Verify severity was elevated due to high threat IOC
        self.assertEqual(event.severity, "high")

        # Cleanup
        db.session.delete(event)
        db.session.delete(ioc)
        db.session.commit()

    def test_detection_engine_trigger_on_critical_ingest(self):
        """Test that ingesting a critical security event triggers Detection Engine and Alert Center."""
        # Ensure a detection rule exists
        rule = DetectionRule.query.filter_by(status="active").first()
        if not rule:
            rule = DetectionRule(
                rule_id="DET-TEST-001",
                name="Test Detection Rule",
                category="Malware",
                severity="critical",
                status="active",
            )
            db.session.add(rule)
            db.session.commit()

        payload = {
            "source": "CrowdStrike EDR",
            "host": "DC-PROD-01",
            "severity": "critical",
            "category": "Endpoint",
            "message": "Mimikatz LSASS memory dump detected",
            "fields": {"process": "mimikatz.exe", "target": "lsass.exe"},
            "tags": ["credential-access", "mitre:t1003"],
        }
        event = ingest_event(payload)
        self.assertIsNotNone(event.detection_event_id)

        # Verify detection event was created
        det_evt = DetectionEvent.query.get(event.detection_event_id)
        self.assertIsNotNone(det_evt)
        self.assertEqual(det_evt.severity, "critical")
        self.assertEqual(det_evt.host, "DC-PROD-01")

        # Cleanup
        db.session.delete(event)
        Alert.query.filter_by(detection_event_id=det_evt.id).delete()
        db.session.delete(det_evt)
        db.session.commit()

    def test_bulk_ingest(self):
        """Test bulk log ingestion."""
        events_data = [
            {"source": "AWS CloudTrail", "host": "CLOUD-01", "severity": "info", "message": "Bulk event 1"},
            {"source": "AWS CloudTrail", "host": "CLOUD-02", "severity": "low", "message": "Bulk event 2"},
        ]
        created = ingest_events_bulk(events_data)
        self.assertEqual(len(created), 2)
        for ev in created:
            db.session.delete(ev)
        db.session.commit()

    # ========================================================
    # QUERY & STATS TESTS
    # ========================================================

    def test_get_logs_filtering(self):
        """Test log search and filtering capabilities."""
        result = get_logs(filters={"sev": "critical"}, page=1, per_page=5)
        self.assertIn("items", result)
        self.assertIn("total", result)
        for item in result["items"]:
            self.assertEqual(item["sev"], "critical")

    def test_get_filter_options(self):
        """Test that distinct filter options are returned."""
        options = get_filter_options()
        self.assertIn("sources", options)
        self.assertIn("hosts", options)
        self.assertIn("categories", options)
        self.assertIn("tags", options)
        self.assertTrue(len(options["sources"]) > 0)

    def test_get_log_by_event_id(self):
        """Test fetching a specific log event and related events."""
        first_event = SiemEvent.query.first()
        self.assertIsNotNone(first_event)

        log_data = get_log_by_event_id(first_event.event_id)
        self.assertIsNotNone(log_data)
        self.assertEqual(log_data["id"], first_event.event_id)
        self.assertIn("related", log_data)

    def test_siem_dashboard_stats(self):
        """Test SIEM dashboard KPI and aggregation computation."""
        stats = get_siem_dashboard_stats()
        self.assertIn("kpi", stats)
        self.assertIn("chart", stats)
        self.assertIn("severity_counts", stats)
        self.assertIn("top_sources", stats)
        self.assertIn("noisiest_hosts", stats)
        self.assertIn("stream", stats)

        self.assertGreater(stats["kpi"]["total_events_24h"], 0)
        self.assertGreater(stats["kpi"]["active_sources_count"], 0)
        self.assertEqual(len(stats["chart"]["labels"]), 24)

    # ========================================================
    # SAVED SEARCHES TESTS
    # ========================================================

    def test_saved_searches_crud(self):
        """Test create, pin, and delete of saved searches."""
        new_search = create_saved_search({
            "name": "Unit Test Saved Search",
            "query": "category:Network AND sev:high",
            "description": "Searches high severity network events",
            "scope": "Team",
            "pinned": False,
        })
        self.assertIsNotNone(new_search)
        search_id = new_search.search_id

        # Toggle pin
        toggled = toggle_pin_saved_search(search_id)
        self.assertTrue(toggled.pinned)

        # Retrieve
        searches = get_saved_searches(search="Unit Test Saved Search")
        self.assertTrue(any(s["id"] == search_id for s in searches))

        # Delete
        success = delete_saved_search(search_id)
        self.assertTrue(success)
        self.assertIsNone(SiemSavedSearch.query.filter_by(search_id=search_id).first())

    # ========================================================
    # HTTP PAGE ROUTES TESTS
    # ========================================================

    def test_siem_page_routes(self):
        """Test that all SIEM HTML page routes render successfully."""
        routes = [
            "/siem/",
            "/siem/dashboard",
            "/siem/log-explorer",
            "/siem/log-details",
            "/siem/saved-searches",
        ]
        for route in routes:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Route {route} failed with status {res.status_code}")

    def test_log_explorer_sidebar_redirect(self):
        """Test that /log-explorer/ redirects to /siem/log-explorer for shell.js compatibility."""
        res = self.client.get("/log-explorer/")
        self.assertIn(res.status_code, (301, 302))
        self.assertTrue("/siem/log-explorer" in res.headers.get("Location", ""))

    # ========================================================
    # REST API ENDPOINTS TESTS
    # ========================================================

    def test_api_dashboard(self):
        """Test GET /siem/api/dashboard endpoint."""
        res = self.client.get("/siem/api/dashboard")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("kpi", data.get("data", {}))

    def test_api_logs(self):
        """Test GET /siem/api/logs with pagination and filters."""
        res = self.client.get("/siem/api/logs?page=1&limit=5")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("data", data)
        self.assertIn("pagination", data)
        self.assertLessEqual(len(data["data"]), 5)

    def test_api_log_detail(self):
        """Test GET /siem/api/logs/<event_id>."""
        first_event = SiemEvent.query.first()
        self.assertIsNotNone(first_event)

        res = self.client.get(f"/siem/api/logs/{first_event.event_id}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["data"]["id"], first_event.event_id)

    def test_api_ingest_event(self):
        """Test POST /siem/api/events log ingestion API."""
        payload = {
            "source": "Suricata IDS",
            "host": "DMZ-GW-01",
            "severity": "medium",
            "category": "Network",
            "message": "Nmap port sweep detected across subnet",
            "fields": {"src_ip": "198.18.0.50", "protocol": "TCP"},
            "tags": ["scan", "network"],
        }
        res = self.client.post(
            "/siem/api/events",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        created_id = data["data"]["id"]

        # Cleanup
        ev = SiemEvent.query.filter_by(event_id=created_id).first()
        if ev:
            db.session.delete(ev)
            db.session.commit()

    def test_api_saved_searches(self):
        """Test Saved Searches REST APIs."""
        # 1. Create
        create_res = self.client.post(
            "/siem/api/saved-searches",
            data=json.dumps({
                "name": "API Test Saved Search",
                "query": "message:test",
                "scope": "Team",
            }),
            content_type="application/json",
        )
        self.assertEqual(create_res.status_code, 201)
        search_id = create_res.get_json()["data"]["id"]

        # 2. Pin toggle
        pin_res = self.client.post(f"/siem/api/saved-searches/{search_id}/pin")
        self.assertEqual(pin_res.status_code, 200)
        self.assertTrue(pin_res.get_json().get("pinned"))

        # 3. List
        list_res = self.client.get("/siem/api/saved-searches")
        self.assertEqual(list_res.status_code, 200)
        searches = list_res.get_json().get("data", [])
        self.assertTrue(any(s["id"] == search_id for s in searches))

        # 4. Delete
        del_res = self.client.delete(f"/siem/api/saved-searches/{search_id}")
        self.assertEqual(del_res.status_code, 200)

    # ========================================================
    # RBAC & PERMISSION BOUNDARY TESTS
    # ========================================================

    def test_anonymous_access_rejected(self):
        """Anonymous requests to all SIEM page and API routes must be rejected."""
        from flask import g
        if hasattr(g, "_login_user"):
            delattr(g, "_login_user")
        anon_client = self.app.test_client()

        # HTML Pages redirect to login (302)
        pages = [
            "/siem/",
            "/siem/dashboard",
            "/siem/log-explorer",
            "/siem/log-details",
            "/siem/saved-searches",
        ]
        for route in pages:
            res = anon_client.get(route)
            self.assertEqual(res.status_code, 302, f"Expected 302 for anonymous GET {route}, got {res.status_code}")

        # REST APIs return 401 Unauthorized or redirect 302 to login
        api_gets = [
            "/siem/api/dashboard",
            "/siem/api/logs",
            "/siem/api/logs/filter-options",
            "/siem/api/saved-searches",
        ]
        for route in api_gets:
            res = anon_client.get(route)
            self.assertIn(res.status_code, [302, 401], f"Expected 302 or 401 for anonymous GET {route}, got {res.status_code}")

        # API Mutations return 401 Unauthorized or redirect 302
        res_post_event = anon_client.post("/siem/api/events", json={"source": "test"})
        self.assertIn(res_post_event.status_code, [302, 401])

        res_post_search = anon_client.post("/siem/api/saved-searches", json={"name": "test", "query": "*"})
        self.assertIn(res_post_search.status_code, [302, 401])

    def test_siem_view_authorized(self):
        """User with siem.view can access all SIEM page and read API routes."""
        client = self.get_auth_client(self.siem_viewer_id)

        pages = [
            "/siem/",
            "/siem/dashboard",
            "/siem/log-explorer",
            "/siem/log-details",
            "/siem/saved-searches",
        ]
        for route in pages:
            res = client.get(route)
            self.assertEqual(res.status_code, 200, f"Expected 200 for viewer GET {route}, got {res.status_code}")

        api_gets = [
            "/siem/api/dashboard",
            "/siem/api/logs",
            "/siem/api/logs/filter-options",
            "/siem/api/saved-searches",
        ]
        for route in api_gets:
            res = client.get(route)
            self.assertEqual(res.status_code, 200, f"Expected 200 for viewer GET {route}, got {res.status_code}")

    def test_siem_unprivileged_forbidden(self):
        """User without siem.view (e.g. GUEST) receives 403 Forbidden across all SIEM routes."""
        client = self.get_auth_client(self.siem_unprivileged_id)

        # Pages abort 403
        res = client.get("/siem/")
        self.assertEqual(res.status_code, 403)

        res = client.get("/siem/dashboard")
        self.assertEqual(res.status_code, 403)

        res = client.get("/siem/log-explorer")
        self.assertEqual(res.status_code, 403)

        # APIs return 403
        res = client.get("/siem/api/dashboard")
        self.assertEqual(res.status_code, 403)

        res = client.get("/siem/api/logs")
        self.assertEqual(res.status_code, 403)

        res = client.get("/siem/api/saved-searches")
        self.assertEqual(res.status_code, 403)

        res = client.post("/siem/api/events", json={"source": "test"})
        self.assertEqual(res.status_code, 403)

        res = client.post("/siem/api/saved-searches", json={"name": "test", "query": "*"})
        self.assertEqual(res.status_code, 403)

    def test_siem_event_ingestion_auth_boundaries(self):
        """Test authentication & authorization boundaries for SIEM event ingestion."""
        payload = {
            "source": "Boundary Test Source",
            "host": "TEST-HOST-RBAC",
            "severity": "low",
            "category": "System",
            "message": "Auth boundary test event",
            "fields": {"src_ip": "10.0.0.99"},
        }

        # 1. Anonymous -> 302 or 401
        from flask import g
        if hasattr(g, "_login_user"):
            delattr(g, "_login_user")
        anon_client = self.app.test_client()
        res_anon = anon_client.post("/siem/api/events", json=payload)
        self.assertIn(res_anon.status_code, [302, 401])

        # 2. Unprivileged -> 403
        unpriv_client = self.get_auth_client(self.siem_unprivileged_id)
        res_unpriv = unpriv_client.post("/siem/api/events", json=payload)
        self.assertEqual(res_unpriv.status_code, 403)

        # 3. Authorized -> 201
        auth_client = self.get_auth_client(self.siem_analyst_id)
        res_auth = auth_client.post("/siem/api/events", json=payload)
        self.assertEqual(res_auth.status_code, 201)
        event_id = res_auth.get_json()["data"]["id"]

        # Cleanup
        ev = SiemEvent.query.filter_by(event_id=event_id).first()
        if ev:
            db.session.delete(ev)
            db.session.commit()

    def test_saved_searches_ownership_protection(self):
        """Users can mutate their own saved searches; other analysts receive 403; admins can mutate any."""
        analyst_client = self.get_auth_client(self.siem_analyst_id)
        other_client = self.get_auth_client(self.siem_other_analyst_id)
        admin_client = self.get_auth_client(self.siem_admin_id)

        # 1. Analyst creates search (owned by siem_analyst)
        create_res = analyst_client.post(
            "/siem/api/saved-searches",
            json={
                "name": "Ownership Test Search",
                "query": "category:Network",
                "scope": "Team",
            },
        )
        self.assertEqual(create_res.status_code, 201)
        search_id = create_res.get_json()["data"]["id"]

        try:
            # 2. Other analyst tries to toggle pin -> 403 Forbidden
            pin_other = other_client.post(f"/siem/api/saved-searches/{search_id}/pin")
            self.assertEqual(pin_other.status_code, 403)

            # 3. Other analyst tries to delete -> 403 Forbidden
            del_other = other_client.delete(f"/siem/api/saved-searches/{search_id}")
            self.assertEqual(del_other.status_code, 403)

            # 4. Admin tries to toggle pin -> 200 OK
            pin_admin = admin_client.post(f"/siem/api/saved-searches/{search_id}/pin")
            self.assertEqual(pin_admin.status_code, 200)

            # 5. Owner deletes own search -> 200 OK
            del_owner = analyst_client.delete(f"/siem/api/saved-searches/{search_id}")
            self.assertEqual(del_owner.status_code, 200)
            self.assertIsNone(SiemSavedSearch.query.filter_by(search_id=search_id).first())
        finally:
            # Fallback cleanup
            remaining = SiemSavedSearch.query.filter_by(search_id=search_id).first()
            if remaining:
                db.session.delete(remaining)
                db.session.commit()


def secrets_id():
    import secrets
    return secrets.randbelow(90000) + 10000


if __name__ == "__main__":
    unittest.main()
