"""
Unit and Integration Tests for Network IDS (Suricata) Module
CyberDefense XDR
Uses standard library unittest.
"""

import unittest
import json
import uuid
from datetime import datetime

from app import create_app
from app.extensions import db
from app.users.models import User
from app.alerts.models import Alert
from app.incidents.models import Incident
from app.ids.models import NetworkIDSEvent, IDSSensor
from app.ids.services import (
    validate_interface,
    parse_eve_line,
    compute_event_uuid,
    ingest_eve_event,
    get_ids_dashboard_stats,
    get_ids_events,
    get_ids_event_by_id,
    escalate_event_to_incident,
    get_sensor_status,
)


class NetworkIDSTestCase(unittest.TestCase):
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
            users_to_create = [
                ("ids_analyst", "ids_analyst@cyberdefense.local", "SOC_ANALYST"),
                ("ids_viewer", "ids_viewer@cyberdefense.local", "VIEWER"),
                ("ids_unprivileged", "ids_unprivileged@cyberdefense.local", "GUEST"),
                ("ids_sec_analyst", "ids_sec_analyst@cyberdefense.local", "SECURITY_ANALYST"),
            ]
            for uname, email, role in users_to_create:
                user = User.query.filter_by(username=uname).first()
                if not user:
                    user = User(
                        username=uname,
                        email=email,
                        first_name="IDS",
                        last_name=role.capitalize(),
                        role=role,
                        is_active=True,
                    )
                    user.set_password("SecurePassword123!")
                    db.session.add(user)
                    db.session.commit()
                setattr(cls, f"{uname}_id", user.id)
            cls.test_user_id = cls.ids_analyst_id

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
        self.client = self.get_auth_client(self.test_user_id)

    # -------------------------------------------------------------------------
    # 1. Interface Validation Tests
    # -------------------------------------------------------------------------
    def test_validate_interface(self):
        """Test interface name validation and injection prevention."""
        # Valid loopback or common linux interface
        valid, clean_if = validate_interface("lo")
        self.assertTrue(valid)
        self.assertEqual(clean_if, "lo")

        # Command injection payloads must be rejected
        valid, msg = validate_interface("eth0; rm -rf /")
        self.assertFalse(valid)
        self.assertIn("illegal characters", msg)

        valid, msg = validate_interface("eth0 && cat /etc/passwd")
        self.assertFalse(valid)
        self.assertIn("illegal characters", msg)

        valid, msg = validate_interface("eth0 | grep root")
        self.assertFalse(valid)
        self.assertIn("illegal characters", msg)

        valid, msg = validate_interface("`whoami`")
        self.assertFalse(valid)
        self.assertIn("illegal characters", msg)

        valid, msg = validate_interface("$(whoami)")
        self.assertFalse(valid)
        self.assertIn("illegal characters", msg)

        # Non-existent interface
        valid, msg = validate_interface("nonexistent_iface_999")
        self.assertFalse(valid)
        self.assertIn("not found on system", msg)

    # -------------------------------------------------------------------------
    # 2. EVE JSON Parsing Tests
    # -------------------------------------------------------------------------
    def test_parse_eve_alert_line(self):
        """Test parsing of Suricata EVE alert log lines."""
        raw_alert = {
            "timestamp": "2026-09-08T11:00:00.123456+0000",
            "flow_id": 123456789012345,
            "event_type": "alert",
            "src_ip": "192.168.139.100",
            "src_port": 45678,
            "dest_ip": "192.168.139.148",
            "dest_port": 80,
            "proto": "TCP",
            "app_proto": "http",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2001234,
                "rev": 1,
                "signature": "ET SCAN Suspicious Inbound Network Probe",
                "category": "Attempted Information Leak",
                "severity": 1,  # Suricata 1 = high/critical
            },
        }
        line = json.dumps(raw_alert)
        parsed = parse_eve_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["event_type"], "alert")
        self.assertEqual(parsed["src_ip"], "192.168.139.100")
        self.assertEqual(parsed["dest_ip"], "192.168.139.148")
        self.assertEqual(parsed["dest_port"], 80)
        self.assertEqual(parsed["protocol"], "TCP")
        self.assertEqual(parsed["signature_id"], 2001234)
        self.assertEqual(parsed["signature"], "ET SCAN Suspicious Inbound Network Probe")
        self.assertEqual(parsed["category"], "Attempted Information Leak")
        self.assertEqual(parsed["severity"], "critical")
        self.assertEqual(parsed["action"], "allowed")

    def test_parse_eve_flow_and_dns_lines(self):
        """Test parsing of Suricata EVE flow and DNS records."""
        flow_line = json.dumps({
            "timestamp": "2026-09-08T11:01:00.000000+0000",
            "flow_id": 987654321,
            "event_type": "flow",
            "src_ip": "192.168.139.148",
            "src_port": 54321,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "app_proto": "dns",
        })
        parsed_flow = parse_eve_line(flow_line)
        self.assertIsNotNone(parsed_flow)
        self.assertEqual(parsed_flow["event_type"], "flow")
        self.assertEqual(parsed_flow["dest_ip"], "8.8.8.8")
        self.assertIsNone(parsed_flow["signature_id"])

        dns_line = json.dumps({
            "timestamp": "2026-09-08T11:01:01.000000+0000",
            "event_type": "dns",
            "src_ip": "192.168.139.148",
            "dest_ip": "8.8.8.8",
            "proto": "UDP",
            "dns": {"type": "query", "rrname": "c2.malicious-domain.com", "rrtype": "A"},
        })
        parsed_dns = parse_eve_line(dns_line)
        self.assertIsNotNone(parsed_dns)
        self.assertEqual(parsed_dns["event_type"], "dns")
        self.assertEqual(parsed_dns["signature"], "DNS Query: c2.malicious-domain.com (A)")

    def test_parse_malformed_eve_line(self):
        """Ensure corrupted or non-JSON strings are safely ignored."""
        self.assertIsNone(parse_eve_line(""))
        self.assertIsNone(parse_eve_line("   \n"))
        self.assertIsNone(parse_eve_line("NOT_JSON_LOG_STRING"))
        self.assertIsNone(parse_eve_line("{truncated_json: true"))

    def test_compute_event_uuid_deterministic(self):
        """Test SHA-256 deduplication UUID computation."""
        raw_event = {
            "timestamp": "2026-09-08T11:05:00.000000",
            "event_type": "alert",
            "flow_id": 112233,
            "src_ip": "10.0.0.5",
            "src_port": 1234,
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "signature_id": 2000001,
        }
        uuid1 = compute_event_uuid(raw_event)
        uuid2 = compute_event_uuid(raw_event)
        self.assertEqual(uuid1, uuid2)
        self.assertEqual(len(uuid1), 64)

    # -------------------------------------------------------------------------
    # 3. Model & Ingestion Tests
    # -------------------------------------------------------------------------
    def test_model_and_ingestion(self):
        """Test ingesting an alert event into DB, Alert Center, and SIEM."""
        unique_sig = f"TEST ATTACK SIG {uuid.uuid4().hex[:8]}"
        raw_alert = {
            "timestamp": datetime.utcnow().isoformat() + "+0000",
            "flow_id": 999111222,
            "event_type": "alert",
            "src_ip": "192.168.1.50",
            "src_port": 49152,
            "dest_ip": "192.168.1.10",
            "dest_port": 445,
            "proto": "TCP",
            "app_proto": "smb",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2009999,
                "rev": 1,
                "signature": unique_sig,
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
        }

        with self.app.app_context():
            event = ingest_eve_event(raw_alert, sensor_name="test-sensor", interface="eth0")
            self.assertIsNotNone(event)
            self.assertEqual(event.signature, unique_sig)
            self.assertEqual(event.severity, "critical")
            self.assertEqual(event.sid, 2009999)

            # Test to_dict helper
            d = event.to_dict()
            self.assertEqual(d["signature"], unique_sig)
            self.assertEqual(d["src_ip"], "192.168.1.50")

            # Check Alert Center Alert was generated for this Suricata alert
            alert = Alert.query.filter_by(source="Suricata IDS", title=f"[Suricata IDS] {unique_sig}").first()
            self.assertIsNotNone(alert)
            self.assertEqual(alert.severity, "critical")
            self.assertEqual(alert.status, "new")

            # Deduplication: Re-ingest exact same event, must return existing without duplicate row
            dup_event = ingest_eve_event(raw_alert, sensor_name="test-sensor", interface="eth0")
            self.assertEqual(dup_event.id, event.id)

    def test_non_alert_does_not_create_alert_center_entry(self):
        """Verify flow/telemetry records do NOT flood Alert Center."""
        flow_event = {
            "timestamp": datetime.utcnow().isoformat() + "+0000",
            "flow_id": 888777666,
            "event_type": "flow",
            "src_ip": "192.168.1.50",
            "src_port": 50000,
            "dest_ip": "1.1.1.1",
            "dest_port": 53,
            "proto": "UDP",
        }
        with self.app.app_context():
            count_before = Alert.query.count()
            event = ingest_eve_event(flow_event)
            self.assertIsNotNone(event)
            count_after = Alert.query.count()
            self.assertEqual(count_before, count_after)

    def test_sid_2200074_checksum_diagnostic_classification(self):
        """
        Verify SID 2200074 / 'SURICATA TCPv4 invalid checksum':
        A. Event is persisted in PostgreSQL network_ids_events.
        B. Event is classified as 'diagnostic' and is_diagnostic is True.
        C. Event does NOT create an Alert Center alert.
        D. Event does NOT create an Incident, and manual escalation is rejected.
        E. Event remains queryable in Network IDS Events explorer.
        """
        raw_checksum_event = {
            "timestamp": datetime.utcnow().isoformat() + "+0000",
            "flow_id": 1122334455,
            "event_type": "alert",
            "src_ip": "203.0.113.88",
            "src_port": 54320,
            "dest_ip": "198.51.100.99",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2200074,
                "rev": 1,
                "signature": "SURICATA TCPv4 invalid checksum",
                "category": "Generic Protocol Command Decode",
                "severity": 3,
            },
        }

        with self.app.app_context():
            # Record counts before ingestion
            alert_count_before = Alert.query.count()
            incident_count_before = Incident.query.count()

            test_start = datetime.utcnow()

            # A. Persisted in PostgreSQL
            event = ingest_eve_event(raw_checksum_event, interface="eth0")
            self.assertIsNotNone(event)
            self.assertEqual(event.signature_id, 2200074)
            self.assertEqual(event.signature, "SURICATA TCPv4 invalid checksum")

            # B. Classified as diagnostic
            self.assertTrue(event.is_diagnostic)
            self.assertEqual(event.classification, "diagnostic")
            d = event.to_dict()
            self.assertEqual(d["classification"], "diagnostic")
            self.assertTrue(d["isDiagnostic"])

            # C. Does NOT create an Alert Center alert
            alert_count_after = Alert.query.count()
            self.assertEqual(alert_count_before, alert_count_after)
            new_alerts = Alert.query.filter(Alert.created_at >= test_start).all()
            self.assertEqual(len(new_alerts), 0)

            # D. Does NOT create an Incident, and escalation attempt is safely rejected
            incident_count_after = Incident.query.count()
            self.assertEqual(incident_count_before, incident_count_after)
            with self.assertRaises(ValueError) as ctx:
                escalate_event_to_incident(event.id)
            self.assertIn("diagnostic", str(ctx.exception).lower())

            # E. Event remains queryable and visible in Network IDS Events
            fetched = get_ids_event_by_id(event.id)
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched.classification, "diagnostic")
            res = get_ids_events(filters={"classification": "diagnostic", "src_ip": "203.0.113.88"}, per_page=50)
            diag_ids = [e["id"] for e in res["events"]]
            self.assertIn(event.id, diag_ids)

    # -------------------------------------------------------------------------
    # 4. Telemetry & Query Service Tests
    # -------------------------------------------------------------------------
    def test_dashboard_stats_and_queries(self):
        """Test aggregation service functions."""
        with self.app.app_context():
            stats = get_ids_dashboard_stats()
            self.assertIn("kpis", stats)
            self.assertIn("sensor", stats)
            self.assertIn("protocol_distribution", stats)
            self.assertIn("top_signatures", stats)
            self.assertIn("recent_alerts", stats)
            self.assertIn("recent_events", stats)

            res = get_ids_events(page=1, per_page=10)
            events = res["events"]
            pagination = res["pagination"]
            self.assertIsInstance(events, list)
            self.assertIn("total", pagination)

    def test_escalate_to_incident(self):
        """Test SOC analyst incident escalation from an IDS event."""
        unique_sig = f"TEST RANSOMWARE TRAFFIC {uuid.uuid4().hex[:6]}"
        raw_alert = {
            "timestamp": datetime.utcnow().isoformat() + "+0000",
            "event_type": "alert",
            "src_ip": "10.10.10.55",
            "dest_ip": "10.10.10.1",
            "proto": "TCP",
            "alert": {
                "signature_id": 2008888,
                "signature": unique_sig,
                "category": "Trojan Activity",
                "severity": 1,
            },
        }
        with self.app.app_context():
            event = ingest_eve_event(raw_alert)
            incident = escalate_event_to_incident(event.id, notes="Automated test escalation")
            self.assertIsNotNone(incident)
            self.assertIn(unique_sig, incident.title)

    # -------------------------------------------------------------------------
    # 5. HTTP Routes & API Tests
    # -------------------------------------------------------------------------
    def test_ids_pages_render(self):
        """Test Jinja template routes."""
        res = self.client.get("/network-ids/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Network IDS (Suricata)", res.data)

        res = self.client.get("/network-ids/dashboard")
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/network-ids/events")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Network IDS Events Explorer", res.data)

    def test_ids_api_endpoints(self):
        """Test JSON REST APIs."""
        # Dashboard API
        res = self.client.get("/network-ids/api/dashboard")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("kpis", data)

        # Events API
        res = self.client.get("/network-ids/api/events?per_page=5")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("events", data)

        # Sensor Status API
        res = self.client.get("/network-ids/api/sensor")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("sensor", data)

    # -------------------------------------------------------------------------
    # 6. RBAC & Authorization Boundary Tests
    # -------------------------------------------------------------------------
    def test_ids_anonymous_access_rejected(self):
        """Anonymous requests to all IDS page and API routes must be rejected."""
        anon_client = self.app.test_client()

        # HTML Pages redirect to login (302)
        pages = [
            "/network-ids/",
            "/network-ids/dashboard",
            "/network-ids/events",
        ]
        for route in pages:
            res = anon_client.get(route)
            self.assertIn(res.status_code, [302, 401], f"Expected 302 or 401 for anonymous GET {route}, got {res.status_code}")

        # REST APIs return 401 or redirect 302
        api_gets = [
            "/network-ids/api/dashboard",
            "/network-ids/api/events",
            "/network-ids/api/sensor",
            "/network-ids/api/logs/status",
        ]
        for route in api_gets:
            res = anon_client.get(route)
            self.assertIn(res.status_code, [302, 401], f"Expected 302 or 401 for anonymous GET {route}, got {res.status_code}")

        # API Mutations return 401 or redirect 302
        mutations = [
            ("POST", "/network-ids/api/sensor/start"),
            ("POST", "/network-ids/api/sensor/stop"),
            ("POST", "/network-ids/api/sensor/restart"),
            ("POST", "/network-ids/api/rules/update"),
            ("POST", "/network-ids/api/logs/rotate"),
            ("POST", "/network-ids/api/events/fake-event/create-incident"),
        ]
        for method, route in mutations:
            res = anon_client.post(route, json={})
            self.assertIn(res.status_code, [302, 401], f"Expected 302 or 401 for anonymous {method} {route}, got {res.status_code}")

    def test_ids_view_authorized(self):
        """User with ids.view (e.g. VIEWER) can access all IDS read pages and read APIs."""
        client = self.get_auth_client(self.ids_viewer_id)

        pages = [
            "/network-ids/",
            "/network-ids/dashboard",
            "/network-ids/events",
        ]
        for route in pages:
            res = client.get(route)
            self.assertEqual(res.status_code, 200, f"Expected 200 for viewer GET {route}, got {res.status_code}")

        api_gets = [
            "/network-ids/api/dashboard",
            "/network-ids/api/events",
            "/network-ids/api/sensor",
            "/network-ids/api/logs/status",
        ]
        for route in api_gets:
            res = client.get(route)
            self.assertEqual(res.status_code, 200, f"Expected 200 for viewer GET {route}, got {res.status_code}")

    def test_ids_unprivileged_forbidden(self):
        """User without ids.view (e.g. GUEST) receives 403 Forbidden across all IDS routes."""
        client = self.get_auth_client(self.ids_unprivileged_id)

        # Pages abort 403
        res = client.get("/network-ids/")
        self.assertEqual(res.status_code, 403)

        res = client.get("/network-ids/dashboard")
        self.assertEqual(res.status_code, 403)

        res = client.get("/network-ids/events")
        self.assertEqual(res.status_code, 403)

        # APIs return 403
        res = client.get("/network-ids/api/dashboard")
        self.assertEqual(res.status_code, 403)

        res = client.get("/network-ids/api/events")
        self.assertEqual(res.status_code, 403)

        res = client.get("/network-ids/api/sensor")
        self.assertEqual(res.status_code, 403)

        res = client.get("/network-ids/api/logs/status")
        self.assertEqual(res.status_code, 403)

        res = client.post("/network-ids/api/sensor/start", json={})
        self.assertEqual(res.status_code, 403)

        res = client.post("/network-ids/api/rules/update", json={})
        self.assertEqual(res.status_code, 403)

        res = client.post("/network-ids/api/logs/rotate", json={})
        self.assertEqual(res.status_code, 403)

        res = client.post("/network-ids/api/events/fake-event/create-incident", json={})
        self.assertEqual(res.status_code, 403)

    def test_ids_control_permission_boundaries(self):
        """ids.control is required for sensor start, stop, and restart."""
        # Viewer lacks ids.control -> 403
        viewer_client = self.get_auth_client(self.ids_viewer_id)
        for ep in ["start", "stop", "restart"]:
            res = viewer_client.post(f"/network-ids/api/sensor/{ep}", json={})
            self.assertEqual(res.status_code, 403, f"Expected 403 for viewer POST /sensor/{ep}")

        # SOC Analyst has ids.control -> 200 (mock service layer to avoid real sensor processes)
        analyst_client = self.get_auth_client(self.ids_analyst_id)
        from unittest.mock import patch

        with patch("app.ids.services.start_sensor", return_value=(True, "Mock sensor started")):
            res = analyst_client.post("/network-ids/api/sensor/start", json={"interface": "lo"})
            self.assertEqual(res.status_code, 200)

        with patch("app.ids.services.stop_sensor", return_value=(True, "Mock sensor stopped")):
            res = analyst_client.post("/network-ids/api/sensor/stop", json={})
            self.assertEqual(res.status_code, 200)

        with patch("app.ids.services.restart_sensor", return_value=(True, "Mock sensor restarted")):
            res = analyst_client.post("/network-ids/api/sensor/restart", json={"interface": "lo"})
            self.assertEqual(res.status_code, 200)

    def test_ids_rules_modify_boundaries(self):
        """ids.rules.modify is required to trigger rule updates."""
        # Viewer lacks ids.rules.modify -> 403
        viewer_client = self.get_auth_client(self.ids_viewer_id)
        res = viewer_client.post("/network-ids/api/rules/update", json={})
        self.assertEqual(res.status_code, 403)

        # Analyst has ids.rules.modify -> 200 (mock service to avoid network update)
        analyst_client = self.get_auth_client(self.ids_analyst_id)
        from unittest.mock import patch
        with patch("app.ids.services.update_suricata_rules", return_value={"success": True, "message": "Mock rules updated"}):
            res = analyst_client.post("/network-ids/api/rules/update", json={})
            self.assertEqual(res.status_code, 200)

    def test_ids_incident_escalation_boundaries(self):
        """Incident creation requires both ids.view and incidents.create."""
        # Viewer has ids.view but lacks incidents.create -> 403
        viewer_client = self.get_auth_client(self.ids_viewer_id)
        res = viewer_client.post("/network-ids/api/events/EVT-TEST/create-incident", json={})
        self.assertEqual(res.status_code, 403)

        # Sec Analyst has ids.view and incidents.create -> authorized
        sec_client = self.get_auth_client(self.ids_sec_analyst_id)
        # Create a real test IDS event
        with self.app.app_context():
            test_evt = NetworkIDSEvent(
                event_uuid=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                event_type="alert",
                src_ip="10.0.0.1",
                dest_ip="10.0.0.2",
                severity=2,
                signature="Test Escalation Alert",
                category="Attempted Information Leak",
            )
            db.session.add(test_evt)
            db.session.commit()
            evt_id = test_evt.id

        try:
            res = sec_client.post(f"/network-ids/api/events/{evt_id}/create-incident", json={"notes": "RBAC test"})
            self.assertEqual(res.status_code, 201)
            inc_id = res.get_json()["incidentId"]
            # Cleanup created incident
            with self.app.app_context():
                inc = Incident.query.filter_by(incident_id=inc_id).first()
                if inc:
                    db.session.delete(inc)
                    db.session.commit()
        finally:
            with self.app.app_context():
                ev = db.session.get(NetworkIDSEvent, evt_id)
                if ev:
                    db.session.delete(ev)
                    db.session.commit()

    def test_ids_logs_rotate_boundaries(self):
        """ids.control is required for manual log rotation."""
        # Viewer lacks ids.control -> 403
        viewer_client = self.get_auth_client(self.ids_viewer_id)
        res = viewer_client.post("/network-ids/api/logs/rotate", json={})
        self.assertEqual(res.status_code, 403)

        # Sec Analyst lacks ids.control -> 403
        sec_client = self.get_auth_client(self.ids_sec_analyst_id)
        res_sec = sec_client.post("/network-ids/api/logs/rotate", json={})
        self.assertEqual(res_sec.status_code, 403)

        # SOC Analyst has ids.control -> 200 (mock rotate_ids_logs to avoid file rotation in unit tests)
        analyst_client = self.get_auth_client(self.ids_analyst_id)
        from unittest.mock import patch
        with patch("app.ids.services.rotate_ids_logs", return_value={"rotated": [], "skipped": ["fast.log"], "errors": []}):
            res_analyst = analyst_client.post("/network-ids/api/logs/rotate", json={})
            self.assertEqual(res_analyst.status_code, 200)


if __name__ == "__main__":
    unittest.main()
