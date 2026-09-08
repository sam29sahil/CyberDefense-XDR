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

        with cls.app.app_context():
            user = User.query.filter_by(username="ids_analyst").first()
            if not user:
                user = User(
                    username="ids_analyst",
                    email="ids_analyst@cyberdefense.local",
                    first_name="IDS",
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
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.test_user_id
            sess["_fresh"] = True

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


if __name__ == "__main__":
    unittest.main()
