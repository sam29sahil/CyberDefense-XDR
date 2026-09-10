"""
Unit and Integration Tests for Vulnerability Scanner Module
CyberDefense XDR
Multi-tool authorized scanner: Nmap, WhatWeb, Nikto, Nuclei, testssl
"""

import unittest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime

from app import create_app
from app.extensions import db
from app.users.models import User
from app.scanner.models import Scan, VulnerabilityFinding, ScanTarget
from app.scanner.services import (
    validate_target,
    normalize_and_validate_target,
    resolve_target_dns,
    get_available_tools,
    generate_finding_fingerprint,
    deduplicate_and_merge_findings,
    parse_nmap_xml,
    evaluate_findings_from_ports,
    run_whatweb_scan,
    run_nikto_scan,
    get_scans,
    get_scan_by_id,
    get_scan_findings,
    get_vulnerabilities,
    get_vulnerability_by_id,
    update_vulnerability_status,
    get_targets,
    create_target,
    delete_target,
    get_scanner_dashboard_stats,
    seed_initial_scanner_data,
    build_nmap_command,
)


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV 127.0.0.1" start="1725600000" version="7.94">
<host>
  <status state="up" reason="localhost-response"/>
  <address addr="127.0.0.1" addrtype="ipv4"/>
  <hostnames><hostname name="localhost" type="user"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="9.2p1" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="nginx" version="1.24.0" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="23">
      <state state="open" reason="syn-ack"/>
      <service name="telnet" product="Linux telnetd" version="1.0" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="5432">
      <state state="open" reason="syn-ack"/>
      <service name="postgresql" product="PostgreSQL Database" version="16.2" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="8080">
      <state state="closed" reason="conn-refused"/>
      <service name="http-proxy" method="table" conf="3"/>
    </port>
  </ports>
</host>
</nmaprun>
"""

SAMPLE_WHATWEB_JSON = [
    {
        "target": "http://127.0.0.1:5000",
        "http_status": 200,
        "plugins": {
            "HTTPServer": {"string": ["Werkzeug/3.0.1 Python/3.11"]},
            "Python": {"version": ["3.11"]},
            "X-Powered-By": {"string": ["Flask"]},
            "X-XSS-Protection": {"string": ["1; mode=block"]},
        }
    }
]


class ScannerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            seed_initial_scanner_data()

            # Ensure a test analyst exists for authenticated requests
            user = User.query.filter_by(username="scanner_analyst").first()
            if not user:
                user = User(
                    username="scanner_analyst",
                    email="scanner_analyst@cyberdefense.local",
                    first_name="Scanner",
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
            sess["_user_id"] = str(self.test_user_id)
            sess["_fresh"] = True

    # ----------------------------------------------------------------------
    # 1. Target Validation & Target Types (All 7 Types)
    # ----------------------------------------------------------------------
    def test_target_validation_all_seven_types(self):
        valid_targets = [
            # 1. IPv4
            ("127.0.0.1", "ipv4"),
            ("192.168.1.50", "ipv4"),
            ("10.0.0.1", "ipv4"),
            ("93.184.216.34", "ipv4"),
            # 2. IPv6
            ("::1", "ipv6"),
            ("fe80::1", "ipv6"),
            ("2001:db8::1", "ipv6"),
            # 3. Hostname
            ("localhost", "hostname"),
            ("internal-db.local", "hostname"),
            ("workstation.lan", "hostname"),
            # 4. Domain
            ("example.com", "domain"),
            ("scanme.nmap.org", "domain"),
            ("sub.domain.org", "domain"),
            # 5. CIDR (/24 max)
            ("192.168.1.0/24", "cidr"),
            ("10.10.10.0/24", "cidr"),
            ("172.16.1.0/28", "cidr"),
            # 6. HTTP URL
            ("http://127.0.0.1:5000", "url"),
            ("http://example.com/api/v1", "url"),
            # 7. HTTPS URL
            ("https://secure.example.com", "url"),
            ("https://127.0.0.1:8443/app", "url"),
        ]
        with self.app.app_context():
            for target_str, expected_type in valid_targets:
                is_valid, t_info, msg = normalize_and_validate_target(target_str)
                self.assertTrue(is_valid, f"Expected '{target_str}' to be valid, got: {msg}")
                self.assertEqual(t_info["target_type"], expected_type)
                self.assertTrue(bool(t_info["normalized"]))

    def test_target_validation_rejection_and_injection_defense(self):
        dangerous_or_invalid = [
            "127.0.0.1; rm -rf /",
            "127.0.0.1 && cat /etc/passwd",
            "127.0.0.1 | whoami",
            "`touch pwned`",
            "$(whoami)",
            "10.0.0.0/16",       # CIDR prefix /16 exceeds max /24
            "192.168.0.0/8",     # CIDR prefix /8 exceeds max /24
            "ftp://files.example.com",  # non HTTP/HTTPS scheme
            "javascript:alert(1)",
            "not an ip or domain @@",
            "",
        ]
        with self.app.app_context():
            for target in dangerous_or_invalid:
                is_valid, t_info, msg = normalize_and_validate_target(target)
                self.assertFalse(is_valid, f"Expected '{target}' to be rejected, but it passed: {msg}")

    # ----------------------------------------------------------------------
    # 2. Tool Capability Detection & DNS Resolution
    # ----------------------------------------------------------------------
    def test_get_available_tools(self):
        tools = get_available_tools()
        self.assertIsInstance(tools, dict)
        self.assertIn("nmap", tools)
        self.assertIn("whatweb", tools)
        self.assertIn("nikto", tools)
        self.assertIn("nuclei", tools)
        self.assertIn("testssl", tools)

        # On Kali Linux, nmap should be available
        self.assertTrue(tools["nmap"]["available"])
        self.assertIsNotNone(tools["nmap"]["path"])

    def test_dns_resolution(self):
        # localhost should resolve reliably to 127.0.0.1
        dns_data = resolve_target_dns("localhost")
        self.assertIsInstance(dns_data, dict)
        self.assertIn("ipv4", dns_data)
        self.assertIn("127.0.0.1", dns_data["ipv4"])

    # ----------------------------------------------------------------------
    # 3. Finding Deduplication & Merging
    # ----------------------------------------------------------------------
    def test_fingerprint_generation_and_deduplication(self):
        f1 = VulnerabilityFinding(
            host="127.0.0.1",
            port=80,
            service="http",
            cve="CVE-2023-44487",
            title="HTTP/2 Rapid Reset",
            severity="high",
            cvss_score=7.5,
            tool="nmap",
        )
        fp1 = generate_finding_fingerprint("127.0.0.1", 80, "http", "CVE-2023-44487")
        self.assertTrue(len(fp1) == 64)  # SHA-256 hex length

        f2 = VulnerabilityFinding(
            host="127.0.0.1",
            port=80,
            service="http",
            cve="CVE-2023-44487",
            title="HTTP/2 Rapid Reset Attack",
            severity="critical",
            cvss_score=8.5,
            tool="nuclei",
        )

        merged = deduplicate_and_merge_findings([f1, f2])
        # Two findings with the same host, port, and CVE should deduplicate into one finding
        self.assertEqual(len(merged), 1)
        # Should merge with highest CVSS
        self.assertEqual(merged[0].get("cvss_score"), 8.5)
        self.assertEqual(merged[0].get("severity"), "critical")

    # ----------------------------------------------------------------------
    # 4. Scan Profiles & Nmap Command Building
    # ----------------------------------------------------------------------
    def test_build_nmap_command_profiles(self):
        for profile in ["QUICK", "STANDARD", "WEB", "DEEP"]:
            cmd = build_nmap_command("127.0.0.1", profile=profile)
            self.assertIn("-sT", cmd)
            self.assertIn("-oX", cmd)
            self.assertIn("127.0.0.1", cmd)
            # Must remain safe and unprivileged
            self.assertNotIn("-sS", cmd)

        quick_cmd = build_nmap_command("127.0.0.1", profile="QUICK")
        self.assertIn("--top-ports", quick_cmd)

        web_cmd = build_nmap_command("127.0.0.1", profile="WEB")
        self.assertIn("-p", web_cmd)

    # ----------------------------------------------------------------------
    # 5. XML Parsing & Vulnerability Evaluation
    # ----------------------------------------------------------------------
    def test_parse_nmap_xml(self):
        ports = parse_nmap_xml(SAMPLE_NMAP_XML)
        self.assertEqual(len(ports), 4)

        port_numbers = [p["port"] for p in ports]
        self.assertIn(22, port_numbers)
        self.assertIn(80, port_numbers)
        self.assertIn(23, port_numbers)
        self.assertIn(5432, port_numbers)
        self.assertNotIn(8080, port_numbers)

    def test_evaluate_findings_from_ports(self):
        with self.app.app_context():
            scan = Scan(
                name="Evaluation Test Scan",
                scan_type="Full Scan",
                profile="DEEP",
                status="running",
                targets=["127.0.0.1"],
                options={"cve_matching": True},
            )
            db.session.add(scan)
            db.session.commit()

            ports = parse_nmap_xml(SAMPLE_NMAP_XML)
            findings = evaluate_findings_from_ports(scan, ports, "127.0.0.1")

            self.assertTrue(len(findings) >= 2)
            telnet_findings = [f for f in findings if f.port == 23]
            self.assertEqual(len(telnet_findings), 1)
            self.assertEqual(telnet_findings[0].severity, "high")
            self.assertEqual(telnet_findings[0].cvss_score, 7.5)

            pg_findings = [f for f in findings if f.port == 5432]
            self.assertEqual(len(pg_findings), 1)
            self.assertEqual(pg_findings[0].severity, "medium")

            self.assertTrue(scan.risk_score > 0)

            # Cleanup
            for f in findings:
                db.session.delete(f)
            db.session.delete(scan)
            db.session.commit()

    # ----------------------------------------------------------------------
    # 6. Model CRUD & Target Management
    # ----------------------------------------------------------------------
    def test_scan_crud_and_to_dict(self):
        with self.app.app_context():
            scan = Scan(
                name="Unit Test Local Sweep",
                scan_type="Quick Scan",
                profile="QUICK",
                status="completed",
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                duration_min=1,
                initiated_by="Unit Tester",
                targets=["127.0.0.1"],
                tools_used=["nmap", "whatweb"],
                options={"safe_checks": True},
                findings_summary={"critical": 1, "high": 0, "medium": 0, "low": 0},
                risk_score=75,
            )
            db.session.add(scan)
            db.session.commit()

            fetched = get_scan_by_id(scan.scan_id)
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched["name"], "Unit Test Local Sweep")
            self.assertEqual(fetched["profile"], "QUICK")
            self.assertIn("whatweb", fetched["toolsUsed"])

            db.session.delete(scan)
            db.session.commit()

    def test_target_creation_and_deletion(self):
        with self.app.app_context():
            target = create_target(
                {
                    "name": "Test Web URL Target",
                    "target_input": "http://127.0.0.1:5000",
                    "type": "URL",
                    "is_authorized": True,
                },
                owner="DevSecOps",
            )
            self.assertIsNotNone(target)
            self.assertEqual(target.name, "Test Web URL Target")
            self.assertEqual(target.target_type, "url")
            self.assertTrue(target.is_authorized)

            # Delete target
            deleted = delete_target(target.target_id)
            self.assertTrue(deleted)

    def test_vulnerability_lifecycle_and_status(self):
        with self.app.app_context():
            scan = Scan(
                name="Lifecycle Test Scan",
                scan_type="Standard Scan",
                targets=["127.0.0.1"],
            )
            db.session.add(scan)
            db.session.commit()

            finding = VulnerabilityFinding(
                scan_id=scan.id,
                host="127.0.0.1",
                cve="CVE-2026-TEST",
                title="Test Vulnerability Finding",
                severity="critical",
                cvss_score=9.5,
                tool="nmap",
                cwe="CWE-200",
                confidence="high",
                status="open",
            )
            db.session.add(finding)
            db.session.commit()

            updated = update_vulnerability_status(finding.finding_id, "patched")
            self.assertIsNotNone(updated)
            self.assertEqual(updated["status"], "patched")

            db.session.delete(finding)
            db.session.delete(scan)
            db.session.commit()

    # ----------------------------------------------------------------------
    # 7. REST APIs
    # ----------------------------------------------------------------------
    def test_api_tools_endpoint(self):
        resp = self.client.get("/scanner/api/tools")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data.get("success"))
        self.assertIn("tools", data)
        self.assertIn("nmap", data["tools"])

    def test_api_scan_findings_endpoint(self):
        with self.app.app_context():
            scan = Scan(
                name="Findings API Test Scan",
                scan_type="Standard Scan",
                targets=["127.0.0.1"],
            )
            db.session.add(scan)
            db.session.commit()

            finding = VulnerabilityFinding(
                scan_id=scan.id,
                host="127.0.0.1",
                cve="CVE-2026-API-TEST",
                title="API Test Finding",
                severity="high",
                cvss_score=7.8,
                tool="whatweb",
                status="open",
            )
            db.session.add(finding)
            db.session.commit()

            resp = self.client.get(f"/scanner/api/scans/{scan.scan_id}/findings")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.data)
            self.assertTrue(data.get("success"))
            self.assertTrue(len(data.get("findings", [])) >= 1)

            # Cleanup
            db.session.delete(finding)
            db.session.delete(scan)
            db.session.commit()

    def test_api_create_scan_profiles_and_validation(self):
        # Valid authorized loopback scan
        resp = self.client.post(
            "/scanner/api/scans",
            json={
                "name": "Quick Loopback Audit",
                "type": "Quick Scan",
                "profile": "QUICK",
                "targets": ["127.0.0.1"],
                "options": {"safe_checks": True},
                "schedule_mode": "scheduled",  # don't run execution thread during test
            },
        )
        self.assertEqual(resp.status_code, 201)
        data = json.loads(resp.data)
        self.assertTrue(data.get("success"))
        self.assertEqual(data["scan"]["profile"], "QUICK")

        # Cleanup created scan
        scan_id = data["scan"]["id"]
        with self.app.app_context():
            s = Scan.query.filter_by(scan_id=scan_id).first()
            if s:
                db.session.delete(s)
                db.session.commit()

        # Reject dangerous injection target
        resp_bad = self.client.post(
            "/scanner/api/scans",
            json={"name": "Bad Scan", "targets": ["127.0.0.1; rm -rf /"]},
        )
        self.assertEqual(resp_bad.status_code, 400)


    # ----------------------------------------------------------------------
    # 10. Quality Fixes: Classification, Service Observations, Tool Availability
    # ----------------------------------------------------------------------
    def test_tcpwrapped_and_generic_open_ports_are_observations_not_vulnerabilities(self):
        """Verifies tcpwrapped and generic open ports (e.g. SSH) are NOT classified as VulnerabilityFinding."""
        with self.app.app_context():
            scan = Scan(
                name="Classification Test Scan",
                scan_type="Quick Scan",
                status="running",
                targets=["10.0.0.1"],
            )
            db.session.add(scan)
            db.session.commit()

            test_ports = [
                {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.2p1", "state": "open"},
                {"port": 100, "protocol": "tcp", "service": "tcpwrapped", "product": "", "version": "", "state": "open"},
                {"port": 101, "protocol": "tcp", "service": "unknown", "product": "tcpwrapped", "version": "", "state": "open"},
                {"port": 53, "protocol": "udp", "service": "domain", "product": "BIND", "version": "9.18", "state": "open"},
            ]

            findings = evaluate_findings_from_ports(scan, test_ports, "10.0.0.1")

            # Must NOT produce any VulnerabilityFinding
            self.assertEqual(len(findings), 0)
            self.assertEqual(scan.total_findings, 0)
            self.assertEqual(scan.critical_count, 0)
            self.assertEqual(scan.high_count, 0)
            self.assertEqual(scan.risk_score, 0)

            # Must be recorded as ServiceObservation
            observations = scan.service_observations
            self.assertEqual(len(observations), 4)
            obs_services = {o["service"] for o in observations}
            self.assertIn("ssh", obs_services)
            self.assertIn("tcpwrapped", obs_services)
            self.assertIn("domain", obs_services)

            # Ensure no CVE or CWE is assigned to observations
            for o in observations:
                self.assertNotIn("cvss_score", o)
                self.assertNotIn("cwe", o)

            # Cleanup
            db.session.delete(scan)
            db.session.commit()

    def test_http_port_80_alone_is_not_hsts_vulnerability(self):
        """Verifies port 80 being open alone does not create an HSTS vulnerability finding."""
        with self.app.app_context():
            scan = Scan(
                name="HTTP Test Scan",
                scan_type="Quick Scan",
                status="running",
                targets=["192.168.1.100"],
            )
            db.session.add(scan)
            db.session.commit()

            # Port 80 on a host that cannot be reached or without confirmed HTTP response evidence
            ports = [
                {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache", "version": "2.4.52", "state": "open"}
            ]

            findings = evaluate_findings_from_ports(scan, ports, "192.168.1.100")

            # In the absence of actual HTTP response evidence, port 80 alone is NOT a vulnerability
            self.assertEqual(len(findings), 0)
            self.assertEqual(scan.total_findings, 0)

            # Must be recorded as a service observation
            self.assertEqual(len(scan.service_observations), 1)
            self.assertEqual(scan.service_observations[0]["port"], 80)
            self.assertEqual(scan.service_observations[0]["service"], "http")

            db.session.delete(scan)
            db.session.commit()

    def test_no_invented_cves_on_smb_and_rdp(self):
        """Verifies SMB and RDP findings do not assign invented CVEs (e.g. CVE-2026-3225, CVE-2026-6089)."""
        with self.app.app_context():
            scan = Scan(
                name="SMB RDP CVE Check",
                scan_type="Quick Scan",
                status="running",
                targets=["10.0.0.5"],
            )
            db.session.add(scan)
            db.session.commit()

            ports = [
                {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "product": "Samba", "version": "4.15", "state": "open"},
                {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "product": "xrdp", "version": "", "state": "open"},
            ]

            findings = evaluate_findings_from_ports(scan, ports, "10.0.0.5")
            self.assertEqual(len(findings), 2)

            for f in findings:
                # Must NOT contain fake 2026 CVEs
                self.assertNotEqual(f.cve, "CVE-2026-3225")
                self.assertNotEqual(f.cve, "CVE-2026-6089")
                self.assertEqual(f.cve or "", "")

            # Cleanup
            for f in findings:
                db.session.delete(f)
            db.session.delete(scan)
            db.session.commit()

    def test_dynamic_tool_availability_truthful_reporting(self):
        """Verifies tools endpoint accurately reflects system availability without faking."""
        resp = self.client.get("/scanner/api/tools")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data.get("success"))

        tools = data.get("tools", {})
        self.assertIn("nmap", tools)
        self.assertIn("whatweb", tools)
        self.assertIn("nikto", tools)
        self.assertIn("nuclei", tools)
        self.assertIn("testssl", tools)

        # Host tools truthful check
        import shutil
        self.assertTrue(tools["nmap"]["available"])
        self.assertTrue(tools["whatweb"]["available"])
        self.assertTrue(tools["nikto"]["available"])
        self.assertEqual(tools["nuclei"]["available"], bool(shutil.which("nuclei")))
        self.assertEqual(tools["testssl"]["available"], bool(shutil.which("testssl.sh") or shutil.which("testssl")))

        # Also check boolean availability dictionary
        avail = data.get("availability", {})
        self.assertEqual(avail.get("nuclei"), bool(shutil.which("nuclei")))
        self.assertEqual(avail.get("testssl"), bool(shutil.which("testssl.sh") or shutil.which("testssl")))

    def test_api_scan_services_endpoint(self):
        """Verifies GET /scanner/api/scans/<scan_id>/services returns service observations."""
        with self.app.app_context():
            scan = Scan(
                name="Services API Scan",
                scan_type="Quick Scan",
                status="completed",
                targets=["127.0.0.1"],
                service_observations_json=json.dumps([
                    {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.2p1", "state": "open", "host": "127.0.0.1", "tool": "nmap"},
                    {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.24", "state": "open", "host": "127.0.0.1", "tool": "nmap"}
                ]),
                service_observations_count=2,
            )
            db.session.add(scan)
            db.session.commit()

            resp = self.client.get(f"/scanner/api/scans/{scan.scan_id}/services")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.data)
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("count"), 2)
            self.assertEqual(len(data.get("services")), 2)
            self.assertEqual(data["services"][0]["port"], 22)

            db.session.delete(scan)
            db.session.commit()

    def test_whatweb_output_parsing_fixture(self):
        """Verifies WhatWeb JSON output is correctly parsed into technology observations without network calls."""
        fixture_data = [
            {
                "target": "http://127.0.0.1:8000",
                "http_status": 200,
                "plugins": {
                    "HTTPServer": {"string": ["gunicorn/21.2.0"], "module": ["Web Server"]},
                    "Python": {"version": ["3.11.8"], "module": ["Programming Language"]},
                    "X-Powered-By": {"string": ["Flask"]},
                },
            }
        ]

        def fake_run(cmd, *args, **kwargs):
            # Write fixture to the output temp file specified in cmd
            for arg in cmd:
                if arg.startswith("--log-json="):
                    file_path = arg.split("=", 1)[1]
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(fixture_data, f)
            mock_res = MagicMock()
            mock_res.returncode = 0
            return mock_res

        with patch("subprocess.run", side_effect=fake_run):
            techs = run_whatweb_scan("http://127.0.0.1:8000", timeout=5)
            self.assertEqual(len(techs), 3)
            names = [t["name"] for t in techs]
            self.assertIn("HTTPServer", names)
            self.assertIn("Python", names)
            self.assertIn("X-Powered-By", names)

            py_tech = next(t for t in techs if t["name"] == "Python")
            self.assertEqual(py_tech["version"], "3.11.8")
            self.assertEqual(py_tech["category"], "Programming Language")

    def test_nikto_output_parsing_fixture(self):
        """Verifies Nikto JSON output is parsed into findings with empty CVE and bounded execution flags."""
        fixture_data = {
            "host": "127.0.0.1",
            "port": "8080",
            "vulnerabilities": [
                {
                    "id": "000001",
                    "OSVDB": "0",
                    "url": "/admin/",
                    "msg": "Directory indexing found on /admin/",
                    "method": "GET"
                },
                {
                    "id": "000002",
                    "OSVDB": "0",
                    "url": "/login",
                    "msg": "Cookie without Secure flag set",
                    "method": "GET"
                }
            ]
        }

        captured_cmd = []

        def fake_run(cmd, *args, **kwargs):
            captured_cmd.extend(cmd)
            for idx, arg in enumerate(cmd):
                if arg == "-output" and idx + 1 < len(cmd):
                    file_path = cmd[idx + 1]
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(fixture_data, f)
            mock_res = MagicMock()
            mock_res.returncode = 0
            return mock_res

        with patch("subprocess.run", side_effect=fake_run):
            findings = run_nikto_scan("http://127.0.0.1:8080", timeout=10)
            self.assertEqual(len(findings), 2)

            # Check that -nointeractive and -ask no were passed
            self.assertIn("-nointeractive", captured_cmd)
            self.assertIn("-ask", captured_cmd)
            self.assertIn("no", captured_cmd)

            for f in findings:
                # Must NOT contain fake CVEs
                self.assertEqual(f["cve"], "")
                self.assertEqual(f["tool"], "nikto")
                self.assertIn("port", f)
                self.assertEqual(f["port"], 8080)


if __name__ == "__main__":
    unittest.main()

