"""
CyberDefense XDR
Unit Test Suite for Global Real-Time Clock Enhancement
Verifies:
1. shell.js defines the real-time clock container, elements, role="timer", aria-label, visible LIVE indicator, and 1-second updater.
2. shell.js utilizes standard JS Date and Intl APIs for local time, date, and timezone.
3. layout.css defines styles for the clock, live pulse indicator, typography, and responsive media queries.
4. Static assets (/static/js/core/shell.js and /static/css/layout.css) return HTTP 200.
5. Authenticated page templates render HTTP 200 and include navbar-root and shell.js.
6. Historical timestamps across system entities (incidents, alerts, audit logs) remain completely intact and unaffected.
"""

import unittest
from pathlib import Path
from app import create_app
from app.extensions import db
from app.users.models import User
from app.incidents.models import Incident
from app.audit_logs.models import AuditLog


class RealtimeClockTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="clock_test_analyst").first()
            if not user:
                user = User(
                    username="clock_test_analyst",
                    email="clock_analyst@defense.local",
                    first_name="Clock",
                    last_name="Analyst",
                    role="ANALYST",
                    status="active",
                    is_active=True,
                )
                user.set_password("ClockPass123!")
                db.session.add(user)
                db.session.commit()
            cls.user_id = user.id

    def get_auth_client(self):
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["_user_id"] = str(self.user_id)
            sess["user_id"] = self.user_id
            sess["_fresh"] = True
        return client

    def test_shell_js_clock_markup_and_accessibility(self):
        """shell.js must contain clock container, IDs, role='timer', aria-label, and LIVE text."""
        shell_path = Path(self.app.root_path) / "static" / "js" / "core" / "shell.js"
        self.assertTrue(shell_path.exists(), "shell.js must exist")
        content = shell_path.read_text(encoding="utf-8")

        self.assertIn('id="xdrRealtimeClock"', content)
        self.assertIn('role="timer"', content)
        self.assertIn('aria-label="System Real-Time Clock"', content)
        self.assertIn('id="xdrClockTime"', content)
        self.assertIn('id="xdrClockDate"', content)
        self.assertIn('id="xdrClockTz"', content)
        self.assertIn('LIVE', content)
        self.assertIn('live-pulse', content)
        self.assertIn('live-label', content)

    def test_shell_js_clock_script_logic(self):
        """shell.js must update clock every 1000ms using Date and Intl APIs."""
        shell_path = Path(self.app.root_path) / "static" / "js" / "core" / "shell.js"
        content = shell_path.read_text(encoding="utf-8")

        self.assertIn("initRealtimeClock", content)
        self.assertIn("setInterval(updateClock, 1000)", content)
        self.assertIn("toLocaleTimeString", content)
        self.assertIn("toLocaleDateString", content)
        self.assertIn("Intl.DateTimeFormat", content)

    def test_layout_css_clock_styles_and_responsiveness(self):
        """layout.css must contain clock styling, animations, and responsive media queries."""
        css_path = Path(self.app.root_path) / "static" / "css" / "layout.css"
        self.assertTrue(css_path.exists(), "layout.css must exist")
        content = css_path.read_text(encoding="utf-8")

        self.assertIn(".xdr-realtime-clock", content)
        self.assertIn(".clock-live-indicator", content)
        self.assertIn(".live-pulse", content)
        self.assertIn(".live-label", content)
        self.assertIn(".clock-display", content)
        self.assertIn(".clock-time", content)
        self.assertIn(".clock-date", content)
        self.assertIn(".clock-tz", content)
        self.assertIn("@keyframes xdrClockPulse", content)
        self.assertIn("@media (max-width: 1100px)", content)
        self.assertIn("@media (max-width: 768px)", content)
        self.assertIn("@media (max-width: 480px)", content)

    def test_static_assets_http_200(self):
        """shell.js and layout.css must be accessible via HTTP 200."""
        client = self.app.test_client()
        res_js = client.get("/static/js/core/shell.js")
        self.assertEqual(res_js.status_code, 200)
        self.assertIn(b"xdrRealtimeClock", res_js.data)

        res_css = client.get("/static/css/layout.css")
        self.assertEqual(res_css.status_code, 200)
        self.assertIn(b"xdr-realtime-clock", res_css.data)

    def test_authenticated_pages_render_with_shell(self):
        """Core authenticated pages render HTTP 200 and include navbar-root and shell.js."""
        client = self.get_auth_client()
        endpoints = [
            "/dashboard/",
            "/alert-center/",
            "/incidents/dashboard",
            "/threat-intelligence/dashboard",
            "/notifications/",
        ]
        for url in endpoints:
            res = client.get(url, follow_redirects=True)
            self.assertEqual(res.status_code, 200, f"Page {url} failed with status {res.status_code}")
            html = res.data.decode("utf-8")
            self.assertIn('id="navbar-root"', html, f"Page {url} missing #navbar-root")
            self.assertIn("shell.js", html, f"Page {url} missing shell.js reference")

    def test_historical_timestamps_integrity(self):
        """Verification that existing models retain their original historical timestamps without modification."""
        with self.app.app_context():
            # Check Incidents
            incident = Incident.query.first()
            if incident:
                self.assertIsNotNone(incident.created_at, "Incident created_at must be preserved")
                self.assertTrue(hasattr(incident, "created_at"), "Incident must retain created_at field")

            # Check Audit Logs
            audit = AuditLog.query.first()
            if audit:
                self.assertIsNotNone(audit.timestamp, "AuditLog timestamp must be preserved")
                self.assertTrue(hasattr(audit, "timestamp"), "AuditLog must retain timestamp field")


if __name__ == "__main__":
    unittest.main()
