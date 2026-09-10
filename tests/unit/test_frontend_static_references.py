"""
CyberDefense XDR
Unit Test Suite for Frontend & Static Reference Hardening
Verifies:
1. Threat Intelligence dashboard references actual existing threat-data.js (no threat-dataa.js)
2. Incident Dashboard does not reference obsolete timeline-data.js
3. Incident Details does not reference obsolete timeline-data.js
4. Timeline page does not reference obsolete timeline-data.js or timeline.js
5. All 4 affected HTML pages render HTTP 200 and every referenced static asset exists (returns HTTP 200)
6. Project-wide assertion: 0 missing url_for('static', ...) references across all templates
"""

import unittest
import re
from pathlib import Path
from app import create_app
from app.extensions import db
from app.users.models import User
from app.incidents.models import Incident
from app.incidents.services import create_incident


class FrontendStaticReferencesTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="static_ref_analyst").first()
            if not user:
                user = User(
                    username="static_ref_analyst",
                    email="static_analyst@defense.local",
                    first_name="Static",
                    last_name="Analyst",
                    role="ANALYST",
                    status="active",
                    is_active=True,
                )
                user.set_password("StaticPass123!")
                db.session.add(user)

            # Ensure at least one incident exists for details & timeline pages
            incident = Incident.query.first()
            if not incident:
                incident = create_incident({
                    "title": "Static Verification Incident",
                    "description": "Used to test incident details & timeline static references",
                    "severity": "medium",
                    "category": "Security",
                }, created_by=user)

            db.session.commit()
            cls.user_id = user.id
            cls.incident_id = incident.incident_id

    def get_auth_client(self):
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = self.user_id
            sess["_user_id"] = str(self.user_id)
            sess["_fresh"] = True
        return client

    # =========================================================================
    # 1. Threat Intelligence Dashboard Template References
    # =========================================================================
    def test_01_threat_dashboard_references_correct_threat_data(self):
        tmpl_path = Path("app/templates/threatintel/threat-dashboard.html")
        content = tmpl_path.read_text(encoding="utf-8")

        # Must not contain typo
        self.assertNotIn("threat-dataa.js", content)
        # Must contain correct reference
        self.assertIn("js/data/threat-data.js", content)

        # File must exist on disk
        self.assertTrue((Path("app/static/js/data/threat-data.js")).exists())

    # =========================================================================
    # 2. Incident Dashboard Template References
    # =========================================================================
    def test_02_incident_dashboard_no_obsolete_timeline_scripts(self):
        tmpl_path = Path("app/templates/incidents/incident-dashboard.html")
        content = tmpl_path.read_text(encoding="utf-8")

        self.assertNotIn("timeline-data.js", content)
        self.assertNotIn("timeline.js", content)

    # =========================================================================
    # 3. Incident Details Template References
    # =========================================================================
    def test_03_incident_details_no_obsolete_timeline_scripts(self):
        tmpl_path = Path("app/templates/incidents/incident-details.html")
        content = tmpl_path.read_text(encoding="utf-8")

        self.assertNotIn("timeline-data.js", content)
        self.assertNotIn("timeline.js", content)

    # =========================================================================
    # 4. Incident Timeline Template References
    # =========================================================================
    def test_04_timeline_page_no_obsolete_timeline_scripts(self):
        tmpl_path = Path("app/templates/incidents/timeline.html")
        content = tmpl_path.read_text(encoding="utf-8")

        self.assertNotIn("timeline-data.js", content)
        self.assertNotIn("timeline.js", content)

    # =========================================================================
    # 5. Live Page Renders & Static Asset Verification
    # =========================================================================
    def test_05_pages_render_and_static_assets_exist(self):
        client = self.get_auth_client()

        pages_to_test = [
            "/threat-intelligence/dashboard",
            "/incidents/dashboard",
            f"/incidents/{self.incident_id}",
            f"/incidents/{self.incident_id}/timeline",
        ]

        for page_url in pages_to_test:
            res = client.get(page_url)
            self.assertEqual(
                res.status_code,
                200,
                f"Expected 200 for {page_url}, got {res.status_code}",
            )

            # Parse HTML and find all script/link static tags
            html_text = res.data.decode("utf-8", errors="ignore")
            static_urls = re.findall(r'(?:src|href)=["\'](/static/[^"\']+)["\']', html_text)

            # Ensure all static URLs return 200 (not 404)
            for s_url in static_urls:
                asset_res = client.get(s_url)
                self.assertEqual(
                    asset_res.status_code,
                    200,
                    f"Static asset {s_url} referenced in {page_url} returned {asset_res.status_code}",
                )

    # =========================================================================
    # 6. Project-wide scan for missing url_for static references
    # =========================================================================
    def test_06_zero_missing_url_for_static_references(self):
        template_dir = Path("app/templates")
        static_dir = Path("app/static")

        url_for_pattern = re.compile(r'url_for\([\'"]static[\'"],\s*filename=[\'"]([^\'"]+)[\'"]\)')

        missing = []
        for html_file in template_dir.rglob("*.html"):
            content = html_file.read_text(encoding="utf-8", errors="ignore")
            for match in url_for_pattern.finditer(content):
                filename = match.group(1)
                full_path = static_dir / filename
                if not full_path.exists():
                    missing.append((str(html_file), filename))

        self.assertEqual(
            missing,
            [],
            f"Found missing static references in templates: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
