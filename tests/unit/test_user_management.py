"""
Unit and Integration Tests for User Management & Role-Based Access Control (RBAC)
CyberDefense XDR
Tests role permissions, decorators, admin safety, self-protection,
referential integrity deactivation, and API access boundaries.
"""

import unittest
import json
from datetime import datetime, timedelta

from app import create_app
from app.extensions import db
from app.users.models import User
from app.user_management.permissions import (
    ALL_PERMISSIONS,
    ROLE_PERMISSIONS,
    ROLE_METADATA,
    normalize_role,
    get_permissions_for_role,
)
from app.user_management.services import (
    validate_password_complexity,
    validate_username,
    validate_email,
    count_active_admins,
    create_managed_user,
    update_managed_user,
    delete_managed_user,
    get_role_summary,
    list_users,
    get_user_by_id,
)
from app.incidents.models import Incident


class UserManagementRBACTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            # Setup Admin User
            cls.admin_user = User.query.filter_by(username="rbac_test_admin").first()
            if not cls.admin_user:
                cls.admin_user = User(
                    username="rbac_test_admin",
                    email="rbac_admin@defense.local",
                    first_name="RBAC",
                    last_name="Admin",
                    role="ADMIN",
                    status="active",
                    is_active=True,
                )
                cls.admin_user.set_password("AdminSecure123!")
                db.session.add(cls.admin_user)
                db.session.commit()

            # Setup Analyst User
            cls.analyst_user = User.query.filter_by(username="rbac_test_analyst").first()
            if not cls.analyst_user:
                cls.analyst_user = User(
                    username="rbac_test_analyst",
                    email="rbac_analyst@defense.local",
                    first_name="RBAC",
                    last_name="Analyst",
                    role="SOC_ANALYST",
                    status="active",
                    is_active=True,
                )
                cls.analyst_user.set_password("AnalystPass123!")
                db.session.add(cls.analyst_user)
                db.session.commit()

            # Setup Viewer User
            cls.viewer_user = User.query.filter_by(username="rbac_test_viewer").first()
            if not cls.viewer_user:
                cls.viewer_user = User(
                    username="rbac_test_viewer",
                    email="rbac_viewer@defense.local",
                    first_name="RBAC",
                    last_name="Viewer",
                    role="VIEWER",
                    status="active",
                    is_active=True,
                )
                cls.viewer_user.set_password("ViewerPass123!")
                db.session.add(cls.viewer_user)
                db.session.commit()

            cls.admin_id = cls.admin_user.id
            cls.analyst_id = cls.analyst_user.id
            cls.viewer_id = cls.viewer_user.id

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            admin = db.session.get(User, self.admin_id)
            if admin:
                admin.role = "ADMIN"
                admin.status = "active"
                admin.is_active = True
            analyst = db.session.get(User, self.analyst_id)
            if analyst:
                analyst.role = "SOC_ANALYST"
                analyst.status = "active"
                analyst.is_active = True
            viewer = db.session.get(User, self.viewer_id)
            if viewer:
                viewer.role = "VIEWER"
                viewer.status = "active"
                viewer.is_active = True
            db.session.commit()

    def get_auth_client(self, user_id):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(user_id)
            sess["_fresh"] = True
        return self.client

    # ==========================================================================
    # 1. PERMISSIONS & ROLE UTILITY TESTS
    # ==========================================================================

    def test_01_role_normalization_and_aliases(self):
        """Tests that aliases and casing map correctly to canonical roles."""
        self.assertEqual(normalize_role("admin"), "ADMIN")
        self.assertEqual(normalize_role("ADMINISTRATOR"), "ADMIN")
        self.assertEqual(normalize_role("analyst"), "SOC_ANALYST")
        self.assertEqual(normalize_role("soc_analyst"), "SOC_ANALYST")
        self.assertEqual(normalize_role("security_analyst"), "SECURITY_ANALYST")
        self.assertEqual(normalize_role("incident_responder"), "INCIDENT_RESPONDER")
        self.assertEqual(normalize_role("viewer"), "VIEWER")
        self.assertEqual(normalize_role("read_only"), "VIEWER")
        self.assertEqual(normalize_role("UNKNOWN_ROLE"), "UNKNOWN_ROLE")

    def test_02_permissions_for_role(self):
        """Verifies assigned permission sets across canonical roles."""
        admin_perms = get_permissions_for_role("ADMIN")
        self.assertIn("*", admin_perms)
        self.assertIn("users.create", admin_perms)
        self.assertIn("users.delete", admin_perms)

        soc_perms = get_permissions_for_role("SOC_ANALYST")
        self.assertIn("alerts.modify", soc_perms)
        self.assertIn("incidents.create", soc_perms)
        self.assertIn("soar.execute", soc_perms)
        self.assertNotIn("users.create", soc_perms)
        self.assertNotIn("users.delete", soc_perms)

        viewer_perms = get_permissions_for_role("VIEWER")
        self.assertIn("dashboard.view", viewer_perms)
        self.assertIn("assets.view", viewer_perms)
        self.assertNotIn("assets.create", viewer_perms)
        self.assertNotIn("alerts.modify", viewer_perms)
        self.assertNotIn("soar.execute", viewer_perms)

    # ==========================================================================
    # 2. USER MODEL RBAC HELPERS
    # ==========================================================================

    def test_03_user_model_rbac_methods(self):
        """Tests has_permission, has_role, is_admin, and is_locked on User."""
        with self.app.app_context():
            admin = db.session.get(User, self.admin_id)
            analyst = db.session.get(User, self.analyst_id)
            viewer = db.session.get(User, self.viewer_id)

            self.assertTrue(admin.is_admin)
            self.assertFalse(analyst.is_admin)
            self.assertFalse(viewer.is_admin)

            self.assertTrue(admin.has_role("ADMIN"))
            self.assertTrue(analyst.has_role("SOC_ANALYST", "analyst"))
            self.assertTrue(viewer.has_role("VIEWER"))

            # Admin has wildcard access
            self.assertTrue(admin.has_permission("users.create"))
            self.assertTrue(admin.has_permission("assets.create"))

            # Analyst has operations, but not user management
            self.assertTrue(analyst.has_permission("alerts.modify"))
            self.assertFalse(analyst.has_permission("users.create"))

            # Viewer has view only
            self.assertTrue(viewer.has_permission("assets.view"))
            self.assertFalse(viewer.has_permission("assets.create"))
            self.assertFalse(viewer.has_permission("alerts.modify"))

    def test_04_user_locked_state(self):
        """Tests is_locked behaviour on status and lockout timestamp."""
        with self.app.app_context():
            test_locked = User(
                username="test_lock_user",
                email="lock_user@defense.local",
                first_name="Lock",
                last_name="User",
                role="VIEWER",
                status="locked",
                is_active=False,
            )
            test_locked.set_password("SecurePass123!")
            db.session.add(test_locked)
            db.session.commit()

            self.assertTrue(test_locked.is_locked)
            self.assertFalse(test_locked.has_permission("assets.view"))

            # Unlock
            test_locked.status = "active"
            test_locked.is_active = True
            db.session.commit()
            self.assertFalse(test_locked.is_locked)
            self.assertTrue(test_locked.has_permission("assets.view"))

            # Clean up
            db.session.delete(test_locked)
            db.session.commit()

    # ==========================================================================
    # 3. SERVICE VALIDATIONS
    # ==========================================================================

    def test_05_password_complexity_validator(self):
        """Tests strict enterprise password complexity enforcement."""
        valid, _ = validate_password_complexity("ValidPass123!")
        self.assertTrue(valid)

        short, err = validate_password_complexity("Short1!")
        self.assertFalse(short)
        self.assertIn("at least 8 characters", err)

        no_upper, err = validate_password_complexity("nouppercase123!")
        self.assertFalse(no_upper)
        self.assertIn("uppercase", err)

        no_lower, err = validate_password_complexity("NOLOWERCASE123!")
        self.assertFalse(no_lower)
        self.assertIn("lowercase", err)

        no_digit, err = validate_password_complexity("NoDigitsHere!")
        self.assertFalse(no_digit)
        self.assertIn("number", err)

    def test_06_username_and_email_validators(self):
        """Tests uniqueness and format validation for usernames and emails."""
        with self.app.app_context():
            # Duplicate username
            valid_un, err_un = validate_username("rbac_test_admin")
            self.assertFalse(valid_un)
            self.assertIn("already taken", err_un)

            # Duplicate email
            valid_em, err_em = validate_email("rbac_admin@defense.local")
            self.assertFalse(valid_em)
            self.assertIn("already registered", err_em)

            # Valid new credentials
            valid_un2, _ = validate_username("new_unique_user_99")
            self.assertTrue(valid_un2)
            valid_em2, _ = validate_email("unique.email.99@example.com")
            self.assertTrue(valid_em2)

    # ==========================================================================
    # 4. ADMIN SAFETY & SELF-PROTECTION CHECKS
    # ==========================================================================

    def test_07_last_admin_demotion_and_deletion_protection(self):
        """Ensures the last remaining active administrator cannot be demoted or deleted."""
        with self.app.app_context():
            admin = db.session.get(User, self.admin_id)

            # Temporarily deactivate any other admins to test last-admin boundary
            other_admins = User.query.filter(
                User.id != admin.id,
                User.status == "active"
            ).all()
            orig_states = {}
            for oa in other_admins:
                if oa.get_canonical_role() == "ADMIN":
                    orig_states[oa.id] = oa.role
                    oa.role = "SOC_ANALYST"
            db.session.commit()

            try:
                # Count should be exactly 1
                self.assertEqual(count_active_admins(), 1)

                # Attempt to demote last admin
                with self.assertRaises(ValueError) as ctx:
                    update_managed_user(admin.id, {"role": "VIEWER"}, current_user=None)
                self.assertIn("last remaining active Administrator", str(ctx.exception))

                # Attempt to deactivate last admin
                with self.assertRaises(ValueError) as ctx:
                    update_managed_user(admin.id, {"status": "disabled"}, current_user=None)
                self.assertIn("last remaining active Administrator", str(ctx.exception))

                # Attempt to delete last admin
                with self.assertRaises(ValueError) as ctx:
                    delete_managed_user(admin.id, current_user=None)
                self.assertIn("last remaining active Administrator", str(ctx.exception))

            finally:
                # Restore original roles
                for uid, role in orig_states.items():
                    u = db.session.get(User, uid)
                    if u:
                        u.role = role
                db.session.commit()

    def test_08_self_protection_against_deactivation(self):
        """Ensures an authenticated user cannot deactivate or delete their own account."""
        with self.app.app_context():
            analyst = db.session.get(User, self.analyst_id)

            # Attempt self-deactivation
            with self.assertRaises(ValueError) as ctx:
                update_managed_user(analyst.id, {"status": "disabled"}, current_user=analyst)
            self.assertIn("cannot deactivate or lock your own account", str(ctx.exception))

            # Attempt self-deletion
            with self.assertRaises(ValueError) as ctx:
                delete_managed_user(analyst.id, current_user=analyst)
            self.assertIn("cannot delete your own account", str(ctx.exception))

    def test_09_referential_integrity_soft_deactivation(self):
        """
        Tests that deleting a user with linked security records (e.g. Incidents)
        results in a safe soft-deactivation instead of destructive removal.
        """
        with self.app.app_context():
            # Create temporary user
            temp_user = User(
                username="temp_ir_user",
                email="temp_ir@defense.local",
                first_name="Temp",
                last_name="Responder",
                role="INCIDENT_RESPONDER",
                status="active",
                is_active=True,
            )
            temp_user.set_password("TempPass123!")
            db.session.add(temp_user)
            db.session.commit()

            # Link an incident to this user
            incident = Incident(
                incident_id="INC-RBAC-TEST-01",
                title="RBAC Integrity Test Incident",
                severity="low",
                status="open",
                created_by=temp_user.id,
            )
            db.session.add(incident)
            db.session.commit()

            # Attempt deletion
            result = delete_managed_user(temp_user.id, current_user=None)
            self.assertTrue(result["success"])
            self.assertFalse(result["deleted"])
            self.assertTrue(result["soft_deleted"])
            self.assertIn("safely disabled", result["message"])

            # Verify user status is disabled in DB
            reloaded = db.session.get(User, temp_user.id)
            self.assertEqual(reloaded.status, "disabled")
            self.assertFalse(reloaded.is_active)

            # Cleanup incident and user
            db.session.delete(incident)
            db.session.delete(reloaded)
            db.session.commit()

    # ==========================================================================
    # 5. REST API ENDPOINT TESTS
    # ==========================================================================

    def test_10_api_users_list_and_roles(self):
        """Tests GET /user-management/api/users and /api/roles as Admin."""
        with self.app.app_context():
            client = self.get_auth_client(self.admin_id)

            # Fetch users
            res = client.get("/user-management/api/users")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertTrue(data["success"])
            self.assertGreater(data["total"], 0)
            self.assertIn("stats", data)
            self.assertIn("admins", data["stats"])

            # Fetch roles
            res_roles = client.get("/user-management/api/roles")
            self.assertEqual(res_roles.status_code, 200)
            roles_data = res_roles.get_json()
            self.assertTrue(roles_data["success"])
            self.assertGreaterEqual(len(roles_data["roles"]), 5)

    def test_11_api_user_lifecycle_crud(self):
        """Tests end-to-end user provisioning, detail fetch, modification, and deletion."""
        with self.app.app_context():
            client = self.get_auth_client(self.admin_id)

            # Clean up prior test user if leftover
            old_user = User.query.filter_by(username="api_test_engineer").first()
            if old_user:
                db.session.delete(old_user)
                db.session.commit()

            # 1. Create new user via API
            create_payload = {
                "username": "api_test_engineer",
                "email": "api_engineer@defense.local",
                "first_name": "API",
                "last_name": "Engineer",
                "role": "SECURITY_ANALYST",
                "status": "active",
                "company": "SOC Security",
                "password": "Engine3rPass123!",
            }
            res_create = client.post("/user-management/api/users", json=create_payload)
            self.assertEqual(res_create.status_code, 201)
            created = res_create.get_json()
            self.assertTrue(created["success"])
            new_user_id = created["user"]["id"]

            # 2. Fetch user details
            res_get = client.get(f"/user-management/api/users/{new_user_id}")
            self.assertEqual(res_get.status_code, 200)
            user_detail = res_get.get_json()["user"]
            self.assertEqual(user_detail["username"], "api_test_engineer")
            self.assertEqual(user_detail["role"], "SECURITY_ANALYST")
            self.assertIn("permissions", user_detail)

            # 3. Modify user via PATCH
            patch_payload = {
                "company": "SOC Tier 2",
                "status": "inactive",
            }
            res_patch = client.patch(f"/user-management/api/users/{new_user_id}", json=patch_payload)
            self.assertEqual(res_patch.status_code, 200)
            updated = res_patch.get_json()["user"]
            self.assertEqual(updated["company"], "SOC Tier 2")
            self.assertEqual(updated["status"], "inactive")

            # 4. Delete user via DELETE
            res_delete = client.delete(f"/user-management/api/users/{new_user_id}")
            self.assertEqual(res_delete.status_code, 200)
            self.assertTrue(res_delete.get_json()["success"])

            # Verify deleted
            res_verify = client.get(f"/user-management/api/users/{new_user_id}")
            self.assertEqual(res_verify.status_code, 404)

    # ==========================================================================
    # 6. CROSS-MODULE AUTHORIZATION & 403 BOUNDARIES
    # ==========================================================================

    def test_12_viewer_role_access_boundaries(self):
        """
        Verifies that a VIEWER user is strictly forbidden (HTTP 403) from:
        - Provisioning users (User Management)
        - Creating assets (Asset Management)
        - Creating alerts (Alert Center)
        - Executing SOAR playbooks (Security Automation)
        """
        with self.app.app_context():
            client = self.get_auth_client(self.viewer_id)

            # 1. Viewer cannot provision users (needs users.create)
            res_users = client.post("/user-management/api/users", json={
                "username": "viewer_illegal_user",
                "email": "illegal@defense.local",
                "first_name": "Illegal",
                "last_name": "User",
                "password": "IllegalPass123!",
            })
            self.assertEqual(res_users.status_code, 403)

            # 2. Viewer cannot create assets (needs assets.create)
            res_assets = client.post("/assets/api", json={
                "name": "Unauthorized Asset",
                "ip_address": "192.168.1.99",
                "type": "server",
            })
            self.assertEqual(res_assets.status_code, 403)

            # 3. Viewer cannot create alerts (needs alerts.modify)
            res_alerts = client.post("/alert-center/create", json={
                "title": "Unauthorized Alert",
                "severity": "low",
            })
            self.assertEqual(res_alerts.status_code, 403)

            # 4. Viewer cannot execute SOAR playbooks (needs soar.execute)
            res_soar = client.post("/soar/api/playbooks/pb-containment-01/execute", json={
                "target_id": "HOST-001",
                "target_type": "asset",
            })
            self.assertEqual(res_soar.status_code, 403)


if __name__ == "__main__":
    unittest.main()
