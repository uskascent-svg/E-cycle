import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("ECYCLE_SECRET_KEY", "upgrade-test-secret")
os.environ["ECYCLE_ADMIN_PASSWORD"] = "AdminPass123"
os.environ.setdefault("ADMIN_ACCESS_CODE", "test-admin-access")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app
import db


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "e.db"
        self.application = app.create_app(self.path)
        db.seed(self.path)
        self.user_data = {"name": "Upgrade User", "phone": "9876543210", "email": "upgrade@example.com", "password": "Secret123!", "address": "Nashik"}
        self.client = self.application.test_client()
        self.client.post("/api/auth/register", json=self.user_data)
        self.client.post("/api/auth/login", json={"email": self.user_data["email"], "password": self.user_data["password"]})

    def tearDown(self):
        self.tmp.cleanup()

    def admin(self):
        client = self.application.test_client()
        client.post("/api/auth/login", json={"email": "admin@ecycle.local", "password": "AdminPass123"})
        return client

    def test_submission_creates_public_qr_and_reward(self):
        result = self.client.post("/api/submissions", json={"category": "Laptop", "device_name": "Latitude", "quantity": 1, "condition": "working", "location": "Nashik"})
        self.assertEqual(result.status_code, 201)
        payload = result.get_json()
        qr = self.client.get("/api/qr/" + payload["qr_token"])
        self.assertEqual(qr.status_code, 200)
        self.assertEqual(qr.get_json()["tracking_id"], payload["tracking_id"])
        qr_image = self.client.get("/api/qr-image/" + payload["qr_token"] + ".svg")
        self.assertEqual(qr_image.status_code, 200)
        self.assertIn("svg", qr_image.content_type)
        rewards = self.client.get("/api/rewards/mine")
        self.assertEqual(rewards.status_code, 200)
        self.assertEqual(rewards.get_json()["points"], 10)

    def test_shared_admin_access_code_is_server_side_and_scoped(self):
        code_client = self.application.test_client()
        bad = code_client.post("/api/auth/admin-code", json={"access_code": "wrong"})
        self.assertEqual(bad.status_code, 401)
        good = code_client.post("/api/auth/admin-code", json={"access_code": "test-admin-access"})
        self.assertEqual(good.status_code, 200)
        self.assertEqual(code_client.get("/api/admin/summary").status_code, 200)
        self.assertEqual(code_client.get("/api/submissions/mine").status_code, 401)

    def test_admin_upgrade_endpoints_are_protected_and_operational(self):
        self.assertEqual(self.client.get("/api/admin/summary").status_code, 403)
        admin = self.admin()
        self.assertEqual(admin.get("/api/admin/summary").status_code, 200)
        self.assertEqual(admin.get("/api/admin/analytics").status_code, 200)
        self.assertEqual(admin.get("/api/admin/security-events").status_code, 200)
        self.assertEqual(admin.get("/api/admin/collection-map").status_code, 200)
        self.assertEqual(admin.get("/api/admin/analytics?from=2026-01-01&to=2026-12-31").status_code, 200)
        self.assertEqual(admin.get("/api/admin/settings").status_code, 200)
        self.assertEqual(admin.patch("/api/admin/settings", json={"estimated_recovery_rate": 0.8}).status_code, 200)

    def test_rbac_user_activity_and_csrf_origin_guard(self):
        admin = self.admin()
        me = admin.get("/api/admin/me")
        self.assertEqual(me.status_code, 200)
        self.assertIn("Super Admin", me.get_json()["admin_role"])
        self.assertEqual(admin.get("/api/admin/users/1").status_code, 200)
        self.assertEqual(admin.get("/api/admin/roles").status_code, 200)
        self.assertEqual(admin.patch("/api/admin/users/1", json={"role": "user"}).status_code, 409)
        self.assertEqual(self.client.post("/api/auth/logout", headers={"Origin": "https://attacker.invalid"}).status_code, 403)

    def test_verified_location_and_certificate_pdf_access(self):
        admin = self.admin()
        submission = self.client.post("/api/submissions", json={"category": "Laptop", "device_name": "Latitude", "quantity": 1, "condition": "working", "location": "Nashik"}).get_json()
        conn = db.connect(self.path); submission_id = conn.execute("SELECT id FROM submissions WHERE tracking_id=?", (submission["tracking_id"],)).fetchone()[0]; conn.close()
        self.assertEqual(admin.post("/api/admin/locations", json={"entity_type": "SUBMISSION", "entity_id": submission_id, "latitude": 91, "longitude": 77, "consented": True}).status_code, 400)
        self.assertEqual(admin.post("/api/admin/locations", json={"entity_type": "SUBMISSION", "entity_id": submission_id, "latitude": 20.0, "longitude": 73.78, "consented": True}).status_code, 200)
        self.assertTrue(admin.get("/api/admin/collection-map").get_json()["markers"])
        for status in ("VERIFIED", "COLLECTION_SCHEDULED", "COLLECTED"):
            self.assertEqual(admin.patch("/api/admin/submissions/" + submission["tracking_id"] + "/status", json={"status": status}).status_code, 200)
        facility = admin.post("/api/admin/facilities", json={"name": "Verified Facility", "service_area": "Nashik", "supported_categories": ["Laptop"], "capacity": 100}).get_json()
        self.assertEqual(admin.patch(f"/api/admin/facilities/{facility['id']}", json={"verification_status": "VERIFIED"}).status_code, 200)
        self.assertEqual(admin.post("/api/admin/facility-intake", json={"tracking_id": submission["tracking_id"], "facility_id": facility["id"], "received_quantity": 1}).status_code, 201)
        self.assertEqual(admin.post("/api/admin/processing", json={"tracking_id": submission["tracking_id"], "facility_id": facility["id"], "outcome": "MATERIAL_RECOVERY", "processed_quantity": 1, "evidence_note": "Recorded processing."}).status_code, 201)
        issued = self.client.get("/api/certificates/mine").get_json()["certificates"][0]
        self.assertEqual(self.client.get("/api/certificates/" + issued["certificate_no"]).status_code, 200)
        pdf = self.client.get("/api/certificates/" + issued["verification_token"] + "/pdf")
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.content_type, "application/pdf")
        self.assertEqual(admin.patch("/api/admin/certificates/" + issued["certificate_no"], json={"action": "revoke", "reason": "Administrative correction"}).status_code, 200)

    def test_user_location_requires_consent_and_is_pending_verification(self):
        self.client.post("/api/submissions", json={"category": "Laptop", "device_name": "Latitude", "quantity": 1, "condition": "working", "location": "Nashik"})
        mine = self.client.get("/api/submissions/mine").get_json()["submissions"][0]
        self.assertEqual(self.client.post("/api/locations/mine", json={"submission_id": mine["id"], "latitude": 20, "longitude": 73}).status_code, 400)
        response = self.client.post("/api/locations/mine", json={"submission_id": mine["id"], "latitude": 20, "longitude": 73, "consented": True})
        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.get_json()["verified"])

    def test_migration_marker_and_new_tables_are_additive(self):
        conn = db.connect(self.path)
        marker = conn.execute("SELECT version FROM schema_migrations WHERE version=?", ("2026-11-platform-upgrade",)).fetchone()
        self.assertIsNotNone(marker)
        self.assertIsNotNone(conn.execute("SELECT version FROM schema_migrations WHERE version=?", ("2026-11-certificates-map-admin-code",)).fetchone())
        for table in ("qr_tracking", "green_wallets", "facility_inventory", "security_events", "collection_forecasts", "platform_settings"):
            self.assertIsNotNone(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())
        conn.close()

    def test_login_rate_limit_is_enforced(self):
        for _ in range(10):
            self.assertEqual(self.application.test_client().post("/api/auth/login", json={"email": "wrong@example.com", "password": "wrong-password"}).status_code, 401)
        self.assertEqual(self.application.test_client().post("/api/auth/login", json={"email": "wrong@example.com", "password": "wrong-password"}).status_code, 429)

    def test_security_command_centre_is_authorized_and_operational(self):
        self.assertEqual(self.client.get("/api/admin/security/overview").status_code, 403)
        admin = self.admin()
        self.assertEqual(admin.get("/admin/security").status_code, 200)
        self.assertEqual(admin.get("/admin/operations").status_code, 200)
        for _ in range(11):
            self.application.test_client().post("/api/auth/login", json={"email": "security-test@example.com", "password": "wrong-password"})
        overview = admin.get("/api/admin/security/overview").get_json()
        self.assertIn("CRITICAL", overview["counts"])
        self.assertIn("HIGH", overview["counts"])
        self.assertIn("events", overview)
        self.assertEqual(admin.patch("/api/admin/security/config", json={"login_lockdown": False, "registration_suspended": True, "reason": "Security test"}).status_code, 200)
        self.assertEqual(self.application.test_client().post("/api/auth/register", json={"name": "Blocked", "phone": "9876543210", "email": "blocked-security@example.com", "password": "Secret123!", "address": "Nashik"}).status_code, 503)


if __name__ == "__main__":
    unittest.main()
