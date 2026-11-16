import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("ECYCLE_SECRET_KEY", "upgrade-test-secret")
os.environ["ECYCLE_ADMIN_PASSWORD"] = "AdminPass123"
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

    def test_admin_upgrade_endpoints_are_protected_and_operational(self):
        self.assertEqual(self.client.get("/api/admin/summary").status_code, 403)
        admin = self.admin()
        self.assertEqual(admin.get("/api/admin/summary").status_code, 200)
        self.assertEqual(admin.get("/api/admin/analytics").status_code, 200)
        self.assertEqual(admin.get("/api/admin/security-events").status_code, 200)
        self.assertEqual(admin.get("/api/admin/collection-map").status_code, 200)

    def test_migration_marker_and_new_tables_are_additive(self):
        conn = db.connect(self.path)
        marker = conn.execute("SELECT version FROM schema_migrations WHERE version=?", ("2026-11-platform-upgrade",)).fetchone()
        self.assertIsNotNone(marker)
        for table in ("qr_tracking", "green_wallets", "facility_inventory", "security_events", "collection_forecasts"):
            self.assertIsNotNone(conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())
        conn.close()

    def test_login_rate_limit_is_enforced(self):
        for _ in range(10):
            self.assertEqual(self.application.test_client().post("/api/auth/login", json={"email": "wrong@example.com", "password": "wrong-password"}).status_code, 401)
        self.assertEqual(self.application.test_client().post("/api/auth/login", json={"email": "wrong@example.com", "password": "wrong-password"}).status_code, 429)


if __name__ == "__main__":
    unittest.main()
