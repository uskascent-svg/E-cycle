import os, sys, tempfile, unittest
from pathlib import Path
os.environ.setdefault("ECYCLE_SECRET_KEY", "demo-test-secret")
os.environ.setdefault("ECYCLE_ADMIN_PASSWORD", "AdminPass123")
os.environ.setdefault("ADMIN_ACCESS_CODE", "test-admin-access")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app, db

class DemoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.path = Path(self.tmp.name) / "e.db"
        self.application = app.create_app(self.path); db.seed(self.path); self.client = self.application.test_client()
        self.admin = self.application.test_client(); self.admin.post("/api/auth/login", json={"email":"admin@ecycle.local","password":"AdminPass123"})
    def tearDown(self): self.tmp.cleanup()
    def reset(self): return self.admin.post("/api/admin/demo/reset")

    def test_exactly_100_isolated_records(self):
        r = self.reset(); self.assertEqual(r.status_code, 200); self.assertEqual(r.get_json()["counts"]["total"], 100)
        self.assertEqual(r.get_json()["counts"], {"submissions":35,"pickups":15,"assignments":10,"centres":5,"facilities":5,"processing":10,"certificates":10,"drives":5,"notifications":5,"total":100})
        conn = db.connect(self.path); self.assertEqual(conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0], 0); conn.close()

    def test_summary_feed_relationships_and_map(self):
        self.assertEqual(self.reset().status_code, 200)
        summary = self.admin.get("/api/admin/demo/summary").get_json(); self.assertEqual(summary["total"], 100); self.assertEqual(summary["certificates_issued"], 10)
        feed = self.admin.get("/api/admin/demo/feed?advance=1").get_json(); types = {e["event_type"] for e in feed["events"]}
        for expected in ("SUBMISSION_RECEIVED","PICKUP_UPDATE","DISTRIBUTOR_ASSIGNED","COLLECTION_COMPLETED","FACILITY_INTAKE","PROCESSING_COMPLETED","CERTIFICATE_ISSUED","COMMUNITY_DRIVE_COMPLETED"): self.assertIn(expected, types)
        markers = self.admin.get("/api/admin/demo/map").get_json(); self.assertTrue(markers["simulated"]); self.assertGreaterEqual(len(markers["markers"]), 30)
        for marker in markers["markers"]: self.assertTrue(-90 <= marker["latitude"] <= 90 and -180 <= marker["longitude"] <= 180)

    def test_demo_inputs_are_available_in_normal_admin_workflow(self):
        inputs = self.admin.get("/api/admin/demo/inputs"); self.assertEqual(inputs.status_code, 200)
        rows = inputs.get_json()["submissions"]; self.assertEqual(len(rows), 100); self.assertTrue(all(row["is_demo"] for row in rows))
        first = next(row for row in rows if row["next_status"]); result = self.admin.patch("/api/admin/demo/inputs/" + first["tracking_id"] + "/status", json={"status": first["next_status"]})
        self.assertEqual(result.status_code, 200); conn = db.connect(self.path); self.assertEqual(conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0], 0); conn.close()

    def test_controls_qr_pdf_and_production_isolation(self):
        self.assertEqual(self.reset().status_code, 200)
        cert = self.admin.get("/api/admin/demo/certificates").get_json()["certificates"][0]
        self.assertEqual(self.client.get("/api/demo/qr/" + cert["verification_token"]).status_code, 200)
        pdf = self.client.get("/api/demo/certificates/" + cert["certificate_no"] + "/pdf"); self.assertEqual(pdf.status_code, 200); self.assertTrue(pdf.data.startswith(b"%PDF"))
        self.assertEqual(self.admin.patch("/api/admin/demo/control", json={"feed_running":False}).status_code, 200)
        self.assertFalse(self.admin.get("/api/admin/demo/status").get_json()["feed_running"])
        self.assertEqual(self.admin.patch("/api/admin/demo/control", json={"enabled":False}).status_code, 200)
        self.assertEqual(self.admin.get("/api/admin/demo/summary").status_code, 409)
        self.assertEqual(self.client.get("/api/demo/certificates/" + cert["certificate_no"]).status_code, 404)

if __name__ == "__main__": unittest.main()
