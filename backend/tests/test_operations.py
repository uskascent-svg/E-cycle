import os
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

os.environ.setdefault("ECYCLE_SECRET_KEY", "operations-test-secret")
os.environ["ECYCLE_ADMIN_PASSWORD"] = "AdminPass123"
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app
import db


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "e.db"
        self.application = app.create_app(self.path)
        db.seed(self.path)
        self.client = self.application.test_client()
        self.user = {"name": "Ops User", "phone": "9876543210", "email": "ops@example.com", "password": "Secret123!", "address": "Nashik"}
        self.client.post("/api/auth/register", json=self.user)
        self.client.post("/api/auth/login", json={"email": self.user["email"], "password": self.user["password"]})

    def tearDown(self):
        self.tmp.cleanup()

    def admin(self):
        c = self.application.test_client()
        c.post("/api/auth/login", json={"email": "admin@ecycle.local", "password": "AdminPass123"})
        return c

    def test_pickup_booking_is_capacity_safe_and_owns_submission(self):
        submission = self.client.post("/api/submissions", json={"category": "Laptop", "device_name": "ThinkPad", "quantity": 1, "condition": "working", "location": "Nashik"}).get_json()
        slot = self.admin().post("/api/admin/pickup-slots", json={"partner_name": "Verified Recycler", "service_area": "Nashik", "slot_date": (date.today() + timedelta(days=1)).isoformat(), "start_time": "10:00", "end_time": "11:00", "capacity": 1}).get_json()
        booked = self.client.post("/api/pickups", json={"slot_id": slot["id"], "tracking_id": submission["tracking_id"]})
        self.assertEqual(booked.status_code, 201)
        self.assertEqual(self.client.get("/api/pickup-slots?area=Nashik").get_json()["slots"], [])

    def test_certificate_requires_processed_submission_and_public_verification(self):
        submission = self.client.post("/api/submissions", json={"category": "Laptop", "device_name": "ThinkPad", "quantity": 1, "condition": "working", "location": "Nashik"}).get_json()
        admin = self.admin()
        for status in ("VERIFIED", "COLLECTION_SCHEDULED", "COLLECTED", "PROCESSED"):
            self.assertEqual(admin.patch("/api/admin/submissions/" + submission["tracking_id"] + "/status", json={"status": status}).status_code, 200)
        issued = admin.post("/api/admin/certificates", json={"tracking_id": submission["tracking_id"]})
        self.assertEqual(issued.status_code, 201)
        verified = self.client.get("/api/certificates/" + issued.get_json()["verification_token"])
        self.assertEqual(verified.status_code, 200)
        self.assertTrue(verified.get_json()["valid"])

    def test_assistant_fails_truthfully_when_not_configured(self):
        os.environ.pop("GEMINI_API_KEY", None)
        response = self.client.post("/api/assistant/chat", json={"message": "How do I recycle a laptop?"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["fallback"])
        self.assertIn("submit-ewaste.html", response.get_json()["message"])

    def test_distributor_assignment_collection_processing_and_notification(self):
        admin = self.admin()
        submission = self.client.post("/api/submissions", json={"category": "Laptop", "device_name": "ThinkPad", "quantity": 1, "condition": "working", "location": "Nashik"}).get_json()
        distributor_user = {"name": "Verified Recycler", "phone": "9876543211", "email": "recycler@example.com", "password": "Secret123!", "address": "Nashik"}
        self.assertEqual(self.application.test_client().post("/api/auth/register", json=distributor_user).status_code, 201)
        created = admin.post("/api/admin/distributors", json={"email": distributor_user["email"], "service_area": "Nashik", "supported_categories": ["Laptop"], "capacity": 2}).get_json()
        self.assertEqual(admin.patch(f"/api/admin/distributors/{created['id']}", json={"verification_status": "VERIFIED"}).status_code, 200)
        assignment = admin.post("/api/admin/assignments", json={"tracking_id": submission["tracking_id"], "distributor_id": created["id"], "pickup_date": (date.today() + timedelta(days=1)).isoformat(), "start_time": "10:00", "end_time": "11:00"})
        self.assertEqual(assignment.status_code, 201)
        distributor = self.application.test_client(); self.assertEqual(distributor.post("/api/auth/login", json={"email": distributor_user["email"], "password": distributor_user["password"]}).status_code, 200)
        aid = assignment.get_json()["assignment_id"]
        self.assertEqual(distributor.get("/api/distributor/jobs").get_json()["jobs"][0]["id"], aid)
        self.assertEqual(distributor.post(f"/api/distributor/assignments/{aid}/decision", json={"decision": "ACCEPTED"}).status_code, 200)
        self.assertEqual(distributor.post(f"/api/distributor/assignments/{aid}/complete", json={"collected_quantity": 1, "evidence_note": "Collection acknowledgement recorded."}).status_code, 200)
        facility = admin.post("/api/admin/facilities", json={"name": "Nashik Recovery Facility", "service_area": "Nashik", "supported_categories": ["Laptop"], "capacity": 100}).get_json()
        self.assertEqual(admin.patch(f"/api/admin/facilities/{facility['id']}", json={"verification_status": "VERIFIED"}).status_code, 200)
        self.assertEqual(admin.post("/api/admin/facility-intake", json={"tracking_id": submission["tracking_id"], "facility_id": facility["id"], "received_quantity": 1}).status_code, 201)
        self.assertEqual(admin.post("/api/admin/processing", json={"tracking_id": submission["tracking_id"], "facility_id": facility["id"], "outcome": "REUSE", "processed_quantity": 1, "evidence_note": "Device tested and prepared for reuse."}).status_code, 201)
        self.assertTrue(self.client.get("/api/notifications/mine").get_json()["notifications"])


if __name__ == "__main__":
    unittest.main()
