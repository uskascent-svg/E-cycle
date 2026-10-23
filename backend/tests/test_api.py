"""Run from the backend folder:  python -m unittest discover -s tests -v"""
import os
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ECYCLE_SECRET_KEY", "test-secret")
os.environ["ECYCLE_ADMIN_PASSWORD"] = "AdminPass123"

import app as app_module  # noqa: E402
import db  # noqa: E402
import rules  # noqa: E402

USER = {"name": "Asha Patil", "phone": "9876543210", "email": "asha@example.com",
        "password": "Secret123!", "address": "12 MG Road, Nashik"}
ITEM = {"category": "Laptop", "device_name": "Dell Laptop", "brand": "Dell", "quantity": 1,
        "condition": "partially_working", "location": "Nashik", "description": "Screen flickers"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name) / "t.db"
        self.app = app_module.create_app(path)
        db.seed(path)
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def register_login(self, c=None, user=USER):
        c = c or self.c
        self.assertEqual(c.post("/api/auth/register", json=user).status_code, 201)
        r = c.post("/api/auth/login", json={"email": user["email"], "password": user["password"]})
        self.assertEqual(r.status_code, 200)
        return c

    def admin(self):
        c = self.app.test_client()
        r = c.post("/api/auth/login", json={"email": "admin@ecycle.local", "password": "AdminPass123"})
        self.assertEqual(r.status_code, 200)
        return c


class RulesTests(unittest.TestCase):
    def test_recommendations(self):
        self.assertEqual(rules.recommend("working"), "Reuse / Donate")
        self.assertEqual(rules.recommend("partially_working"), "Repair / Refurbish")
        self.assertEqual(rules.recommend("non_working"), "Recycle")
        self.assertEqual(rules.recommend("???"), "Manual Review")
        self.assertEqual(rules.recommend("working", battery_damaged=True), "Specialized Handling")


class AuthTests(Base):
    def test_register_validation(self):
        bad = [({**USER, "email": "nope"}, "email"), ({**USER, "password": "short"}, "password"),
               ({**USER, "phone": "12"}, "phone"), ({**USER, "name": ""}, "name")]
        for payload, field in bad:
            r = self.c.post("/api/auth/register", json=payload)
            self.assertEqual(r.status_code, 400, field)
            self.assertEqual(r.get_json()["field"], field)

    def test_duplicate_email_case_insensitive(self):
        self.c.post("/api/auth/register", json=USER)
        r = self.c.post("/api/auth/register", json={**USER, "email": "ASHA@Example.com"})
        self.assertEqual(r.status_code, 409)

    def test_password_is_hashed(self):
        self.c.post("/api/auth/register", json=USER)
        with self.app.app_context():
            conn = db.connect(self.app.config["DB_PATH"])
            h = conn.execute("SELECT password_hash FROM users WHERE email=?", (USER["email"],)).fetchone()[0]
            conn.close()
        self.assertNotIn(USER["password"], h)

    def test_login_logout_me(self):
        self.assertIsNone(self.c.get("/api/auth/me").get_json()["user"])
        self.register_login()
        self.assertEqual(self.c.get("/api/auth/me").get_json()["user"]["email"], USER["email"])
        self.c.post("/api/auth/logout")
        self.assertIsNone(self.c.get("/api/auth/me").get_json()["user"])

    def test_wrong_password_and_unknown_user_same_message(self):
        self.c.post("/api/auth/register", json=USER)
        a = self.c.post("/api/auth/login", json={"email": USER["email"], "password": "wrongwrong"})
        b = self.c.post("/api/auth/login", json={"email": "ghost@example.com", "password": "wrongwrong"})
        self.assertEqual((a.status_code, b.status_code), (401, 401))
        self.assertEqual(a.get_json(), b.get_json())

    def test_non_json_write_rejected(self):
        r = self.c.post("/api/auth/login", data="email=a@b.c&password=x",
                        content_type="application/x-www-form-urlencoded")
        self.assertEqual(r.status_code, 415)


class SubmissionTests(Base):
    def test_guest_submission_and_tracking(self):
        r = self.c.post("/api/submissions", json=ITEM)
        self.assertEqual(r.status_code, 201)
        d = r.get_json()
        self.assertEqual(d["recommendation"], "Repair / Refurbish")
        self.assertRegex(d["tracking_id"], r"^EC-\d{4}-\d{4}$")
        self.assertFalse(d["linked_to_account"])
        t = self.c.get(f"/api/track/{d['tracking_id'].lower()}").get_json()  # case-insensitive
        self.assertEqual(t["status"], "SUBMITTED")
        self.assertEqual([s["done"] for s in t["stages"]], [True, False, False, False, False])
        self.assertEqual(len(t["history"]), 1)
        self.assertEqual(t["history"][0]["status"], "SUBMITTED")
        for private in ("location", "description", "owner_email", "user_id"):
            self.assertNotIn(private, t)

    def test_tracking_ids_unique_and_sequential(self):
        ids = [self.c.post("/api/submissions", json=ITEM).get_json()["tracking_id"] for _ in range(5)]
        self.assertEqual(len(set(ids)), 5)

    def test_validation(self):
        for patch in ({"category": "Fridge"}, {"condition": "broken"}, {"quantity": 0},
                      {"quantity": "3"}, {"quantity": True}, {"device_name": ""}, {"location": ""}):
            r = self.c.post("/api/submissions", json={**ITEM, **patch})
            self.assertEqual(r.status_code, 400, patch)

    def test_battery_flag_requires_json_boolean(self):
        for value in ("false", "true", 0, 1, None):
            r = self.c.post("/api/submissions", json={**ITEM, "battery_damaged": value})
            self.assertEqual(r.status_code, 400, repr(value))
            self.assertEqual(r.get_json()["field"], "battery_damaged")
        r = self.c.post("/api/submissions", json={**ITEM, "battery_damaged": True})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["recommendation"], "Specialized Handling")

    def test_battery_override(self):
        d = self.c.post("/api/submissions", json={**ITEM, "condition": "working",
                                                   "battery_damaged": True}).get_json()
        self.assertEqual(d["recommendation"], "Specialized Handling")

    def test_unknown_and_malformed_tracking(self):
        self.assertEqual(self.c.get("/api/track/EC-2026-9999").status_code, 404)
        self.assertEqual(self.c.get("/api/track/hello").status_code, 400)

    def test_dashboard_requires_login_and_is_per_user(self):
        self.assertEqual(self.c.get("/api/submissions/mine").status_code, 401)
        self.register_login()
        r = self.c.post("/api/submissions", json=ITEM)
        self.assertTrue(r.get_json()["linked_to_account"])
        other = self.register_login(self.app.test_client(), {**USER, "email": "b@example.com"})
        self.assertEqual(other.get("/api/submissions/mine").get_json()["stats"]["total"], 0)
        mine = self.c.get("/api/submissions/mine").get_json()
        self.assertEqual(mine["stats"], {"total": 1, "active": 1, "completed": 0, "certificates": 0})
        self.assertEqual(mine["submissions"][0]["device_name"], "Dell Laptop")


class AdminTests(Base):
    def test_admin_only(self):
        self.assertEqual(self.c.get("/api/admin/submissions").status_code, 401)
        self.register_login()
        self.assertEqual(self.c.get("/api/admin/submissions").status_code, 403)
        self.assertEqual(self.c.patch("/api/admin/submissions/EC-2026-0001/status",
                                      json={"status": "VERIFIED"}).status_code, 403)

    def test_status_flow_is_strictly_linear(self):
        tid = self.c.post("/api/submissions", json=ITEM).get_json()["tracking_id"]
        a = self.admin()
        url = f"/api/admin/submissions/{tid}/status"
        self.assertEqual(a.patch(url, json={"status": "COLLECTED"}).status_code, 409)  # skipping
        self.assertEqual(a.patch(url, json={"status": "SUBMITTED"}).status_code, 409)  # backwards
        self.assertEqual(a.patch(url, json={"status": "bogus"}).status_code, 400)
        for st in rules.STATUS_FLOW[1:]:
            self.assertEqual(a.patch(url, json={"status": st}).status_code, 200, st)
        self.assertEqual(a.patch(url, json={"status": "PROCESSED"}).status_code, 409)  # final
        t = self.c.get(f"/api/track/{tid}").get_json()
        self.assertTrue(all(s["done"] for s in t["stages"]))
        self.assertEqual(t["status"], "PROCESSED")
        self.assertEqual(len(t["history"]), len(rules.STATUS_FLOW))

    def test_processed_updates_dashboard_and_impact(self):
        self.register_login()
        tid = self.c.post("/api/submissions", json={**ITEM, "quantity": 3}).get_json()["tracking_id"]
        a = self.admin()
        for st in rules.STATUS_FLOW[1:]:
            a.patch(f"/api/admin/submissions/{tid}/status", json={"status": st})
        s = self.c.get("/api/submissions/mine").get_json()["stats"]
        self.assertEqual(s, {"total": 1, "active": 0, "completed": 1, "certificates": 1})
        imp = self.c.get("/api/impact").get_json()
        self.assertEqual(imp["total_submissions"], 1)
        self.assertEqual(imp["collected_items"], 3)
        self.assertEqual(imp["distribution"]["repair"], 1)

    def test_admin_list_filter(self):
        self.c.post("/api/submissions", json=ITEM)
        a = self.admin()
        self.assertEqual(len(a.get("/api/admin/submissions").get_json()["submissions"]), 1)
        self.assertEqual(len(a.get("/api/admin/submissions?status=VERIFIED").get_json()["submissions"]), 0)
        self.assertEqual(a.get("/api/admin/submissions?status=nope").status_code, 400)


class DriveTests(Base):
    def test_admin_can_create_future_drive_and_cannot_create_past_drive(self):
        admin = self.admin()
        future = (date.today() + timedelta(days=10)).isoformat()
        created = admin.post("/api/admin/drives", json={
            "title": "Neighbourhood E-Waste Drive", "location": "Community Hall",
            "drive_date": future, "description": "Bring small electronics."
        })
        self.assertEqual(created.status_code, 201)
        self.assertTrue(any(d["id"] == created.get_json()["id"]
                            for d in self.c.get("/api/drives").get_json()["drives"]))
        past = (date.today() - timedelta(days=1)).isoformat()
        rejected = admin.post("/api/admin/drives", json={
            "title": "Past Drive", "location": "Hall", "drive_date": past
        })
        self.assertEqual(rejected.status_code, 400)

    def test_list_join_and_duplicate(self):
        drives = self.c.get("/api/drives").get_json()["drives"]
        self.assertEqual(len(drives), 2)
        self.assertTrue(all(d["status"] == "UPCOMING" for d in drives))
        did = drives[0]["id"]
        self.assertEqual(self.c.post(f"/api/drives/{did}/join").status_code, 401)
        self.register_login()
        self.assertEqual(self.c.post(f"/api/drives/{did}/join").status_code, 201)
        self.assertEqual(self.c.post(f"/api/drives/{did}/join").status_code, 409)
        d = [x for x in self.c.get("/api/drives").get_json()["drives"] if x["id"] == did][0]
        self.assertTrue(d["joined"])
        self.assertEqual(d["participants"], 1)
        self.assertEqual(self.c.post("/api/drives/9999/join").status_code, 404)
        self.assertEqual(self.c.get("/api/impact").get_json()["community_participants"], 1)

    def test_past_drive_cannot_be_joined(self):
        a = self.admin()
        past = (date.today() - timedelta(days=3)).isoformat()
        with self.app.app_context():
            conn = db.connect(self.app.config["DB_PATH"])
            did = conn.execute("INSERT INTO drives (title, location, drive_date) VALUES (?,?,?)",
                               ("Old drive", "Hall", past)).lastrowid
            conn.commit()
            conn.close()
        self.register_login()
        self.assertEqual(self.c.post(f"/api/drives/{did}/join").status_code, 400)
        self.assertEqual(self.c.get("/api/impact").get_json()["completed_drives"], 1)

    def test_admin_create_drive_validation(self):
        a = self.admin()
        r = a.post("/api/admin/drives", json={"title": "Drive", "location": "Hall", "drive_date": "31/12/2026"})
        self.assertEqual(r.status_code, 400)


class StaticTests(Base):
    def test_health_endpoint_and_security_headers(self):
        r = self.c.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"status": "ok", "database": "connected"})
        self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")

    def test_pages_served_and_traversal_blocked(self):
        self.assertEqual(self.c.get("/").status_code, 200)
        self.assertEqual(self.c.get("/login.html").status_code, 200)
        self.assertEqual(self.c.get("/css/style.css").status_code, 200)
        self.assertEqual(self.c.get("/../backend/app.py").status_code, 404)
        self.assertEqual(self.c.get("/%2e%2e/backend/app.py").status_code, 404)
        self.assertEqual(self.c.get("/api/nothing").status_code, 404)


if __name__ == "__main__":
    unittest.main()
