"""E-Cycle backend: Flask + SQLite.

Serves the static frontend AND the JSON API from one origin, so session
cookies work without any CORS setup.

    python app.py            -> http://127.0.0.1:5000
"""
import os
import re
import secrets
import sqlite3
import json
import csv
import io
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from google import genai
except ImportError:  # optional until GEMINI_API_KEY is configured
    genai = None

import db
import rules

BASE = Path(__file__).resolve().parent
FRONTEND = BASE.parent / "frontend"

def _load_local_env():
    """Load ignored local secrets for development without exposing them to clients."""
    env_file = BASE / ".env.local"
    if not env_file.exists():
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(name.strip(), value)

_load_local_env()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?\d{10,13}$")
TRACKING_RE = re.compile(r"^EC-\d{4}-\d{4,}$")

# Compared against when an email is unknown, so "no such user" and "wrong
# password" take about the same time (avoids leaking which emails exist).
_DUMMY_HASH = generate_password_hash("not-a-real-password")


class ApiError(Exception):
    def __init__(self, message, status=400, field=None):
        self.message, self.status, self.field = message, status, field


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _secret_key():
    """Env var wins; otherwise generate once and keep it so logins survive restarts."""
    key = os.environ.get("ECYCLE_SECRET_KEY")
    if key:
        return key
    path = BASE / "data" / ".secret_key"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(secrets.token_hex(32))
    return path.read_text().strip()


def create_app(db_path=None):
    app = Flask(__name__, static_folder=None)
    app.config["DB_PATH"] = str(db_path or os.environ.get("ECYCLE_DB", db.DEFAULT_DB))
    app.config["SECRET_KEY"] = _secret_key()
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_REFRESH_EACH_REQUEST"] = False
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("ECYCLE_SECURE_COOKIES") == "1"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # no request here needs more than 64 KB
    assistant_requests = {}

    db.init_schema(app.config["DB_PATH"])

    # ---------------------------------------------------------------- plumbing
    def get_db():
        if "db" not in g:
            g.db = db.connect(app.config["DB_PATH"])
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.errorhandler(ApiError)
    def handle_api_error(e):
        body = {"error": e.message}
        if e.field:
            body["field"] = e.field
        return jsonify(body), e.status

    @app.errorhandler(404)
    def not_found(_e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return "Page not found", 404

    @app.errorhandler(400)
    def bad_request(_e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Bad request"}), 400
        return "Bad request", 400

    @app.errorhandler(405)
    def bad_method(_e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify({"error": "Request too large"}), 413

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify({"error": "Internal server error"}), 500

    @app.before_request
    def require_json_for_writes():
        # Cross-site HTML forms cannot send application/json without a CORS
        # preflight, so this doubles as a simple CSRF defence.
        if request.path.startswith("/api/") and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.get_data(cache=True) and not request.is_json:
                raise ApiError("Content-Type must be application/json", 415)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Content-Type-Options"] = "nosniff"
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ApiError("Request body must be a JSON object")
        return data

    def text(data, key, label, min_len=1, max_len=200, required=True):
        v = data.get(key)
        if v is None or (isinstance(v, str) and not v.strip()):
            if required:
                raise ApiError(f"{label} is required", field=key)
            return None
        if not isinstance(v, str):
            raise ApiError(f"{label} must be text", field=key)
        v = v.strip()
        if len(v) < min_len:
            raise ApiError(f"{label} must be at least {min_len} characters", field=key)
        if len(v) > max_len:
            raise ApiError(f"{label} must be at most {max_len} characters", field=key)
        return v

    def current_user():
        if "user" not in g:
            g.user = None
            uid = session.get("user_id")
            if uid is not None:
                row = get_db().execute(
                    "SELECT id, name, email, role FROM users WHERE id = ?", (uid,)
                ).fetchone()
                if row:
                    g.user = row
                else:
                    session.clear()  # account was deleted
        return g.user

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if current_user() is None:
                raise ApiError("Please log in first", 401)
            return fn(*a, **kw)
        return wrapper

    def admin_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = current_user()
            if user is None:
                raise ApiError("Please log in first", 401)
            if user["role"] != "admin":
                raise ApiError("Admin access required", 403)
            return fn(*a, **kw)
        return wrapper

    def user_json(u):
        return {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"]}

    # -------------------------------------------------------------------- health
    @app.get("/api/health")
    def health():
        # Lightweight liveness/readiness check; never expose paths or secrets.
        get_db().execute("SELECT 1").fetchone()
        return jsonify({"status": "ok", "database": "connected"})

    # -------------------------------------------------------------------- auth
    @app.post("/api/auth/register")
    def register():
        d = body()
        name = text(d, "name", "Name", 2, 100)
        email = text(d, "email", "Email", 3, 254).lower()
        phone = (text(d, "phone", "Phone", 1, 20)).replace(" ", "").replace("-", "")
        password = d.get("password")
        address = text(d, "address", "Address", 5, 500)
        if not EMAIL_RE.match(email):
            raise ApiError("Enter a valid email address", field="email")
        if not PHONE_RE.match(phone):
            raise ApiError("Enter a valid phone number (10-13 digits)", field="phone")
        if not isinstance(password, str) or not (8 <= len(password) <= 128):
            raise ApiError("Password must be 8-128 characters", field="password")
        try:
            get_db().execute(
                "INSERT INTO users (name, email, phone, password_hash, address) VALUES (?,?,?,?,?)",
                (name, email, phone, generate_password_hash(password), address),
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            raise ApiError("An account with this email already exists", 409, field="email")
        return jsonify({"message": "Account created"}), 201

    @app.post("/api/auth/login")
    def login():
        d = body()
        email = str(d.get("email", "")).strip().lower()
        password = str(d.get("password", ""))
        row = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        ok = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password)
        if not (row and ok):
            raise ApiError("Invalid email or password", 401)
        session.clear()
        session.permanent = True
        session["user_id"] = row["id"]
        return jsonify({"user": user_json(row)})

    @app.post("/api/auth/logout")
    def logout():
        session.clear()
        return jsonify({"message": "Logged out"})

    @app.get("/api/auth/me")
    def me():
        # 200 with user:null (not 401) so the navbar check on every page
        # doesn't litter the browser console with errors for visitors.
        u = current_user()
        return jsonify({"user": user_json(u) if u else None})

    # ------------------------------------------------------------- submissions
    @app.post("/api/submissions")
    def create_submission():
        d = body()
        category = text(d, "category", "Device category", 1, 50)
        if category not in rules.CATEGORIES:
            raise ApiError("Choose a valid device category", field="category")
        device_name = text(d, "device_name", "Device name", 1, 100)
        brand = text(d, "brand", "Brand", 1, 100, required=False)
        condition = text(d, "condition", "Condition", 1, 30)
        if condition not in rules.CONDITIONS:
            raise ApiError("Choose a valid condition", field="condition")
        location = text(d, "location", "Location", 2, 200)
        description = text(d, "description", "Description", 1, 1000, required=False)
        qty = d.get("quantity", 1)
        if isinstance(qty, bool) or not isinstance(qty, int) or not (1 <= qty <= 1000):
            raise ApiError("Quantity must be a whole number from 1 to 1000", field="quantity")
        battery_value = d.get("battery_damaged", False)
        if not isinstance(battery_value, bool):
            raise ApiError("Battery damage must be true or false", field="battery_damaged")
        battery = battery_value

        recommendation = rules.recommend(condition, battery)
        user = current_user()
        conn = get_db()
        # Insert with a throwaway tracking id, then derive the real one from the
        # row id: unique by construction, no random-collision risk, and both
        # statements commit together.
        cur = conn.execute(
            "INSERT INTO submissions (tracking_id, user_id, category, device_name, brand, quantity,"
            " device_condition, battery_damaged, location, description, recommendation)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("PENDING-" + secrets.token_hex(8), user["id"] if user else None, category,
             device_name, brand, qty, condition, int(battery), location, description, recommendation),
        )
        sid = cur.lastrowid
        tracking_id = f"EC-{date.today().year}-{sid:04d}"
        conn.execute("UPDATE submissions SET tracking_id = ? WHERE id = ?", (tracking_id, sid))
        conn.execute(
            "INSERT INTO status_history (submission_id, status, note) VALUES (?,?,?)",
            (sid, "SUBMITTED", "Request received by E-Cycle."),
        )
        conn.commit()
        return jsonify({
            "tracking_id": tracking_id,
            "recommendation": recommendation,
            "status": "SUBMITTED",
            "linked_to_account": user is not None,
        }), 201

    @app.get("/api/submissions/mine")
    @login_required
    def my_submissions():
        uid = current_user()["id"]
        rows = get_db().execute(
            "SELECT tracking_id, category, device_name, quantity, device_condition,"
            " recommendation, status, created_at FROM submissions"
            " WHERE user_id = ? ORDER BY id DESC LIMIT 100", (uid,)
        ).fetchall()
        total, processed = get_db().execute(
            "SELECT COUNT(*), COALESCE(SUM(status = 'PROCESSED'), 0) FROM submissions WHERE user_id = ?",
            (uid,)).fetchone()
        return jsonify({
            "stats": {
                "total": total,
                "active": total - processed,
                "completed": processed,
                # Prototype showed a "Certificates" tile. No certificate feature
                # exists yet, so this counts items eligible for one (processed).
                "certificates": processed,
            },
            "submissions": [dict(r) for r in rows],
        })

    @app.get("/api/track/<tracking_id>")
    def track(tracking_id):
        tid = tracking_id.strip().upper()
        if not TRACKING_RE.match(tid):
            raise ApiError("Tracking ID looks like EC-2026-0001", 400)
        conn = get_db()
        s = conn.execute(
            "SELECT id, tracking_id, category, device_name, quantity, recommendation, status, created_at"
            " FROM submissions WHERE tracking_id = ?", (tid,)).fetchone()
        if not s:
            raise ApiError("No submission found with that tracking ID", 404)
        history_rows = conn.execute(
            "SELECT status, note, created_at FROM status_history "
            "WHERE submission_id = ? ORDER BY id ASC", (s["id"],)
        ).fetchall()
        reached = {r["status"]: r["created_at"] for r in history_rows}
        # Public tracking includes operational notes only; it never exposes owner,
        # email, phone, street address, or the submission's private description.
        history = [{"status": r["status"], "note": r["note"], "at": r["created_at"]}
                   for r in history_rows]
        stages = []
        for key in rules.STATUS_FLOW:
            label, desc = rules.STAGES[key]
            stages.append({"key": key, "label": label, "description": desc,
                           "done": key in reached, "at": reached.get(key)})
        # Deliberately NOT returned: owner, location, description (personal data).
        return jsonify({
            "tracking_id": s["tracking_id"], "category": s["category"],
            "device_name": s["device_name"], "quantity": s["quantity"],
            "recommendation": s["recommendation"], "status": s["status"],
            "submitted_at": s["created_at"], "stages": stages, "history": history,
        })

    # ------------------------------------------------------------------ drives
    def drive_json(r, today):
        return {
            "id": r["id"], "title": r["title"], "location": r["location"],
            "drive_date": r["drive_date"], "description": r["description"],
            "participants": r["participants"], "joined": bool(r["joined"]),
            "status": "UPCOMING" if r["drive_date"] >= today else "COMPLETED",
        }

    @app.get("/api/drives")
    def list_drives():
        uid = current_user()["id"] if current_user() else -1
        today = date.today().isoformat()
        rows = get_db().execute(
            "SELECT d.*, (SELECT COUNT(*) FROM drive_participants p WHERE p.drive_id = d.id) AS participants,"
            " EXISTS(SELECT 1 FROM drive_participants p WHERE p.drive_id = d.id AND p.user_id = ?) AS joined"
            " FROM drives d ORDER BY d.drive_date", (uid,)).fetchall()
        drives = [drive_json(r, today) for r in rows]
        upcoming = [x for x in drives if x["status"] == "UPCOMING"]
        past = [x for x in drives if x["status"] == "COMPLETED"][::-1]
        return jsonify({"drives": upcoming + past})

    @app.post("/api/drives/<int:drive_id>/join")
    @login_required
    def join_drive(drive_id):
        conn = get_db()
        d = conn.execute("SELECT * FROM drives WHERE id = ?", (drive_id,)).fetchone()
        if not d:
            raise ApiError("Drive not found", 404)
        if d["drive_date"] < date.today().isoformat():
            raise ApiError("This drive has already taken place", 400)
        try:
            conn.execute("INSERT INTO drive_participants (drive_id, user_id) VALUES (?,?)",
                         (drive_id, current_user()["id"]))
            conn.commit()
        except sqlite3.IntegrityError:
            raise ApiError("You have already joined this drive", 409)
        return jsonify({"message": "Joined"}), 201

    # ------------------------------------------------------------------ impact
    @app.get("/api/impact")
    def impact():
        conn = get_db()
        one = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
        dist = {r["recommendation"]: r["n"] for r in conn.execute(
            "SELECT recommendation, COUNT(*) AS n FROM submissions GROUP BY recommendation")}
        return jsonify({
            "total_submissions": one("SELECT COUNT(*) FROM submissions"),
            "collected_items": one(
                "SELECT COALESCE(SUM(quantity),0) FROM submissions WHERE status IN ('COLLECTED','PROCESSED')"),
            "community_participants": one("SELECT COUNT(DISTINCT user_id) FROM drive_participants"),
            "completed_drives": one("SELECT COUNT(*) FROM drives WHERE drive_date < ?",
                                    date.today().isoformat()),
            "distribution": {
                "reuse": dist.get(rules.RECOMMENDATIONS["working"], 0),
                "repair": dist.get(rules.RECOMMENDATIONS["partially_working"], 0),
                "recycle": dist.get(rules.RECOMMENDATIONS["non_working"], 0),
                "specialized": dist.get(rules.SPECIALIZED, 0),
            },
        })

    # ------------------------------------------------------------------- admin
    @app.get("/api/admin/submissions")
    @admin_required
    def admin_list():
        status = request.args.get("status")
        sql = ("SELECT s.tracking_id, s.category, s.device_name, s.quantity, s.device_condition,"
               " s.battery_damaged, s.location, s.recommendation, s.status, s.created_at,"
               " u.email AS owner_email FROM submissions s LEFT JOIN users u ON u.id = s.user_id")
        args = ()
        if status:
            if status not in rules.STATUS_FLOW:
                raise ApiError("Unknown status filter")
            sql += " WHERE s.status = ?"
            args = (status,)
        rows = get_db().execute(sql + " ORDER BY s.id DESC LIMIT 200", args).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["next_status"] = rules.next_status(r["status"])
            out.append(item)
        return jsonify({"submissions": out, "flow": rules.STATUS_FLOW})

    @app.patch("/api/admin/submissions/<tracking_id>/status")
    @admin_required
    def admin_set_status(tracking_id):
        d = body()
        new = d.get("status")
        note = text(d, "note", "Note", 1, 300, required=False)
        conn = get_db()
        s = conn.execute("SELECT id, status FROM submissions WHERE tracking_id = ?",
                         (tracking_id.strip().upper(),)).fetchone()
        if not s:
            raise ApiError("Submission not found", 404)
        if new not in rules.STATUS_FLOW:
            raise ApiError("Unknown status", field="status")
        expected = rules.next_status(s["status"])
        if new != expected:
            raise ApiError(
                f"Status can only move from {s['status']} to {expected}" if expected
                else f"Submission is already {s['status']} (final)", 409)
        label_note = note or rules.STAGES[new][1]
        conn.execute("UPDATE submissions SET status = ?, updated_at = ? WHERE id = ?",
                     (new, now_iso(), s["id"]))
        conn.execute("INSERT INTO status_history (submission_id, status, note) VALUES (?,?,?)",
                     (s["id"], new, label_note))
        conn.commit()
        return jsonify({"tracking_id": tracking_id.upper(), "status": new})

    @app.post("/api/admin/drives")
    @admin_required
    def admin_create_drive():
        d = body()
        title = text(d, "title", "Title", 3, 150)
        location = text(d, "location", "Location", 2, 200)
        description = text(d, "description", "Description", 1, 1000, required=False)
        raw_date = d.get("drive_date")
        if not isinstance(raw_date, str):
            raise ApiError("drive_date must look like 2026-12-31", field="drive_date")
        try:
            when = date.fromisoformat(raw_date)
        except ValueError:
            raise ApiError("drive_date must look like 2026-12-31", field="drive_date")
        if when < date.today():
            raise ApiError("New community drives must be scheduled for today or later", field="drive_date")
        cur = get_db().execute(
            "INSERT INTO drives (title, location, drive_date, description) VALUES (?,?,?,?)",
            (title, location, when.isoformat(), description))
        get_db().commit()
        return jsonify({"id": cur.lastrowid}), 201

    # --------------------------------------------------------- operations
    @app.get("/api/pickup-slots")
    def pickup_slots():
        area = request.args.get("area", "").strip()
        from_date = request.args.get("from", date.today().isoformat())
        sql = "SELECT id, partner_name, service_area, slot_date, start_time, end_time, capacity, booked FROM pickup_slots WHERE slot_date >= ? AND booked < capacity"
        args = [from_date]
        if area:
            sql += " AND lower(service_area) = lower(?)"
            args.append(area)
        rows = get_db().execute(sql + " ORDER BY slot_date, start_time LIMIT 100", args).fetchall()
        return jsonify({"slots": [dict(r) for r in rows]})

    @app.post("/api/admin/pickup-slots")
    @admin_required
    def create_pickup_slot():
        d = body()
        partner = text(d, "partner_name", "Partner name", 2, 150)
        area = text(d, "service_area", "Service area", 2, 100)
        raw_date = d.get("slot_date")
        if not isinstance(raw_date, str):
            raise ApiError("slot_date must be YYYY-MM-DD", field="slot_date")
        try: when = date.fromisoformat(raw_date)
        except ValueError: raise ApiError("slot_date must be YYYY-MM-DD", field="slot_date")
        if when < date.today(): raise ApiError("Pickup slots cannot be in the past", field="slot_date")
        start = text(d, "start_time", "Start time", 4, 5)
        end = text(d, "end_time", "End time", 4, 5)
        capacity = d.get("capacity")
        if not isinstance(capacity, int) or not 1 <= capacity <= 500:
            raise ApiError("Capacity must be a whole number from 1 to 500", field="capacity")
        try:
            cur = get_db().execute("INSERT INTO pickup_slots (partner_name, service_area, slot_date, start_time, end_time, capacity) VALUES (?,?,?,?,?,?)", (partner, area, raw_date, start, end, capacity))
            get_db().commit()
        except sqlite3.IntegrityError: raise ApiError("That pickup slot already exists", 409)
        return jsonify({"id": cur.lastrowid}), 201

    @app.post("/api/pickups")
    @login_required
    def book_pickup():
        d = body(); slot_id = d.get("slot_id"); tracking_id = str(d.get("tracking_id", "")).strip().upper()
        if not isinstance(slot_id, int) or not tracking_id: raise ApiError("slot_id and tracking_id are required")
        conn = get_db(); user = current_user()
        conn.execute("BEGIN IMMEDIATE")
        slot = conn.execute("SELECT * FROM pickup_slots WHERE id = ?", (slot_id,)).fetchone()
        sub = conn.execute("SELECT id, status, user_id FROM submissions WHERE tracking_id = ?", (tracking_id,)).fetchone()
        if not slot or not sub: conn.rollback(); raise ApiError("Pickup slot or submission not found", 404)
        if sub["user_id"] != user["id"]: conn.rollback(); raise ApiError("You can only book your own submission", 403)
        if sub["status"] not in ("SUBMITTED", "VERIFIED"): conn.rollback(); raise ApiError("This submission is not eligible for pickup booking", 409)
        if slot["booked"] >= slot["capacity"]: conn.rollback(); raise ApiError("That pickup slot is full", 409)
        try:
            pickup_cur = conn.execute("INSERT INTO pickups (slot_id, submission_id, user_id) VALUES (?,?,?)", (slot_id, sub["id"], user["id"]))
        except sqlite3.IntegrityError: conn.rollback(); raise ApiError("This submission already has a pickup", 409)
        conn.execute("UPDATE pickup_slots SET booked = booked + 1 WHERE id = ?", (slot_id,))
        if sub["status"] == "SUBMITTED":
            conn.execute("UPDATE submissions SET status='VERIFIED', updated_at=? WHERE id=?", (now_iso(), sub["id"]))
            conn.execute("INSERT INTO status_history (submission_id,status,note) VALUES (?,?,?)", (sub["id"], "VERIFIED", "Submission verified for pickup booking."))
        conn.execute("UPDATE submissions SET status='COLLECTION_SCHEDULED', updated_at=? WHERE id=?", (now_iso(), sub["id"]))
        conn.execute("INSERT INTO status_history (submission_id,status,note) VALUES (?,?,?)", (sub["id"], "COLLECTION_SCHEDULED", "Pickup scheduled."))
        conn.execute("INSERT INTO audit_logs (actor_user_id,action,entity_type,entity_id,metadata) VALUES (?,?,?,?,?)", (user["id"], "BOOK_PICKUP", "submission", tracking_id, json.dumps({"slot_id": slot_id})))
        conn.commit()
        return jsonify({"tracking_id": tracking_id, "status": "COLLECTION_SCHEDULED", "pickup_id": pickup_cur.lastrowid}), 201

    @app.get("/api/certificates/<token>")
    def verify_certificate(token):
        row = get_db().execute("SELECT c.certificate_no, c.issued_at, c.revoked_at, s.tracking_id, s.device_name, s.quantity, s.category FROM certificates c JOIN submissions s ON s.id=c.submission_id WHERE c.verification_token=?", (token,)).fetchone()
        if not row: raise ApiError("Certificate not found", 404)
        return jsonify({"valid": row["revoked_at"] is None, **dict(row)})

    @app.get("/api/certificates/mine")
    @login_required
    def my_certificates():
        rows = get_db().execute("SELECT c.certificate_no,c.verification_token,c.issued_at,c.revoked_at,s.tracking_id,s.device_name,s.quantity,s.category FROM certificates c JOIN submissions s ON s.id=c.submission_id WHERE s.user_id=? ORDER BY c.id DESC", (current_user()["id"],)).fetchall()
        return jsonify({"certificates": [dict(r) for r in rows]})

    @app.get("/api/pickups/mine")
    @login_required
    def my_pickups():
        rows = get_db().execute("SELECT p.id,p.status,p.created_at,s.tracking_id,s.device_name,ps.partner_name,ps.service_area,ps.slot_date,ps.start_time,ps.end_time FROM pickups p JOIN submissions s ON s.id=p.submission_id JOIN pickup_slots ps ON ps.id=p.slot_id WHERE p.user_id=? ORDER BY ps.slot_date,ps.start_time", (current_user()["id"],)).fetchall()
        return jsonify({"pickups": [dict(r) for r in rows]})

    # --------------------------------------------------------- threat reports
    REPORT_TYPES = ('Phishing website','Suspicious URL','Malicious email','Scam message','Malware','Credential theft','Impersonation','Suspicious attachment','Other')
    REPORT_STATUSES = ('SUBMITTED','UNDER_REVIEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE')

    @app.post("/api/reports")
    @login_required
    def create_report():
        d = body(); issue_type = text(d, "issue_type", "Issue type", 2, 40); title = text(d, "title", "Title", 3, 150); description = text(d, "description", "Description", 10, 4000); url = text(d, "suspicious_url", "Suspicious URL", 4, 2048, required=False); severity = str(d.get("severity", "MEDIUM")).upper()
        if issue_type not in REPORT_TYPES: raise ApiError("Choose a valid issue type", field="issue_type")
        if severity not in ("LOW","MEDIUM","HIGH","CRITICAL"): raise ApiError("Choose a valid severity", field="severity")
        if url and not re.match(r"^https?://[^\s]+$", url, re.I): raise ApiError("Enter a valid URL", field="suspicious_url")
        conn = get_db(); rid = "RPT-" + date.today().strftime("%Y%m%d") + "-" + secrets.token_hex(4).upper()
        cur = conn.execute("INSERT INTO reports (report_id,user_id,issue_type,title,description,suspicious_url,severity) VALUES (?,?,?,?,?,?,?)", (rid,current_user()["id"],issue_type,title,description,url,severity)); conn.execute("INSERT INTO audit_logs (actor_user_id,action,entity_type,entity_id) VALUES (?,?,?,?)", (current_user()["id"],"CREATE_REPORT","report",rid)); conn.commit()
        return jsonify({"report_id": rid, "status": "SUBMITTED"}), 201

    @app.get("/api/reports/mine")
    @login_required
    def my_reports():
        rows = get_db().execute("SELECT report_id,issue_type,title,severity,status,created_at,updated_at FROM reports WHERE user_id=? ORDER BY id DESC", (current_user()["id"],)).fetchall()
        return jsonify({"reports": [dict(r) for r in rows]})

    @app.get("/api/admin/reports")
    @admin_required
    def admin_reports():
        status = request.args.get("status"); severity = request.args.get("severity"); sql = "SELECT r.report_id,r.issue_type,r.title,r.description,r.suspicious_url,r.severity,r.status,r.analyst_note,r.created_at,r.updated_at,u.email AS reporter_email FROM reports r JOIN users u ON u.id=r.user_id WHERE 1=1"; args = []
        if status:
            if status not in REPORT_STATUSES: raise ApiError("Unknown report status")
            sql += " AND r.status=?"; args.append(status)
        if severity:
            if severity not in ("LOW","MEDIUM","HIGH","CRITICAL"): raise ApiError("Unknown report severity")
            sql += " AND r.severity=?"; args.append(severity)
        rows = get_db().execute(sql + " ORDER BY r.id DESC LIMIT 200", args).fetchall(); return jsonify({"reports": [dict(r) for r in rows]})

    @app.patch("/api/admin/reports/<report_id>")
    @admin_required
    def update_report(report_id):
        d = body(); status = d.get("status"); note = text(d, "analyst_note", "Analyst note", 1, 2000, required=False)
        if status not in REPORT_STATUSES: raise ApiError("Unknown report status", field="status")
        conn = get_db(); row = conn.execute("SELECT report_id FROM reports WHERE report_id=?", (report_id.upper(),)).fetchone()
        if not row: raise ApiError("Report not found", 404)
        conn.execute("UPDATE reports SET status=?, analyst_note=?, updated_at=? WHERE report_id=?", (status,note,now_iso(),report_id.upper())); conn.execute("INSERT INTO audit_logs (actor_user_id,action,entity_type,entity_id,metadata) VALUES (?,?,?,?,?)", (current_user()["id"],"UPDATE_REPORT","report",report_id.upper(),json.dumps({"status":status}))); conn.commit()
        return jsonify({"report_id": report_id.upper(), "status": status})

    @app.get("/api/admin/audit-logs")
    @admin_required
    def audit_logs():
        try: limit = min(max(int(request.args.get("limit", 50)), 1), 200)
        except ValueError: raise ApiError("limit must be a number")
        rows = get_db().execute("SELECT a.id,a.action,a.entity_type,a.entity_id,a.metadata,a.created_at,u.email AS actor_email FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.id DESC LIMIT ?", (limit,)).fetchall()
        return jsonify({"logs": [dict(r) for r in rows]})

    @app.get("/api/admin/export/submissions")
    @admin_required
    def export_submissions():
        rows = get_db().execute("SELECT s.tracking_id,s.category,s.device_name,s.quantity,s.recommendation,s.status,s.created_at,s.updated_at,u.email AS owner_email FROM submissions s LEFT JOIN users u ON u.id=s.user_id ORDER BY s.id").fetchall()
        out = io.StringIO(); writer = csv.writer(out); writer.writerow(["tracking_id","category","device_name","quantity","recommendation","status","created_at","updated_at","owner_email"])
        writer.writerows([tuple(r) for r in rows]); response = app.make_response(out.getvalue()); response.headers["Content-Type"] = "text/csv; charset=utf-8"; response.headers["Content-Disposition"] = 'attachment; filename="ecycle-submissions.csv"'; return response

    @app.post("/api/admin/certificates")
    @admin_required
    def issue_certificate():
        d = body(); tracking_id = str(d.get("tracking_id", "")).strip().upper()
        conn = get_db(); sub = conn.execute("SELECT id,status FROM submissions WHERE tracking_id=?", (tracking_id,)).fetchone()
        if not sub: raise ApiError("Submission not found", 404)
        if sub["status"] != "PROCESSED": raise ApiError("Certificates require a processed submission", 409)
        if conn.execute("SELECT 1 FROM certificates WHERE submission_id=?", (sub["id"],)).fetchone(): raise ApiError("A certificate already exists", 409)
        no = "EC-CERT-" + date.today().strftime("%Y%m%d") + "-" + secrets.token_hex(4).upper()
        token = secrets.token_urlsafe(24)
        conn.execute("INSERT INTO certificates (certificate_no,submission_id,verification_token) VALUES (?,?,?)", (no, sub["id"], token))
        conn.execute("INSERT INTO audit_logs (actor_user_id,action,entity_type,entity_id) VALUES (?,?,?,?)", (current_user()["id"], "ISSUE_CERTIFICATE", "submission", tracking_id))
        conn.commit()
        return jsonify({"certificate_no": no, "verification_token": token}), 201

    @app.post("/api/assistant/chat")
    def assistant_chat():
        d = body(); message = d.get("message")
        if not isinstance(message, str) or not message.strip() or len(message) > 4000: raise ApiError("Message must be 1-4000 characters", field="message")
        now = datetime.now(timezone.utc).timestamp(); key = request.remote_addr or "unknown"
        recent = [t for t in assistant_requests.get(key, []) if now - t < 60]
        if len(recent) >= 20: raise ApiError("AI request limit reached; try again in a minute", 429)
        recent.append(now); assistant_requests[key] = recent
        if not os.environ.get("GEMINI_API_KEY") or genai is None:
            return jsonify({"available": False, "fallback": True, "message": "E-Cycle Guide: Gemini is not configured on this deployment yet. Use guide.html for e-waste guidance, submit-ewaste.html to submit an item, operations.html for pickup and certificates, or track.html to check a tracking ID."})
        try:
            client = genai.Client(api_key=os.environ["GEMINI_API_KEY"], http_options=genai.types.HttpOptions(timeout=15000))
            assistant_prompt = """You are E-Cycle AI, the website's practical e-waste guide and navigation assistant.

Be concise, warm, safety-first, and useful. Help users identify the right E-Cycle workflow:
- submit an item: open submit-ewaste.html
- schedule a pickup: open operations.html after logging in
- track a submission: open track.html with the tracking ID
- report a suspicious issue: open report.html after logging in
- see submissions and certificates: open dashboard.html or operations.html
- learn about accepted items: open guide.html
- join a collection drive: open community.html
- understand the process: open how-it-works.html

When suggesting a page, say exactly what the user should click or enter. Ask one concise
follow-up question when needed. Give clear safety advice for swollen, leaking, hot, damaged,
or unknown batteries: do not puncture, dismantle, charge, burn, or place them in household
waste; keep them away from heat and seek qualified handling. Do not provide unsafe repair steps.

Never invent partners, slots, tracking statuses, certificates, legal approvals, statistics,
or successful actions. You may explain general guidance, but only the application backend can
confirm private records or complete a booking/report/submission. If the user asks about a
private record, tell them to sign in and use the relevant page. If the request is outside
e-waste and website navigation, say what you can help with and redirect.

User message:
""" + message.strip()
            def call_provider():
                if hasattr(client, "interactions"):
                    return client.interactions.create(model=os.environ.get("GEMINI_MODEL", "gemini-3.8-flash"), input=message.strip(), system_instruction=assistant_prompt, store=False)
                return client.models.generate_content(model=os.environ.get("GEMINI_MODEL", "gemini-3.8-flash"), contents=assistant_prompt)
            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(call_provider)
            try:
                response = future.result(timeout=12)
            except FutureTimeoutError:
                future.cancel()
                raise TimeoutError("Gemini request timed out")
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            text_value = getattr(response, "text", None) or str(response)
            return jsonify({"available": True, "message": text_value or "I could not produce a response."})
        except Exception:
            lowered = message.lower()
            if any(word in lowered for word in ("battery", "swollen", "leak", "hot", "damaged")):
                fallback = "E-Cycle Guide (Gemini temporarily unavailable): Do not puncture, dismantle, charge, burn, or place a damaged battery in household waste. Keep it away from heat and seek qualified handling. For a submission, sign in and open submit-ewaste.html."
            elif any(word in lowered for word in ("pickup", "collect", "schedule")):
                fallback = "E-Cycle Guide (Gemini temporarily unavailable): Sign in, open operations.html, choose an eligible submission, and book an available pickup slot."
            elif any(word in lowered for word in ("track", "status", "where is")):
                fallback = "E-Cycle Guide (Gemini temporarily unavailable): Open track.html and enter your E-Cycle tracking ID. Private dashboard records require sign-in."
            elif any(word in lowered for word in ("report", "phishing", "scam", "suspicious")):
                fallback = "E-Cycle Guide (Gemini temporarily unavailable): Sign in and open report.html to submit a suspicious URL, phishing site, scam, malware, or other issue."
            else:
                fallback = "E-Cycle Guide (Gemini temporarily unavailable): Use guide.html for e-waste guidance, submit-ewaste.html to submit an item, operations.html for pickup and certificates, or track.html to check a tracking ID."
            return jsonify({"available": False, "fallback": True, "message": fallback})

    # ---------------------------------------------------------- static frontend
    @app.get("/")
    def home():
        return send_from_directory(FRONTEND, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename):
        # send_from_directory refuses paths that escape FRONTEND (../ tricks).
        return send_from_directory(FRONTEND, filename)

    return app


if __name__ == "__main__":
    application = create_app()
    pw = db.seed(application.config["DB_PATH"])  # no-op if already seeded
    if pw:
        print(f"\n*** Admin account created: {os.environ.get("ECYCLE_ADMIN_EMAIL", "admin@ecycle.local")} / {pw}  (shown once) ***\n")
    # Debug mode is deliberately opt-in and should never be enabled in production.
    application.run(host=os.environ.get("ECYCLE_HOST", "127.0.0.1"),
                    port=int(os.environ.get("PORT", 5000)),
                    debug=os.environ.get("ECYCLE_DEBUG") == "1")
