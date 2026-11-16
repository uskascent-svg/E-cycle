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

from flask import Flask, Response, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from google import genai
except ImportError:  # optional until GEMINI_API_KEY is configured
    genai = None

try:
    import qrcode
    from qrcode.image.svg import SvgPathImage
except ImportError:  # optional fallback keeps token tracking available
    qrcode = None
    SvgPathImage = None

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
    login_attempts = {}

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
                    suspended = get_db().execute("SELECT active FROM account_status WHERE user_id=?", (uid,)).fetchone()
                    if suspended and not suspended["active"]:
                        session.clear()
                    else:
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

    def notify(user_id, event_type, message, conn=None):
        (conn or get_db()).execute(
            "INSERT INTO notifications (user_id, event_type, message) VALUES (?,?,?)",
            (user_id, event_type, message),
        )

    def json_list(value, field):
        if not isinstance(value, list) or not value or any(not isinstance(x, str) for x in value):
            raise ApiError(f"{field} must be a non-empty list of text values", field=field)
        return json.dumps(sorted({x.strip() for x in value if x.strip()}))

    def security_event(event_type, severity="INFO", actor_user_id=None, metadata=None):
        """Record security telemetry without storing credentials or raw IP addresses."""
        raw_ip = request.remote_addr or "unknown"
        ip_hash = secrets.token_hex(16) if raw_ip == "unknown" else __import__("hashlib").sha256(raw_ip.encode()).hexdigest()[:32]
        get_db().execute(
            "INSERT INTO security_events (event_type,severity,actor_user_id,ip_hash,metadata) VALUES (?,?,?,?,?)",
            (event_type, severity, actor_user_id, ip_hash, json.dumps(metadata or {}, separators=(",", ":"))),
        )

    def award_points(user_id, submission_id, points, reason, conn=None):
        """Idempotent reward transaction; frontend values are never trusted."""
        conn = conn or get_db()
        try:
            conn.execute("INSERT INTO green_wallets(user_id,points) VALUES (?,0) ON CONFLICT(user_id) DO NOTHING", (user_id,))
            conn.execute("INSERT INTO green_transactions(user_id,submission_id,points,reason) VALUES (?,?,?,?)", (user_id, submission_id, points, reason))
            conn.execute("UPDATE green_wallets SET points=points+?,updated_at=? WHERE user_id=?", (points, now_iso(), user_id))
        except sqlite3.IntegrityError:
            pass

    def score_for_distributor(distributor_id):
        conn = get_db()
        row = conn.execute("""SELECT
            SUM(CASE WHEN status='COMPLETED' THEN 1 ELSE 0 END) completed,
            SUM(CASE WHEN status='COMPLETED' AND pickup_date >= date(created_at) THEN 1 ELSE 0 END) on_time,
            SUM(CASE WHEN status='RESCHEDULE_REQUESTED' OR status='FAILED' THEN 1 ELSE 0 END) delayed,
            SUM(CASE WHEN status='CANCELLED' THEN 1 ELSE 0 END) cancelled
            FROM assignments WHERE distributor_id=?""", (distributor_id,)).fetchone()
        completed = row["completed"] or 0; on_time = row["on_time"] or 0; delayed = row["delayed"] or 0; cancelled = row["cancelled"] or 0
        score = round(max(0, min(100, (on_time * 100 + completed * 10 - delayed * 15 - cancelled * 20) / max(1, completed + delayed + cancelled))), 2)
        formula = "on_time*100 + completed*10 - delayed*15 - cancelled*20, normalized to 0-100"
        conn.execute("""INSERT INTO distributor_scores(distributor_id,completed,on_time,delayed,cancelled,score,formula,updated_at)
            VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(distributor_id) DO UPDATE SET completed=excluded.completed,on_time=excluded.on_time,delayed=excluded.delayed,cancelled=excluded.cancelled,score=excluded.score,formula=excluded.formula,updated_at=excluded.updated_at""",
            (distributor_id, completed, on_time, delayed, cancelled, score, formula, now_iso()))
        return {"completed": completed, "on_time": on_time, "delayed": delayed, "cancelled": cancelled, "score": score, "formula": formula}

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
        now = datetime.now(timezone.utc).timestamp()
        source = request.remote_addr or "unknown"
        recent = [t for t in login_attempts.get(source, []) if now - t < 300]
        if len(recent) >= 10:
            security_event("LOGIN_RATE_LIMIT", "HIGH", metadata={"window_seconds": 300})
            get_db().commit()
            raise ApiError("Too many login attempts; try again in a few minutes", 429)
        recent.append(now)
        login_attempts[source] = recent
        row = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        ok = check_password_hash(row["password_hash"] if row else _DUMMY_HASH, password)
        if not (row and ok):
            security_event("LOGIN_FAILURE", "MEDIUM", metadata={"email_present": bool(email)})
            get_db().commit()
            raise ApiError("Invalid email or password", 401)
        session.clear()
        session.permanent = True
        session["user_id"] = row["id"]
        login_attempts.pop(source, None)
        security_event("LOGIN_SUCCESS", "INFO", row["id"])
        get_db().commit()
        return jsonify({"user": user_json(row)})

    @app.post("/api/auth/logout")
    def logout():
        user = current_user()
        session.clear()
        if user is not None:
            security_event("LOGOUT", "INFO", user["id"])
            get_db().commit()
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
        qr_token = "QR-" + secrets.token_urlsafe(18)
        conn.execute("INSERT INTO qr_tracking (submission_id,token) VALUES (?,?)", (sid, qr_token))
        if user:
            award_points(user["id"], sid, 10, "Submission received", conn)
        conn.commit()
        return jsonify({
            "tracking_id": tracking_id,
            "recommendation": recommendation,
            "status": "SUBMITTED",
            "linked_to_account": user is not None,
            "qr_token": qr_token,
            "qr_url": request.host_url.rstrip("/") + "/api/qr/" + qr_token,
            "qr_image_url": request.host_url.rstrip("/") + "/api/qr-image/" + qr_token + ".svg",
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
        collected = one("SELECT COALESCE(SUM(quantity),0) FROM submissions WHERE status IN ('COLLECTED','PROCESSED')")
        recovery_rate = float(os.environ.get("ECYCLE_ESTIMATED_RECOVERY_RATE", "0.70"))
        co2_factor = float(os.environ.get("ECYCLE_ESTIMATED_CO2_KG_PER_ITEM", "12"))
        return jsonify({
            "total_submissions": one("SELECT COUNT(*) FROM submissions"),
            "collected_items": collected,
            "estimated_material_recovery": round(collected * recovery_rate, 2),
            "estimated_landfill_diversion": collected,
            "estimated_co2e_savings_kg": round(collected * co2_factor, 2),
            "estimate_assumptions": {
                "recovery_rate": recovery_rate,
                "co2_kg_per_item": co2_factor,
                "warning": "Planning estimates only; replace with verified weight-based lifecycle factors before public claims."
            },
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

    # ----------------------------------------------- distributors and workflow
    @app.get("/api/admin/overview")
    @admin_required
    def admin_overview():
        conn = get_db()
        count = lambda sql: conn.execute(sql).fetchone()[0]
        return jsonify({
            "users": count("SELECT COUNT(*) FROM users WHERE role='user'"),
            "pending_submissions": count("SELECT COUNT(*) FROM submissions WHERE status IN ('SUBMITTED','VERIFIED')"),
            "active_assignments": count("SELECT COUNT(*) FROM assignments WHERE status IN ('OFFERED','ACCEPTED','RESCHEDULE_REQUESTED')"),
            "scheduled_today": conn.execute("SELECT COUNT(*) FROM assignments WHERE pickup_date=? AND status NOT IN ('CANCELLED','FAILED','COMPLETED')", (date.today().isoformat(),)).fetchone()[0],
            "collected_items": conn.execute("SELECT COALESCE(SUM(quantity),0) FROM submissions WHERE status IN ('COLLECTED','PROCESSED')").fetchone()[0],
            "processing_items": count("SELECT COUNT(*) FROM submissions WHERE status='COLLECTED'"),
            "completed_items": count("SELECT COUNT(*) FROM submissions WHERE status='PROCESSED'"),
            "verified_distributors": count("SELECT COUNT(*) FROM distributors WHERE verification_status='VERIFIED' AND status='ACTIVE'"),
            "verified_facilities": count("SELECT COUNT(*) FROM facilities WHERE verification_status='VERIFIED'"),
        })

    # ------------------------------------------------------- platform upgrade API
    @app.get("/api/admin/summary")
    @admin_required
    def admin_summary():
        conn = get_db(); count = lambda sql, args=(): conn.execute(sql, args).fetchone()[0]
        monthly = conn.execute("SELECT substr(created_at,1,7) month, COALESCE(SUM(quantity),0) quantity FROM submissions GROUP BY month ORDER BY month DESC LIMIT 12").fetchall()
        return jsonify({
            "users": count("SELECT COUNT(*) FROM users WHERE role='user'"),
            "submissions": count("SELECT COUNT(*) FROM submissions"),
            "pending": count("SELECT COUNT(*) FROM submissions WHERE status IN ('SUBMITTED','VERIFIED')"),
            "approved": count("SELECT COUNT(*) FROM submissions WHERE status NOT IN ('SUBMITTED', 'PROCESSED')"),
            "completed_pickups": count("SELECT COUNT(*) FROM pickups WHERE status='COMPLETED'") + count("SELECT COUNT(*) FROM assignments WHERE status='COMPLETED'"),
            "distributors": count("SELECT COUNT(*) FROM distributors WHERE status='ACTIVE'"),
            "facilities": count("SELECT COUNT(*) FROM facilities WHERE verification_status='VERIFIED'"),
            "collected_quantity": conn.execute("SELECT COALESCE(SUM(quantity),0) FROM submissions WHERE status IN ('COLLECTED','PROCESSED')").fetchone()[0],
            "unread_security": count("SELECT COUNT(*) FROM security_events WHERE severity IN ('HIGH','CRITICAL') AND created_at >= datetime('now','-30 days')"),
            "monthly": [dict(r) for r in monthly],
        })

    @app.get("/api/admin/users")
    @admin_required
    def admin_users():
        q = request.args.get("q", "").strip()
        try:
            limit = min(max(int(request.args.get("limit", 50)), 1), 200)
        except ValueError:
            raise ApiError("limit must be a whole number", field="limit")
        rows = get_db().execute("SELECT id,name,email,phone,address,role,created_at FROM users WHERE name LIKE ? OR email LIKE ? ORDER BY id DESC LIMIT ?", (f"%{q}%", f"%{q}%", limit)).fetchall()
        return jsonify({"users": [dict(r) for r in rows]})

    @app.patch("/api/admin/users/<int:user_id>")
    @admin_required
    def admin_update_user(user_id):
        d = body(); fields=[]; args=[]
        if "role" in d:
            if d["role"] not in ("user", "admin"): raise ApiError("Invalid role", field="role")
            fields.append("role=?"); args.append(d["role"])
        if "active" in d:
            if not isinstance(d["active"], bool): raise ApiError("active must be boolean", field="active")
            get_db().execute("INSERT INTO account_status(user_id,active,updated_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET active=excluded.active,updated_at=?", (user_id, int(d["active"]), now_iso()))
        if not fields and "active" not in d: raise ApiError("No changes supplied")
        if fields:
            args.append(user_id); cur=get_db().execute("UPDATE users SET " + ",".join(fields) + " WHERE id=?", args)
            if not cur.rowcount: raise ApiError("User not found",404)
        security_event("ADMIN_USER_UPDATE", "MEDIUM", current_user()["id"], {"user_id": user_id, "fields": [f.split('=')[0] for f in fields]})
        get_db().commit(); return jsonify({"updated": True, "user_id": user_id})

    @app.get("/api/admin/security-events")
    @admin_required
    def admin_security_events():
        severity=request.args.get("severity", ""); params=[]; where=""
        if severity:
            where="WHERE s.severity=?"; params.append(severity)
        rows=get_db().execute("SELECT s.id,s.event_type,s.severity,s.metadata,s.created_at,u.email actor_email FROM security_events s LEFT JOIN users u ON u.id=s.actor_user_id " + where + " ORDER BY s.id DESC LIMIT 200", params).fetchall()
        return jsonify({"events": [dict(r) for r in rows]})

    @app.get("/api/admin/analytics")
    @admin_required
    def admin_analytics():
        conn=get_db(); rows=conn.execute("SELECT substr(created_at,1,7) month, SUM(quantity) quantity, COUNT(*) submissions FROM submissions GROUP BY month ORDER BY month").fetchall()
        values=[r["quantity"] or 0 for r in rows]; forecast=round(sum(values[-3:])/max(1,len(values[-3:])),2) if values else 0
        return jsonify({"actual": [dict(r) for r in rows], "forecast": {"next_month_quantity": forecast, "method": "three-month moving average", "based_on_months": min(3,len(values)), "is_estimate": True}})

    @app.get("/api/admin/collection-map")
    @admin_required
    def admin_collection_map():
        rows=get_db().execute("SELECT tracking_id,location,status,quantity,created_at FROM submissions WHERE location IS NOT NULL ORDER BY id DESC LIMIT 500").fetchall()
        return jsonify({"coordinates_available": False, "privacy_note": "Exact coordinates are not collected; locations are shown as operational text.", "locations": [dict(r) for r in rows]})

    @app.get("/api/qr/<token>")
    def public_qr_tracking(token):
        row=get_db().execute("SELECT s.tracking_id,s.device_name,s.category,s.quantity,s.status,s.recommendation FROM qr_tracking q JOIN submissions s ON s.id=q.submission_id WHERE q.token=?", (token,)).fetchone()
        if not row: raise ApiError("QR tracking code not found",404)
        return jsonify({"valid": True, **dict(row), "public_safe": True})

    @app.get("/api/qr-image/<token>.svg")
    def public_qr_svg(token):
        row = get_db().execute("SELECT token FROM qr_tracking WHERE token=?", (token,)).fetchone()
        if not row: raise ApiError("QR tracking code not found", 404)
        if qrcode is None or SvgPathImage is None:
            raise ApiError("QR image generation is unavailable; use the tracking URL", 503)
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
        qr.add_data(request.host_url.rstrip("/") + "/api/qr/" + token)
        qr.make(fit=True)
        image = qr.make_image(image_factory=SvgPathImage)
        stream = io.BytesIO()
        image.save(stream)
        return Response(stream.getvalue(), mimetype="image/svg+xml")

    @app.get("/api/rewards/mine")
    @login_required
    def rewards_mine():
        uid=current_user()["id"]; conn=get_db(); wallet=conn.execute("SELECT points FROM green_wallets WHERE user_id=?",(uid,)).fetchone()
        rows=conn.execute("SELECT points,reason,created_at FROM green_transactions WHERE user_id=? ORDER BY id DESC LIMIT 100",(uid,)).fetchall()
        return jsonify({"points": wallet["points"] if wallet else 0, "transactions": [dict(r) for r in rows]})

    @app.get("/api/admin/distributor-scores")
    @admin_required
    def admin_distributor_scores():
        rows=get_db().execute("SELECT d.id,d.service_area,u.name,u.email FROM distributors d JOIN users u ON u.id=d.user_id ORDER BY d.id").fetchall()
        scores=[]
        for row in rows:
            score=score_for_distributor(row["id"]); scores.append({**dict(row), **score})
        get_db().commit(); return jsonify({"scores": scores})

    @app.post("/api/admin/inventory")
    @admin_required
    def admin_inventory_update():
        d=body(); facility_id=d.get("facility_id"); category=text(d,"category","Category",2,60); quantity=d.get("quantity",0); weight=d.get("weight_kg",0); status=d.get("status","RECEIVED")
        if not isinstance(facility_id,int) or not get_db().execute("SELECT id FROM facilities WHERE id=?",(facility_id,)).fetchone(): raise ApiError("Facility not found",404)
        if isinstance(quantity,bool) or not isinstance(quantity,int) or quantity<0: raise ApiError("quantity must be a non-negative integer",field="quantity")
        if isinstance(weight,bool) or not isinstance(weight,(int,float)) or weight<0: raise ApiError("weight_kg must be non-negative",field="weight_kg")
        if status not in ("RECEIVED","IN_PROCESS","PROCESSED","DISPATCHED"): raise ApiError("Invalid inventory status",field="status")
        conn=get_db(); conn.execute("INSERT INTO facility_inventory(facility_id,category,quantity,weight_kg,status,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(facility_id,category,status) DO UPDATE SET quantity=excluded.quantity,weight_kg=excluded.weight_kg,updated_at=excluded.updated_at",(facility_id,category,quantity,float(weight),status,now_iso()))
        row=conn.execute("SELECT id FROM facility_inventory WHERE facility_id=? AND category=? AND status=?",(facility_id,category,status)).fetchone(); conn.execute("INSERT INTO inventory_movements(inventory_id,quantity_delta,weight_delta_kg,reason,actor_user_id) VALUES (?,?,?,?,?)",(row["id"],quantity,float(weight),"Admin inventory update",current_user()["id"])); conn.commit(); return jsonify({"updated":True,"inventory_id":row["id"]}),201

    @app.get("/api/admin/inventory")
    @admin_required
    def admin_inventory_list():
        rows=get_db().execute("SELECT i.*,f.name facility_name FROM facility_inventory i JOIN facilities f ON f.id=i.facility_id ORDER BY i.updated_at DESC").fetchall()
        return jsonify({"inventory":[dict(r) for r in rows]})

    @app.post("/api/admin/distributors")
    @admin_required
    def admin_create_distributor():
        d = body(); user_id = d.get("user_id"); email = text(d, "email", "Email", 3, 254, required=False)
        if not isinstance(user_id, int) and not email:
            raise ApiError("user_id or email is required")
        user = get_db().execute("SELECT id FROM users WHERE id=? OR lower(email)=lower(?)", (user_id or -1, email or "")).fetchone()
        if not user: raise ApiError("User account not found", 404)
        area = text(d, "service_area", "Service area", 2, 100)
        categories = json_list(d.get("supported_categories"), "supported_categories")
        capacity = d.get("capacity", 1)
        if isinstance(capacity, bool) or not isinstance(capacity, int) or not 1 <= capacity <= 10000:
            raise ApiError("Capacity must be a whole number from 1 to 10000", field="capacity")
        try:
            cur = get_db().execute("INSERT INTO distributors (user_id,service_area,supported_categories,capacity) VALUES (?,?,?,?)", (user["id"], area, categories, capacity))
            get_db().execute("INSERT INTO audit_logs (actor_user_id,action,entity_type,entity_id) VALUES (?,?,?,?)", (current_user()["id"], "CREATE_DISTRIBUTOR", "distributor", str(cur.lastrowid)))
            get_db().commit()
        except sqlite3.IntegrityError: raise ApiError("That user is already a distributor", 409)
        return jsonify({"id": cur.lastrowid, "verification_status": "PENDING", "status": "ACTIVE"}), 201

    @app.get("/api/admin/distributors")
    @admin_required
    def admin_list_distributors():
        rows = get_db().execute("SELECT d.*,u.name,u.email,u.phone FROM distributors d JOIN users u ON u.id=d.user_id ORDER BY d.id DESC").fetchall()
        out = []
        for row in rows:
            item = dict(row); item["supported_categories"] = json.loads(item["supported_categories"] or "[]"); out.append(item)
        return jsonify({"distributors": out})

    @app.patch("/api/admin/distributors/<int:distributor_id>")
    @admin_required
    def admin_update_distributor(distributor_id):
        d = body(); fields = []; args = []
        for key in ("service_area", "document_expires_at"):
            if key in d:
                fields.append(key + "=?"); args.append(text(d, key, key.replace("_", " ").title(), 2, 120))
        if "supported_categories" in d: fields.append("supported_categories=?"); args.append(json_list(d["supported_categories"], "supported_categories"))
        if "capacity" in d:
            if isinstance(d["capacity"], bool) or not isinstance(d["capacity"], int) or not 1 <= d["capacity"] <= 10000: raise ApiError("Invalid capacity", field="capacity")
            fields.append("capacity=?"); args.append(d["capacity"])
        for key, allowed in (("status", ("ACTIVE", "SUSPENDED", "INACTIVE")), ("verification_status", ("PENDING", "VERIFIED", "SUSPENDED", "EXPIRED"))):
            if key in d:
                if d[key] not in allowed: raise ApiError("Invalid " + key, field=key)
                fields.append(key + "=?"); args.append(d[key])
        if not fields: raise ApiError("No changes supplied")
        args.append(distributor_id); cur = get_db().execute("UPDATE distributors SET " + ",".join(fields) + ",updated_at=? WHERE id=?", (*args[:-1], now_iso(), args[-1]))
        if cur.rowcount == 0: raise ApiError("Distributor not found", 404)
        get_db().commit(); return jsonify({"id": distributor_id, "updated": True})

    def distributor_for_user():
        row = get_db().execute("SELECT * FROM distributors WHERE user_id=?", (current_user()["id"],)).fetchone()
        if not row: raise ApiError("Distributor access required", 403)
        if row["status"] != "ACTIVE" or row["verification_status"] != "VERIFIED": raise ApiError("Distributor account is not active and verified", 403)
        return row

    @app.get("/api/distributor/jobs")
    @login_required
    def distributor_jobs():
        distributor = distributor_for_user()
        rows = get_db().execute("SELECT a.*,s.tracking_id,s.category,s.device_name,s.quantity,s.location,s.description FROM assignments a JOIN submissions s ON s.id=a.submission_id WHERE a.distributor_id=? ORDER BY a.pickup_date,a.start_time", (distributor["id"],)).fetchall()
        return jsonify({"jobs": [dict(row) for row in rows]})

    @app.post("/api/admin/assignments")
    @admin_required
    def admin_assign():
        d = body(); tracking_id = str(d.get("tracking_id", "")).strip().upper(); distributor_id = d.get("distributor_id")
        if not tracking_id or not isinstance(distributor_id, int): raise ApiError("tracking_id and distributor_id are required")
        pickup_date = d.get("pickup_date"); start = text(d, "start_time", "Start time", 4, 5); end = text(d, "end_time", "End time", 4, 5)
        try: when = date.fromisoformat(pickup_date)
        except (TypeError, ValueError): raise ApiError("pickup_date must be YYYY-MM-DD", field="pickup_date")
        if when < date.today(): raise ApiError("Pickup date cannot be in the past", field="pickup_date")
        conn = get_db(); sub = conn.execute("SELECT * FROM submissions WHERE tracking_id=?", (tracking_id,)).fetchone(); dist = conn.execute("SELECT * FROM distributors WHERE id=?", (distributor_id,)).fetchone()
        if not sub or not dist: raise ApiError("Submission or distributor not found", 404)
        if sub["status"] not in ("VERIFIED", "SUBMITTED"): raise ApiError("Submission is not awaiting assignment", 409)
        if dist["status"] != "ACTIVE" or dist["verification_status"] != "VERIFIED": raise ApiError("Distributor must be active and verified", 409)
        try: categories = json.loads(dist["supported_categories"])
        except json.JSONDecodeError: categories = []
        if sub["category"] not in categories and "Other" not in categories: raise ApiError("Distributor does not support this category", 409)
        active = conn.execute("SELECT COUNT(*) FROM assignments WHERE distributor_id=? AND pickup_date=? AND status IN ('OFFERED','ACCEPTED','RESCHEDULE_REQUESTED')", (distributor_id, pickup_date)).fetchone()[0]
        if active >= dist["capacity"]: raise ApiError("Distributor capacity is full for that date", 409)
        try:
            cur = conn.execute("INSERT INTO assignments (submission_id,distributor_id,pickup_date,start_time,end_time,assigned_by) VALUES (?,?,?,?,?,?)", (sub["id"],distributor_id,pickup_date,start,end,current_user()["id"]))
        except sqlite3.IntegrityError: raise ApiError("Submission already has an assignment", 409)
        aid = cur.lastrowid; conn.execute("INSERT INTO assignment_history (assignment_id,actor_user_id,status,reason) VALUES (?,?,?,?)", (aid,current_user()["id"],"OFFERED","Admin assignment created."))
        if sub["status"] == "SUBMITTED": conn.execute("UPDATE submissions SET status='VERIFIED',updated_at=? WHERE id=?", (now_iso(),sub["id"])); conn.execute("INSERT INTO status_history (submission_id,status,note) VALUES (?,?,?)", (sub["id"],"VERIFIED","Admin approved the submission for assignment."))
        conn.execute("UPDATE submissions SET status='COLLECTION_SCHEDULED',updated_at=? WHERE id=?", (now_iso(),sub["id"])); conn.execute("INSERT INTO status_history (submission_id,status,note) VALUES (?,?,?)", (sub["id"],"COLLECTION_SCHEDULED","Distributor assignment scheduled."))
        notify(dist["user_id"], "ASSIGNMENT_CREATED", "A new e-waste pickup assignment is waiting for your response.", conn)
        if sub["user_id"]: notify(sub["user_id"], "PICKUP_SCHEDULED", "Your E-Cycle pickup has been scheduled.", conn)
        conn.execute("INSERT INTO audit_logs (actor_user_id,action,entity_type,entity_id,metadata) VALUES (?,?,?,?,?)", (current_user()["id"],"ASSIGN_DISTRIBUTOR","assignment",str(aid),json.dumps({"tracking_id":tracking_id,"distributor_id":distributor_id}))); conn.commit()
        return jsonify({"assignment_id": aid, "status": "OFFERED"}), 201

    @app.post("/api/distributor/assignments/<int:assignment_id>/decision")
    @login_required
    def distributor_decision(assignment_id):
        distributor = distributor_for_user(); d = body(); decision = d.get("decision"); reason = text(d, "reason", "Reason", 3, 500, required=False)
        if decision not in ("ACCEPTED", "DECLINED"): raise ApiError("decision must be ACCEPTED or DECLINED", field="decision")
        conn = get_db(); row = conn.execute("SELECT * FROM assignments WHERE id=? AND distributor_id=?", (assignment_id,distributor["id"])).fetchone()
        if not row: raise ApiError("Assignment not found", 404)
        if row["status"] != "OFFERED": raise ApiError("Only offered assignments can be decided", 409)
        conn.execute("UPDATE assignments SET status=?,accepted_at=?,failure_reason=?,updated_at=? WHERE id=?", (decision,now_iso() if decision=="ACCEPTED" else None,reason,now_iso(),assignment_id)); conn.execute("INSERT INTO assignment_history (assignment_id,actor_user_id,status,reason) VALUES (?,?,?,?)", (assignment_id,current_user()["id"],decision,reason)); conn.commit()
        return jsonify({"assignment_id": assignment_id, "status": decision})

    @app.post("/api/distributor/assignments/<int:assignment_id>/complete")
    @login_required
    def distributor_complete(assignment_id):
        distributor = distributor_for_user(); d = body(); qty = d.get("collected_quantity"); note = text(d, "evidence_note", "Evidence note", 5, 1000)
        if isinstance(qty, bool) or not isinstance(qty, int) or qty < 0: raise ApiError("collected_quantity must be a non-negative whole number", field="collected_quantity")
        conn = get_db(); row = conn.execute("SELECT a.*,s.tracking_id,s.quantity,s.user_id,s.status FROM assignments a JOIN submissions s ON s.id=a.submission_id WHERE a.id=? AND a.distributor_id=?", (assignment_id,distributor["id"])).fetchone()
        if not row: raise ApiError("Assignment not found", 404)
        if row["status"] != "ACCEPTED": raise ApiError("Assignment must be accepted first", 409)
        if qty > row["quantity"]: raise ApiError("Collected quantity cannot exceed submitted quantity", field="collected_quantity")
        conn.execute("UPDATE assignments SET status='COMPLETED',completed_at=?,updated_at=? WHERE id=?", (now_iso(),now_iso(),assignment_id)); conn.execute("INSERT INTO assignment_history (assignment_id,actor_user_id,status,reason) VALUES (?,?,?,?)", (assignment_id,current_user()["id"],"COMPLETED",note)); conn.execute("UPDATE submissions SET status='COLLECTED',updated_at=? WHERE id=?", (now_iso(),row["submission_id"])); conn.execute("INSERT INTO status_history (submission_id,status,note) VALUES (?,?,?)", (row["submission_id"],"COLLECTED",note));
        if row["user_id"]:
            notify(row["user_id"], "PICKUP_COMPLETED", "Your e-waste pickup was recorded as completed.", conn)
            award_points(row["user_id"], row["submission_id"], 25, "Pickup completed", conn)
        score_for_distributor(distributor["id"])
        conn.commit(); return jsonify({"assignment_id": assignment_id, "tracking_id": row["tracking_id"], "status": "COLLECTED"})

    @app.get("/api/notifications/mine")
    @login_required
    def notifications_mine():
        rows = get_db().execute("SELECT id,event_type,message,read_at,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100", (current_user()["id"],)).fetchall()
        return jsonify({"notifications": [dict(row) for row in rows]})

    @app.post("/api/notifications/<int:notification_id>/read")
    @login_required
    def notification_read(notification_id):
        cur = get_db().execute("UPDATE notifications SET read_at=? WHERE id=? AND user_id=?", (now_iso(),notification_id,current_user()["id"]))
        get_db().commit()
        if cur.rowcount == 0: raise ApiError("Notification not found", 404)
        return jsonify({"id": notification_id, "read": True})

    @app.get("/api/notifications/preferences")
    @login_required
    def notification_preferences_get():
        row = get_db().execute("SELECT in_app,email FROM notification_preferences WHERE user_id=?", (current_user()["id"],)).fetchone()
        return jsonify(dict(row) if row else {"in_app": 1, "email": 0})

    @app.patch("/api/notifications/preferences")
    @login_required
    def notification_preferences_update():
        d=body()
        if any(k not in d or not isinstance(d[k], bool) for k in ("in_app", "email")):
            raise ApiError("in_app and email must be boolean values")
        get_db().execute("INSERT INTO notification_preferences(user_id,in_app,email,updated_at) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET in_app=excluded.in_app,email=excluded.email,updated_at=excluded.updated_at", (current_user()["id"], int(d["in_app"]), int(d["email"]), now_iso()))
        get_db().commit(); return jsonify({"in_app": int(d["in_app"]), "email": int(d["email"])})

    @app.post("/api/admin/facilities")
    @admin_required
    def admin_create_facility():
        d = body(); name = text(d, "name", "Facility name", 2, 150); area = text(d, "service_area", "Service area", 2, 100); categories = json_list(d.get("supported_categories"), "supported_categories"); capacity = d.get("capacity", 1)
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1: raise ApiError("Invalid capacity", field="capacity")
        cur = get_db().execute("INSERT INTO facilities (name,service_area,supported_categories,capacity) VALUES (?,?,?,?)", (name,area,categories,capacity)); get_db().commit(); return jsonify({"id": cur.lastrowid, "verification_status": "PENDING"}), 201

    @app.get("/api/admin/facilities")
    @admin_required
    def admin_list_facilities():
        rows = get_db().execute("SELECT * FROM facilities ORDER BY id DESC").fetchall(); out = []
        for row in rows:
            item = dict(row); item["supported_categories"] = json.loads(item["supported_categories"] or "[]"); out.append(item)
        return jsonify({"facilities": out})

    @app.patch("/api/admin/facilities/<int:facility_id>")
    @admin_required
    def admin_update_facility(facility_id):
        d = body(); status = d.get("verification_status")
        if status not in ("PENDING", "VERIFIED", "SUSPENDED", "EXPIRED"): raise ApiError("Invalid verification_status", field="verification_status")
        cur = get_db().execute("UPDATE facilities SET verification_status=?,updated_at=? WHERE id=?", (status, now_iso(), facility_id))
        if cur.rowcount == 0: raise ApiError("Facility not found", 404)
        get_db().commit(); return jsonify({"id": facility_id, "verification_status": status})

    @app.post("/api/admin/facility-intake")
    @admin_required
    def admin_facility_intake():
        d = body(); tracking_id = str(d.get("tracking_id", "")).strip().upper(); facility_id = d.get("facility_id"); qty = d.get("received_quantity"); received_at = d.get("received_at") or now_iso(); note = text(d, "discrepancy_note", "Discrepancy note", 1, 1000, required=False)
        if not tracking_id or not isinstance(facility_id, int) or isinstance(qty, bool) or not isinstance(qty, int) or qty < 0: raise ApiError("tracking_id, facility_id and received_quantity are required")
        conn = get_db(); sub = conn.execute("SELECT id,status,quantity FROM submissions WHERE tracking_id=?", (tracking_id,)).fetchone(); facility = conn.execute("SELECT id,verification_status FROM facilities WHERE id=?", (facility_id,)).fetchone()
        if not sub or not facility: raise ApiError("Submission or facility not found", 404)
        if facility["verification_status"] != "VERIFIED": raise ApiError("Facility must be verified", 409)
        if sub["status"] != "COLLECTED": raise ApiError("Only collected submissions can enter a facility", 409)
        try: conn.execute("INSERT INTO facility_intake (submission_id,facility_id,received_quantity,discrepancy_note,received_at,created_by) VALUES (?,?,?,?,?,?)", (sub["id"],facility_id,qty,note,received_at,current_user()["id"]))
        except sqlite3.IntegrityError: raise ApiError("Facility intake already recorded", 409)
        conn.execute("INSERT INTO audit_logs (actor_user_id,action,entity_type,entity_id) VALUES (?,?,?,?)", (current_user()["id"],"FACILITY_INTAKE","submission",tracking_id)); conn.commit(); return jsonify({"tracking_id": tracking_id, "received": True}), 201

    @app.post("/api/admin/processing")
    @admin_required
    def admin_processing():
        d = body(); tracking_id = str(d.get("tracking_id", "")).strip().upper(); facility_id = d.get("facility_id"); outcome = d.get("outcome"); qty = d.get("processed_quantity"); evidence = text(d, "evidence_note", "Evidence note", 5, 2000); processed_at = d.get("processed_at") or now_iso()
        if not tracking_id or not isinstance(facility_id, int) or outcome not in ("REPAIR","REUSE","REFURBISH","DISMANTLE","MATERIAL_RECOVERY","OTHER") or isinstance(qty, bool) or not isinstance(qty, int) or qty < 0: raise ApiError("Invalid processing record")
        conn = get_db(); sub = conn.execute("SELECT id,status,user_id FROM submissions WHERE tracking_id=?", (tracking_id,)).fetchone(); intake = conn.execute("SELECT 1 FROM facility_intake WHERE submission_id=? AND facility_id=?", (sub["id"],facility_id)).fetchone() if sub else None
        if not sub or not intake: raise ApiError("Collected submission must have matching facility intake", 409)
        if sub["status"] != "COLLECTED": raise ApiError("Submission is not awaiting processing", 409)
        try: conn.execute("INSERT INTO processing_records (submission_id,facility_id,outcome,processed_quantity,evidence_note,processed_at,created_by) VALUES (?,?,?,?,?,?,?)", (sub["id"],facility_id,outcome,qty,evidence,processed_at,current_user()["id"]))
        except sqlite3.IntegrityError: raise ApiError("Processing record already exists", 409)
        conn.execute("UPDATE submissions SET status='PROCESSED',updated_at=? WHERE id=?", (now_iso(),sub["id"])); conn.execute("INSERT INTO status_history (submission_id,status,note) VALUES (?,?,?)", (sub["id"],"PROCESSED", "Processing completed: " + outcome));
        if sub["user_id"]: notify(sub["user_id"], "PROCESSING_COMPLETED", "Your e-waste processing record is complete.", conn)
        conn.execute("INSERT INTO audit_logs (actor_user_id,action,entity_type,entity_id,metadata) VALUES (?,?,?,?,?)", (current_user()["id"],"PROCESSING_COMPLETED","submission",tracking_id,json.dumps({"outcome":outcome,"facility_id":facility_id}))); conn.commit(); return jsonify({"tracking_id": tracking_id, "status": "PROCESSED", "outcome": outcome}), 201

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
            client = genai.Client(api_key=os.environ["GEMINI_API_KEY"], http_options=genai.types.HttpOptions(timeout=30000))
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
                return client.models.generate_content(model=os.environ.get("GEMINI_MODEL", "gemini-3.5-flash"), contents=assistant_prompt)
            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(call_provider)
            try:
                response = future.result(timeout=30)
            except FutureTimeoutError:
                future.cancel()
                raise TimeoutError("Gemini request timed out")
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            text_value = getattr(response, "text", None) or str(response)
            return jsonify({"available": True, "message": text_value or "I could not produce a response."})
        except Exception:
            app.logger.exception("Gemini assistant provider failed")
            lowered = message.lower()
            if any(word in lowered for word in ("battery", "swollen", "leak", "hot", "damaged")):
                fallback = "E-Cycle Guide: Do not puncture, dismantle, charge, burn, or place a damaged battery in household waste. Keep it away from heat and seek qualified handling. For a submission, sign in and open submit-ewaste.html."
            elif any(word in lowered for word in ("pickup", "collect", "schedule")):
                fallback = "E-Cycle Guide: Sign in, open operations.html, choose an eligible submission, and book an available pickup slot."
            elif any(word in lowered for word in ("track", "status", "where is")):
                fallback = "E-Cycle Guide: Open track.html and enter your E-Cycle tracking ID. Private dashboard records require sign-in."
            elif any(word in lowered for word in ("report", "phishing", "scam", "suspicious")):
                fallback = "E-Cycle Guide: Sign in and open report.html to submit a suspicious URL, phishing site, scam, malware, or other issue."
            else:
                fallback = "E-Cycle Guide: Use guide.html for e-waste guidance, submit-ewaste.html to submit an item, operations.html for pickup and certificates, or track.html to check a tracking ID."
            return jsonify({"available": True, "fallback": True, "message": fallback})

    # ---------------------------------------------------------- static frontend
    @app.get("/admin/login")
    def admin_login_page():
        return send_from_directory(FRONTEND, "admin-login.html")

    @app.get("/admin/dashboard")
    def admin_dashboard_page():
        return send_from_directory(FRONTEND, "admin-dashboard.html")

    @app.get("/admin/<section>")
    def admin_section_page(section):
        if section not in {"users", "submissions", "distributors", "facilities", "pickups", "drives", "certificates", "reports", "notifications", "analytics", "security", "settings"}:
            return not_found(None)
        return send_from_directory(FRONTEND, "admin-dashboard.html")

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
