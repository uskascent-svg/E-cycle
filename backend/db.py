"""SQLite helpers: connection per request, schema creation, first-run seed data."""
import os
import secrets
import sqlite3
from datetime import date, timedelta
from pathlib import Path

from werkzeug.security import generate_password_hash

BASE = Path(__file__).resolve().parent
DEFAULT_DB = BASE / "data" / "ecycle.db"


def connect(db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")   # SQLite ignores FKs unless asked
    conn.execute("PRAGMA journal_mode = WAL")  # readers don't block the writer
    return conn


def init_schema(db_path) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        conn.executescript((BASE / "schema.sql").read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()


def seed(db_path):
    """Add starter drives (if none) and an admin account (if none).

    Returns the generated admin password if one was created, else None.
    Drive dates are relative to today so the demo always has upcoming drives.
    """
    conn = connect(db_path)
    generated = None
    try:
        if conn.execute("SELECT COUNT(*) FROM drives").fetchone()[0] == 0:
            today = date.today()
            conn.executemany(
                "INSERT INTO drives (title, location, drive_date, description) VALUES (?,?,?,?)",
                [
                    ("Campus E-Waste Drive", "College Campus",
                     (today + timedelta(days=14)).isoformat(),
                     "Bring eligible e-waste to the campus collection point."),
                    ("Community Collection Day", "Community Centre",
                     (today + timedelta(days=21)).isoformat(),
                     "Neighbourhood collection day open to everyone."),
                ],
            )
        if conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] == 0:
            password = os.environ.get("ECYCLE_ADMIN_PASSWORD")
            if not password:
                password = generated = secrets.token_urlsafe(9)
            conn.execute(
                "INSERT INTO users (name, email, phone, password_hash, address, role) "
                "VALUES (?,?,?,?,?,'admin')",
                ("E-Cycle Admin", os.environ.get("ECYCLE_ADMIN_EMAIL", "admin@ecycle.local"),
                 "0000000000", generate_password_hash(password), "E-Cycle HQ"),
            )
            if not generated:
                generated = "(value of ECYCLE_ADMIN_PASSWORD)"
        conn.commit()
    finally:
        conn.close()
    return generated
