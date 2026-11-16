"""Explicit admin password maintenance command.

Usage requires private environment variables:
    ECYCLE_ADMIN_EMAIL=admin@example.com
    ECYCLE_ADMIN_PASSWORD=<new password>
    python reset_admin.py

This command updates an existing admin only. It never prints the password,
creates a default credential, deletes records, or changes non-admin users.
"""
import os
from pathlib import Path

from werkzeug.security import generate_password_hash

import db


email = os.environ.get("ECYCLE_ADMIN_EMAIL", "").strip().lower()
password = os.environ.get("ECYCLE_ADMIN_PASSWORD", "")
if not email or not password:
    raise SystemExit("Set ECYCLE_ADMIN_EMAIL and ECYCLE_ADMIN_PASSWORD privately before running this command.")
if len(password) < 12 or len(password) > 128:
    raise SystemExit("ECYCLE_ADMIN_PASSWORD must be 12-128 characters.")

db_path = os.environ.get("ECYCLE_DB", str(db.DEFAULT_DB))
conn = db.connect(Path(db_path))
try:
    row = conn.execute("SELECT id FROM users WHERE lower(email)=? AND role='admin'", (email,)).fetchone()
    if not row:
        raise SystemExit("No existing admin account matched ECYCLE_ADMIN_EMAIL; no changes made.")
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password), row["id"]))
    conn.commit()
finally:
    conn.close()

print("Admin password updated for the existing account.")
