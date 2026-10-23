"""Create the database, starter drives and the admin account.

    python init_db.py

Optional environment variables:
    ECYCLE_DB              path of the database file
    ECYCLE_ADMIN_EMAIL     default admin@ecycle.local
    ECYCLE_ADMIN_PASSWORD  if unset, a random password is generated and printed once
"""
import os
from pathlib import Path

import db

path = Path(os.environ.get("ECYCLE_DB", db.DEFAULT_DB))
db.init_schema(path)
password = db.seed(path)
print(f"Database ready: {path}")
if password:
    print(f"Admin login -> email: {os.environ.get('ECYCLE_ADMIN_EMAIL', 'admin@ecycle.local')}  password: {password}")
    print("(Shown once. Change ECYCLE_ADMIN_PASSWORD before running init_db.py to choose your own.)")
else:
    print("Admin account already exists; left unchanged.")
