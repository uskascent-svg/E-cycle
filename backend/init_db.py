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
    if os.environ.get("RENDER") or os.environ.get("CI"):
        print("Admin account created, but its password is intentionally not printed in deployment logs. Set ECYCLE_ADMIN_PASSWORD privately before deployment.")
    else:
        print(f"Admin login -> email: {os.environ.get('ECYCLE_ADMIN_EMAIL', 'admin@ecycle.local')}  password: {password}")
        print("(Shown once for local setup. Change ECYCLE_ADMIN_PASSWORD before any deployment.)")
else:
    print("Admin account already exists; left unchanged.")
