-- E-Cycle database schema (SQLite). Idempotent: safe to run on every start.
-- Column named device_condition (not "condition") because CONDITION is a
-- reserved word in MySQL; this keeps the schema portable.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    phone         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    address       TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS submissions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tracking_id      TEXT NOT NULL UNIQUE,
    user_id          INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- NULL = guest submission
    category         TEXT NOT NULL
                     CHECK (category IN ('Laptop','Mobile Phone','Television','Computer','Other')),
    device_name      TEXT NOT NULL,
    brand            TEXT,
    quantity         INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 1000),
    device_condition TEXT NOT NULL
                     CHECK (device_condition IN ('working','partially_working','non_working')),
    battery_damaged  INTEGER NOT NULL DEFAULT 0 CHECK (battery_damaged IN (0, 1)),
    location         TEXT NOT NULL,
    description      TEXT,
    recommendation   TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'SUBMITTED'
                     CHECK (status IN ('SUBMITTED','VERIFIED','COLLECTION_SCHEDULED','COLLECTED','PROCESSED')),
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_submissions_user   ON submissions(user_id);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);

-- One row per status change: this is what the Track page's timeline is built from.
CREATE TABLE IF NOT EXISTS status_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    status        TEXT NOT NULL,
    note          TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_history_submission ON status_history(submission_id);

CREATE TABLE IF NOT EXISTS drives (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    location    TEXT NOT NULL,
    drive_date  TEXT NOT NULL,            -- YYYY-MM-DD
    description TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Many-to-many between users and drives. The composite primary key makes
-- "joined twice" impossible at the database level.
CREATE TABLE IF NOT EXISTS drive_participants (
    drive_id  INTEGER NOT NULL REFERENCES drives(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    joined_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (drive_id, user_id)
);

-- Operational scheduling. Capacity is enforced transactionally by the API.
CREATE TABLE IF NOT EXISTS pickup_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    partner_name TEXT NOT NULL,
    service_area TEXT NOT NULL,
    slot_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    capacity INTEGER NOT NULL CHECK (capacity BETWEEN 1 AND 500),
    booked INTEGER NOT NULL DEFAULT 0 CHECK (booked >= 0 AND booked <= capacity),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(partner_name, service_area, slot_date, start_time, end_time)
);
CREATE INDEX IF NOT EXISTS idx_pickup_slots_date_area ON pickup_slots(slot_date, service_area);

CREATE TABLE IF NOT EXISTS pickups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot_id INTEGER NOT NULL REFERENCES pickup_slots(id),
    submission_id INTEGER NOT NULL UNIQUE REFERENCES submissions(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'CONFIRMED' CHECK(status IN ('CONFIRMED','CANCELLED','COMPLETED')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    cancelled_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_pickups_user ON pickups(user_id);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_no TEXT NOT NULL UNIQUE,
    submission_id INTEGER NOT NULL UNIQUE REFERENCES submissions(id),
    verification_token TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issue_type TEXT NOT NULL CHECK(issue_type IN ('Phishing website','Suspicious URL','Malicious email','Scam message','Malware','Credential theft','Impersonation','Suspicious attachment','Other')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    suspicious_url TEXT,
    severity TEXT NOT NULL DEFAULT 'MEDIUM' CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    status TEXT NOT NULL DEFAULT 'SUBMITTED' CHECK(status IN ('SUBMITTED','UNDER_REVIEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE')),
    analyst_note TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id);

-- Operational partner and end-to-end collection workflow. These tables extend
-- the existing SQLite deployment without changing or deleting existing data.
CREATE TABLE IF NOT EXISTS distributors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    service_area TEXT NOT NULL,
    supported_categories TEXT NOT NULL DEFAULT '[]',
    capacity INTEGER NOT NULL DEFAULT 1 CHECK (capacity BETWEEN 1 AND 10000),
    verification_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (verification_status IN ('PENDING','VERIFIED','SUSPENDED','EXPIRED')),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','INACTIVE')),
    document_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_distributors_area ON distributors(service_area, status, verification_status);

CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL UNIQUE REFERENCES submissions(id) ON DELETE CASCADE,
    distributor_id INTEGER NOT NULL REFERENCES distributors(id),
    pickup_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OFFERED' CHECK (status IN ('OFFERED','ACCEPTED','DECLINED','RESCHEDULE_REQUESTED','COMPLETED','FAILED','CANCELLED')),
    assigned_by INTEGER NOT NULL REFERENCES users(id),
    accepted_at TEXT,
    completed_at TEXT,
    failure_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_assignments_distributor ON assignments(distributor_id, status, pickup_date);

CREATE TABLE IF NOT EXISTS assignment_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_assignment_history_assignment ON assignment_history(assignment_id, created_at);

CREATE TABLE IF NOT EXISTS facilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    service_area TEXT NOT NULL,
    supported_categories TEXT NOT NULL DEFAULT '[]',
    capacity INTEGER NOT NULL DEFAULT 1 CHECK (capacity BETWEEN 1 AND 100000),
    verification_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (verification_status IN ('PENDING','VERIFIED','SUSPENDED','EXPIRED')),
    document_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS facility_intake (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL UNIQUE REFERENCES submissions(id) ON DELETE CASCADE,
    facility_id INTEGER NOT NULL REFERENCES facilities(id),
    received_quantity INTEGER NOT NULL CHECK (received_quantity >= 0),
    discrepancy_note TEXT,
    received_at TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS processing_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL UNIQUE REFERENCES submissions(id) ON DELETE CASCADE,
    facility_id INTEGER NOT NULL REFERENCES facilities(id),
    outcome TEXT NOT NULL CHECK (outcome IN ('REPAIR','REUSE','REFURBISH','DISMANTLE','MATERIAL_RECOVERY','OTHER')),
    processed_quantity INTEGER NOT NULL CHECK (processed_quantity >= 0),
    evidence_note TEXT NOT NULL,
    processed_at TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    read_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at);

-- Additive platform-upgrade tables. Existing tables and records are preserved.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS admin_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL DEFAULT 'Admin' CHECK (role_name IN ('Super Admin','Admin','Operations Manager','Distributor Manager','Facility Manager','Read-only Auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS account_status (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS notification_preferences (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    in_app INTEGER NOT NULL DEFAULT 1 CHECK (in_app IN (0,1)),
    email INTEGER NOT NULL DEFAULT 0 CHECK (email IN (0,1)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS qr_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL UNIQUE REFERENCES submissions(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_qr_tracking_token ON qr_tracking(token);

CREATE TABLE IF NOT EXISTS green_wallets (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    points INTEGER NOT NULL DEFAULT 0 CHECK (points >= 0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS green_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    submission_id INTEGER REFERENCES submissions(id) ON DELETE SET NULL,
    points INTEGER NOT NULL CHECK (points <> 0),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(user_id, submission_id, reason)
);

CREATE TABLE IF NOT EXISTS facility_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    facility_id INTEGER NOT NULL REFERENCES facilities(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
    weight_kg REAL NOT NULL DEFAULT 0 CHECK (weight_kg >= 0),
    status TEXT NOT NULL DEFAULT 'RECEIVED' CHECK (status IN ('RECEIVED','IN_PROCESS','PROCESSED','DISPATCHED')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(facility_id, category, status)
);
CREATE INDEX IF NOT EXISTS idx_inventory_facility ON facility_inventory(facility_id, status);

CREATE TABLE IF NOT EXISTS inventory_movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inventory_id INTEGER NOT NULL REFERENCES facility_inventory(id) ON DELETE CASCADE,
    quantity_delta INTEGER NOT NULL,
    weight_delta_kg REAL NOT NULL DEFAULT 0,
    reason TEXT NOT NULL,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS environmental_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
    metric_type TEXT NOT NULL,
    value REAL NOT NULL,
    unit TEXT NOT NULL,
    assumption TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS distributor_scores (
    distributor_id INTEGER PRIMARY KEY REFERENCES distributors(id) ON DELETE CASCADE,
    completed INTEGER NOT NULL DEFAULT 0,
    on_time INTEGER NOT NULL DEFAULT 0,
    delayed INTEGER NOT NULL DEFAULT 0,
    cancelled INTEGER NOT NULL DEFAULT 0,
    score REAL NOT NULL DEFAULT 0,
    formula TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO' CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ip_hash TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at, severity);

CREATE TABLE IF NOT EXISTS collection_forecasts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    forecast_month TEXT NOT NULL,
    predicted_quantity REAL NOT NULL,
    method TEXT NOT NULL,
    based_on_months INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(forecast_month, method)
);

INSERT OR IGNORE INTO schema_migrations(version) VALUES ('2026-11-platform-upgrade');
