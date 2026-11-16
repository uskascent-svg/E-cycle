"""Isolated, deterministic presentation data for E-Cycle.

The demo dataset deliberately uses its own tables and fictional .invalid contacts.
The nine data tables contain exactly 100 rows in total:
35 submissions, 15 pickups, 10 assignments, 5 centres, 5 facilities,
10 processing records, 10 certificates, 5 drives, and 5 notifications.
The demo_controls row is configuration, not a demo record.
"""
from datetime import datetime, timedelta, timezone


CITIES = [
    ("Mumbai", "Andheri", 19.1197, 72.8468),
    ("Pune", "Kothrud", 18.5074, 73.8077),
    ("Nashik", "College Road", 20.0059, 73.7781),
    ("Bengaluru", "Indiranagar", 12.9784, 77.6408),
    ("New Delhi", "Dwarka", 28.5921, 77.0460),
]
CATEGORIES = ("Laptop", "Mobile Phone", "Television", "Computer", "Other")
OUTCOMES = ("REUSE", "REPAIR", "REFURBISH", "MATERIAL_RECOVERY", "DISMANTLE")


def create_schema(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS demo_controls (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
        feed_running INTEGER NOT NULL DEFAULT 1 CHECK (feed_running IN (0,1)),
        feed_cursor INTEGER NOT NULL DEFAULT 0 CHECK (feed_cursor >= 0),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );
    INSERT OR IGNORE INTO demo_controls(id) VALUES (1);
    CREATE TABLE IF NOT EXISTS demo_submissions (
        id INTEGER PRIMARY KEY,
        tracking_id TEXT NOT NULL UNIQUE,
        demo_name TEXT NOT NULL,
        category TEXT NOT NULL,
        device_name TEXT NOT NULL,
        quantity INTEGER NOT NULL CHECK (quantity > 0),
        city TEXT NOT NULL,
        locality TEXT NOT NULL,
        latitude REAL NOT NULL CHECK (latitude BETWEEN -90 AND 90),
        longitude REAL NOT NULL CHECK (longitude BETWEEN -180 AND 180),
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS demo_pickups (
        id INTEGER PRIMARY KEY,
        submission_id INTEGER NOT NULL UNIQUE REFERENCES demo_submissions(id) ON DELETE CASCADE,
        scheduled_at TEXT NOT NULL,
        status TEXT NOT NULL,
        centre_id INTEGER,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS demo_assignments (
        id INTEGER PRIMARY KEY,
        submission_id INTEGER NOT NULL UNIQUE REFERENCES demo_submissions(id) ON DELETE CASCADE,
        distributor_name TEXT NOT NULL,
        status TEXT NOT NULL,
        assigned_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS demo_centres (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        city TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        status TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS demo_facilities (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        city TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        capacity INTEGER NOT NULL,
        status TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS demo_processing (
        id INTEGER PRIMARY KEY,
        submission_id INTEGER NOT NULL UNIQUE REFERENCES demo_submissions(id) ON DELETE CASCADE,
        facility_id INTEGER NOT NULL REFERENCES demo_facilities(id),
        outcome TEXT NOT NULL,
        processed_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS demo_certificates (
        id INTEGER PRIMARY KEY,
        submission_id INTEGER NOT NULL UNIQUE REFERENCES demo_submissions(id) ON DELETE CASCADE,
        certificate_no TEXT NOT NULL UNIQUE,
        verification_token TEXT NOT NULL UNIQUE,
        issued_at TEXT NOT NULL,
        watermarked INTEGER NOT NULL DEFAULT 1 CHECK (watermarked = 1)
    );
    CREATE TABLE IF NOT EXISTS demo_drives (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        city TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        drive_date TEXT NOT NULL,
        status TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS demo_notifications (
        id INTEGER PRIMARY KEY,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)


def _time(index):
    return (datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc) + timedelta(hours=index * 7)).strftime("%Y-%m-%dT%H:%M:%SZ")


def reset(conn):
    create_schema(conn)
    for table in ("demo_notifications", "demo_drives", "demo_certificates", "demo_processing", "demo_assignments", "demo_pickups", "demo_submissions", "demo_facilities", "demo_centres"):
        conn.execute("DELETE FROM " + table)
    conn.execute("UPDATE demo_controls SET enabled=1,feed_running=1,feed_cursor=0,updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=1")

    centres = [(i + 1, f"E-Cycle {city} Collection Centre", city, lat, lon, "ACTIVE") for i, (city, _, lat, lon) in enumerate(CITIES)]
    facilities = [(i + 1, f"{city} Circular Recovery Facility", city, lat + 0.012, lon + 0.009, 500 + i * 125, "VERIFIED") for i, (city, _, lat, lon) in enumerate(CITIES)]
    conn.executemany("INSERT INTO demo_centres VALUES (?,?,?,?,?,?)", centres)
    conn.executemany("INSERT INTO demo_facilities VALUES (?,?,?,?,?,?,?)", facilities)

    submissions = []
    statuses = ("SUBMITTED", "VERIFIED", "COLLECTION_SCHEDULED", "COLLECTED", "PROCESSED")
    for i in range(1, 36):
        city, locality, lat, lon = CITIES[(i - 1) % len(CITIES)]
        submissions.append((i, f"DEMO-EC-{i:04d}", f"Demo Resident {i:02d}", CATEGORIES[(i - 1) % len(CATEGORIES)], f"Demo {CATEGORIES[(i - 1) % len(CATEGORIES)]} {i:02d}", (i % 4) + 1, city, locality, lat + ((i % 5) - 2) * 0.002, lon + ((i % 4) - 2) * 0.002, statuses[(i - 1) % len(statuses)], _time(i)))
    conn.executemany("INSERT INTO demo_submissions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", submissions)

    pickups = [(i, i, _time(i + 35), "COMPLETED" if i <= 10 else ("SCHEDULED" if i <= 13 else "PENDING"), ((i - 1) % 5) + 1, _time(i)) for i in range(1, 16)]
    assignments = [(i, i, f"Demo Recycler {((i - 1) % 5) + 1:02d}", "COMPLETED" if i <= 10 else ("ACCEPTED" if i <= 13 else "OFFERED"), _time(i + 10)) for i in range(1, 11)]
    conn.executemany("INSERT INTO demo_pickups VALUES (?,?,?,?,?,?)", pickups)
    conn.executemany("INSERT INTO demo_assignments VALUES (?,?,?,?,?)", assignments)

    processing = [(i, i, ((i - 1) % 5) + 1, OUTCOMES[(i - 1) % len(OUTCOMES)], _time(i + 60)) for i in range(1, 11)]
    certificates = [(i, i, f"DEMO-CERT-{i:04d}", f"DEMO-TOKEN-{i:032d}", _time(i + 70), 1) for i in range(1, 11)]
    conn.executemany("INSERT INTO demo_processing VALUES (?,?,?,?,?)", processing)
    conn.executemany("INSERT INTO demo_certificates VALUES (?,?,?,?,?,?)", certificates)

    drives = [(i + 1, f"Demo {city} E-Waste Drive", city, lat, lon, f"2026-11-{10 + i:02d}", "COMPLETED" if i < 3 else "UPCOMING") for i, (city, _, lat, lon) in enumerate(CITIES)]
    notifications = [(i + 1, event, f"DEMO: {message}", _time(90 + i)) for i, (event, message) in enumerate((("SUBMISSION_RECEIVED", "New demonstration submission received."), ("PICKUP_SCHEDULED", "Demonstration pickup scheduled."), ("DISTRIBUTOR_ASSIGNED", "Demonstration distributor assigned."), ("PROCESSING_COMPLETED", "Demonstration recycling process completed."), ("CERTIFICATE_ISSUED", "Demonstration certificate generated.")))]
    conn.executemany("INSERT INTO demo_drives VALUES (?,?,?,?,?,?,?)", drives)
    conn.executemany("INSERT INTO demo_notifications VALUES (?,?,?,?)", notifications)
    conn.commit()
    return counts(conn)


def control(conn):
    create_schema(conn)
    return conn.execute("SELECT enabled,feed_running,feed_cursor,updated_at FROM demo_controls WHERE id=1").fetchone()


def counts(conn):
    tables = ("demo_submissions", "demo_pickups", "demo_assignments", "demo_centres", "demo_facilities", "demo_processing", "demo_certificates", "demo_drives", "demo_notifications")
    values = {table.replace("demo_", ""): conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in tables}
    values["total"] = sum(values.values())
    return values


def summary(conn):
    return {
        **counts(conn),
        "pending_requests": conn.execute("SELECT COUNT(*) FROM demo_submissions WHERE status IN ('SUBMITTED','VERIFIED','COLLECTION_SCHEDULED')").fetchone()[0],
        "completed_collections": conn.execute("SELECT COUNT(*) FROM demo_pickups WHERE status='COMPLETED'").fetchone()[0],
        "active_distributors": conn.execute("SELECT COUNT(DISTINCT distributor_name) FROM demo_assignments").fetchone()[0],
        "certificates_issued": conn.execute("SELECT COUNT(*) FROM demo_certificates").fetchone()[0],
        "category_distribution": [dict(row) for row in conn.execute("SELECT category,COUNT(*) count,SUM(quantity) quantity FROM demo_submissions GROUP BY category ORDER BY category")],
        "monthly_collection": [dict(row) for row in conn.execute("SELECT substr(created_at,1,7) month,SUM(quantity) quantity,COUNT(*) submissions FROM demo_submissions GROUP BY month ORDER BY month")],
    }


def feed(conn, advance=False):
    state = control(conn); rows = []
    for row in conn.execute("SELECT tracking_id,category,status,created_at FROM demo_submissions ORDER BY created_at DESC LIMIT 35"):
        rows.append({"event_type": "SUBMISSION_RECEIVED", "message": f"Demo submission {row['tracking_id']} received", "reference": row["tracking_id"], "status": row["status"], "category": row["category"], "created_at": row["created_at"]})
    for row in conn.execute("SELECT p.scheduled_at,p.status,s.tracking_id FROM demo_pickups p JOIN demo_submissions s ON s.id=p.submission_id ORDER BY p.scheduled_at DESC LIMIT 15"):
        rows.append({"event_type": "PICKUP_UPDATE", "message": f"Demo pickup {row['status'].lower()}", "reference": row["tracking_id"], "status": row["status"], "category": "Pickup", "created_at": row["scheduled_at"]})
    for row in conn.execute("SELECT c.certificate_no,c.issued_at,s.tracking_id FROM demo_certificates c JOIN demo_submissions s ON s.id=c.submission_id ORDER BY c.issued_at DESC"):
        rows.append({"event_type": "CERTIFICATE_ISSUED", "message": "Demo certificate generated (SAMPLE)", "reference": row["certificate_no"], "status": "SAMPLE", "category": "Certificate", "created_at": row["issued_at"]})
    for row in conn.execute("SELECT a.assigned_at,a.status,a.distributor_name,s.tracking_id,s.category FROM demo_assignments a JOIN demo_submissions s ON s.id=a.submission_id"):
        rows.append({"event_type": "DISTRIBUTOR_ASSIGNED", "message": f"Demo distributor {row['distributor_name']} assigned", "reference": row["tracking_id"], "status": row["status"], "category": row["category"], "created_at": row["assigned_at"]})
    for row in conn.execute("SELECT p.scheduled_at,s.tracking_id,s.category FROM demo_pickups p JOIN demo_submissions s ON s.id=p.submission_id WHERE p.status='COMPLETED'"):
        rows.append({"event_type": "COLLECTION_COMPLETED", "message": "Demo collection completed", "reference": row["tracking_id"], "status": "COMPLETED", "category": row["category"], "created_at": row["scheduled_at"]})
    for row in conn.execute("SELECT p.processed_at,s.tracking_id,s.category,f.name FROM demo_processing p JOIN demo_submissions s ON s.id=p.submission_id JOIN demo_facilities f ON f.id=p.facility_id"):
        rows.append({"event_type": "FACILITY_INTAKE", "message": f"Demo e-waste received at {row['name']}", "reference": row["tracking_id"], "status": "RECEIVED", "category": row["category"], "created_at": row["processed_at"]})
        rows.append({"event_type": "PROCESSING_COMPLETED", "message": "Demo recycling process completed", "reference": row["tracking_id"], "status": "PROCESSED", "category": row["category"], "created_at": row["processed_at"]})
    for row in conn.execute("SELECT drive_date,title FROM demo_drives WHERE status='COMPLETED'"):
        rows.append({"event_type": "COMMUNITY_DRIVE_COMPLETED", "message": f"{row['title']} completed", "reference": "DEMO-DRIVE", "status": "COMPLETED", "category": "Community drive", "created_at": row["drive_date"] + "T12:00:00Z"})
    rows.sort(key=lambda value: value["created_at"], reverse=True)
    if advance and state["feed_running"] and rows:
        conn.execute("UPDATE demo_controls SET feed_cursor=feed_cursor+1,updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=1"); conn.commit()
    cursor = state["feed_cursor"] % max(1, len(rows))
    return {"events": rows[:100], "cursor": cursor, "running": bool(state["feed_running"]), "simulated": True, "label": "DEMO MODE — SIMULATED ACTIVITY"}


def map_data(conn):
    markers = []
    for row in conn.execute("SELECT id,name,city,latitude,longitude FROM demo_centres"):
        markers.append({"type": "collection_centre", "id": row["id"], "name": row["name"], "city": row["city"], "latitude": row["latitude"], "longitude": row["longitude"], "status": "DEMO"})
    for row in conn.execute("SELECT id,name,city,latitude,longitude FROM demo_facilities"):
        markers.append({"type": "facility", "id": row["id"], "name": row["name"], "city": row["city"], "latitude": row["latitude"], "longitude": row["longitude"], "status": "DEMO"})
    for row in conn.execute("SELECT id,title,city,latitude,longitude FROM demo_drives"):
        markers.append({"type": "community_drive", "id": row["id"], "name": row["title"], "city": row["city"], "latitude": row["latitude"], "longitude": row["longitude"], "status": "DEMO"})
    for row in conn.execute("SELECT s.id,s.tracking_id,s.city,s.latitude,s.longitude,s.status,s.category FROM demo_submissions s WHERE s.id <= 15"):
        markers.append({"type": "pickup_request", "id": row["id"], "name": row["tracking_id"], "city": row["city"], "latitude": row["latitude"], "longitude": row["longitude"], "status": row["status"], "category": row["category"]})
    for row in conn.execute("SELECT a.id,a.distributor_name,s.tracking_id,s.city,s.latitude,s.longitude,a.status FROM demo_assignments a JOIN demo_submissions s ON s.id=a.submission_id"):
        markers.append({"type": "distributor_assignment", "id": row["id"], "name": row["distributor_name"], "city": row["city"], "latitude": row["latitude"], "longitude": row["longitude"], "status": row["status"], "reference": row["tracking_id"]})
    return {"markers": markers, "simulated": True, "label": "DEMO MODE — SAMPLE LOCATIONS, NOT LIVE GPS"}


def certificate(conn, identifier):
    return conn.execute("SELECT c.certificate_no,c.verification_token,c.issued_at,s.tracking_id,s.device_name,s.category,s.quantity,f.name facility_name,p.outcome FROM demo_certificates c JOIN demo_submissions s ON s.id=c.submission_id JOIN demo_processing p ON p.submission_id=s.id JOIN demo_facilities f ON f.id=p.facility_id WHERE c.certificate_no=? OR c.verification_token=?", (identifier, identifier)).fetchone()
