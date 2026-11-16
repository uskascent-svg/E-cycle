# E-Cycle — E-Waste Collection & Circular Economy Platform

A full-stack e-waste management website built with HTML, CSS and vanilla JavaScript, a Python/Flask JSON API, and SQLite. It supports device submissions, recommendations, tracking, user accounts, community collection drives, impact statistics and an admin workflow.

**For the complete page-by-page walkthrough, data flow, API list, database design and limitations, read `Explanation.md`.**

## Run it

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python init_db.py                  # creates the DB, 2 starter drives, and the admin account
python app.py                      # open http://127.0.0.1:5000
```

`init_db.py` prints the admin password once. To choose your own, set
`ECYCLE_ADMIN_PASSWORD` before running it (admin email: `admin@ecycle.local`).

Run the tests: `cd backend && python -m unittest discover -s tests -v`

> Open the site through Flask (port 5000), **not** VS Code Live Server: the
> pages call `/api/...` on the same origin.


## Improvements in this version

## Operations added in this upgrade

- Pickup slots with service areas, capacity limits, and transactional booking.
- Ownership checks prevent users from booking another user's submission.
- Audit records for pickup booking and certificate issuance.
- Server-issued processing certificates with public token verification.
- One shared E-Cycle AI launcher on every page, backed by the official `google-genai`
  SDK when `GEMINI_API_KEY` is configured; missing configuration is reported honestly.
- `.env.example` documents the required server-side secrets.

The implementation remains Flask + SQLite so the supplied project stays runnable. It
does not claim to be a Next.js/Supabase migration; that migration should be treated as
a separate project phase with schema and deployment validation.

## Current API additions

- `POST /api/reports` and `GET /api/reports/mine` for authenticated issue reports.
- `GET/PATCH /api/admin/reports` for administrator review and status changes.
- `GET /api/admin/audit-logs` for sensitive-operation review.
- `GET /api/admin/export/submissions` for an authorized CSV export.
- `GET /api/pickup-slots`, `POST /api/pickups`, and `GET /api/pickups/mine`.
- `POST /api/admin/pickup-slots` for capacity-managed collection windows.
- `POST /api/admin/certificates`, `GET /api/certificates/mine`, and public certificate verification.
- `POST /api/assistant/chat` for the single server-side Gemini assistant.

## Deployment checklist

1. Copy `.env.example` to a private environment file and set a long random
   `ECYCLE_SECRET_KEY` and a non-default admin password.
2. Back up `backend/data/ecycle.db` before schema changes or deployment.
3. Use HTTPS and set `ECYCLE_SECURE_COOKIES=1`.
4. Run behind a production WSGI server using `backend/wsgi.py`; do not expose
   Flask's development server publicly.
5. Configure `GEMINI_API_KEY` only as a server-side secret if AI is wanted.
6. Run `python -m unittest discover -s tests -v` from `backend/` before release.

The current implementation still requires a future migration for PostgreSQL/Supabase,
private object storage, email verification, password recovery, and production-grade
distributed rate limiting. These are documented limitations, not simulated features.

## Render deployment

The repository includes `render.yaml` for a Python web service. Connect the repository
to Render, create the Blueprint service, and set `GEMINI_API_KEY` as a secret in the
service environment. The Blueprint generates `ECYCLE_SECRET_KEY`, enables secure
cookies, runs Gunicorn, and checks `/api/health`. The free deployment uses ephemeral
SQLite storage; move to managed PostgreSQL before relying on persistence across
redeploys. Render service deployment still requires a connected Git repository
and Render account authorization; those are not present in this local workspace.

- Added `GET /api/health` to verify the API and database connection.
- Strictly validates `battery_damaged` as a JSON boolean; values such as `"false"` no longer accidentally trigger specialized handling.
- Added consistent API handling for malformed requests and strengthened response security headers.
- Reduced unnecessary session-cookie refreshes and improved logout error feedback/accessibility announcements.
- Expanded automated tests for the health endpoint, security headers and battery-flag validation.
- Tracking now includes a public-safe chronological journey history with operational notes and timestamps; personal contact details remain excluded.
- Admin submission queue supports status filtering and manual refresh; status changes can include an operational note.
- Admins can create community drives from the admin page, with server-side date validation that prevents scheduling new drives in the past.
- Added tests for tracking history and community-drive creation/date validation.

## Production-readiness notes

This is a practical educational project, not a fully audited production service. Before public deployment, use HTTPS, set a long random `ECYCLE_SECRET_KEY`, set `ECYCLE_SECURE_COOKIES=1`, use a production WSGI server, configure backups and monitoring, and add rate limiting/email verification/password reset if needed. The built-in Flask development server is for local development only. Never publish the generated admin password or `backend/data/.secret_key`.

## Operational workflow upgrade

The existing Flask/SQLite architecture remains the single source of business logic. The
schema now adds verified distributors, assignments and assignment history, facilities,
facility intake, processing evidence, and in-app notifications. Existing submissions,
tracking IDs, pickups, certificates, reports, drives, and audit records are preserved.

Admin workflow:

1. Create a distributor record for an existing user with `/api/admin/distributors`.
2. Verify it with `PATCH /api/admin/distributors/<id>` after reviewing documents externally.
3. Create an assignment with `POST /api/admin/assignments`; server validation checks status,
   category, service area, verification, duplicate assignments, and daily capacity.
4. Create and verify a facility, then record facility intake and processing evidence.

Distributor users sign in normally and use `distributor.html`. They can only see assignments
linked to their verified distributor record, accept or decline offers, and record collection
evidence. Users receive in-app notifications through `/api/notifications/mine`.

Important distinction: processing records are E-Cycle platform records backed by facility
intake and evidence notes. They are not statutory certificates. Certificates remain issued
only by an administrator after processing.

New protected API groups include `/api/admin/overview`, `/api/admin/distributors`,
`/api/admin/assignments`, `/api/distributor/jobs`, `/api/distributor/assignments/*`,
`/api/admin/facilities`, `/api/admin/facility-intake`, `/api/admin/processing`, and
`/api/notifications/*`.

The current deployment still uses SQLite, so Render's free ephemeral filesystem is not
suitable for durable production records. The next production migration should move these
tables and existing data to managed PostgreSQL, private object storage for evidence, and a
real email provider with retry tracking.

## Platform upgrade (November 2026)

The platform now includes an additive upgrade layer that preserves the existing API and
database records:

- Secure admin portal at `/admin/login` and `/admin/dashboard`.
- Admin summary, user search, security-event, analytics, distributor-score, inventory,
  and privacy-safe collection-map APIs.
- Submission QR tokens with public-safe tracking at `/api/qr/<token>`.
- Transactional Green Points ledger at `/api/rewards/mine`; points are awarded by the
  backend, never accepted from browser values.
- Additive tables for roles, notification preferences, QR tracking, rewards, inventory,
  environmental metrics, distributor scores, security events, forecasts, and migration
  tracking.
- Transparent three-month moving-average collection forecasts. Forecasts are labelled
  estimates and are not machine-learning predictions.
- Security telemetry for successful and failed authentication without storing passwords,
  API keys, cookies, or raw IP addresses.

The schema upgrade is additive and idempotent. It does not drop, reset, or rewrite existing
tables. The migration marker is `2026-11-platform-upgrade`; production database migration
and storage changes still require a separate backup and approval process.

New test coverage is in `backend/tests/test_upgrade.py`. Run the complete suite with:

```bash
python -m unittest discover -s backend/tests -v
```

The admin portal uses the existing Flask session plus server-side RBAC. Legacy `admin`
accounts are enrolled additively in `admin_roles` (the first bootstrap administrator is
the Super Admin). Supported roles are Super Admin, Admin, Operations Manager, Distributor
Manager, Facility Manager, and Read-only Auditor. Every admin API checks the active role
and permission on the server; frontend visibility is never treated as authorization.
`GET /api/admin/me`, `GET /api/admin/roles`, and `PATCH /api/admin/roles/<user_id>` expose
the role administration workflow, with role changes restricted to Super Admins.
`GET /api/admin/users/<user_id>` returns an authorized user activity view without any
password material. State-changing API requests also reject a mismatched Origin header.

### Admin bootstrap and password recovery

Render runs `python backend/init_db.py` as an idempotent pre-deploy command. For a new
database, set `ECYCLE_ADMIN_EMAIL` and `ECYCLE_ADMIN_PASSWORD` as private Render
environment variables before the first deploy. The initializer creates the admin only when
no admin account exists; it never resets, deletes, or overwrites an existing account.
Passwords are stored only as hashes. Deployment bootstrap never prints generated passwords
to Render or CI logs. If an existing administrator password is forgotten,
set a new value through the private Render environment and use an approved database/admin
maintenance procedure; do not place credentials in source code, logs, or chat.
For an authorized maintenance operator with access to the active database, the repository
also includes `backend/reset_admin.py`. Set `ECYCLE_ADMIN_EMAIL`, `ECYCLE_ADMIN_PASSWORD`,
and optionally `ECYCLE_DB` privately, then run `python reset_admin.py` from `backend/`.
The command updates only an existing admin account and never prints the password.

### Shared admin access code

The admin login also accepts a shared access code through the server-only
`ADMIN_ACCESS_CODE` environment variable. Render defines this variable as a private,
unsynced setting; set its value in the Render dashboard without committing it. The code
is compared with `secrets.compare_digest`, rate-limited, and exchanged for a secure admin
session. It is never embedded in `admin-login.html` or frontend JavaScript. A shared-code
session can access admin APIs only; it cannot be used as a normal user session.

### Certificates and map locations

Processing creates one E-Cycle-issued processing record automatically after a verified
facility processing operation. Certificates have unique IDs and cryptographically secure
verification tokens, public verification by ID/token, QR verification URLs, PDF downloads,
revocation with reason, and certificate audit records. They are not government-approved or
statutory environmental certifications. PDF downloads are authorized to the certificate
owner or an administrator.

`/map.html` uses Leaflet and OpenStreetMap only for authorized, consented, verified
coordinates stored in `operational_locations`. It deliberately shows an empty map when no
real coordinates exist and falls back to the operational list API. Admins can record a
coordinate through `POST /api/admin/locations`; latitude/longitude bounds and explicit
consent are required. Users and verified distributors receive only their permitted markers.
