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
cookies, runs Gunicorn, checks `/api/health`, and mounts persistent storage for the
SQLite database. Render service deployment still requires a connected Git repository
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
