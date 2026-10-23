# E-Cycle: How It Works and Why It Was Built This Way

This document explains the backend and database added to your E-Cycle prototype:
what each piece does, how a request flows through the system, and the reasoning
behind every significant decision.

---

## 1. What changed, in one paragraph

Your prototype was a set of static pages whose JavaScript *pretended* to do things:
a random tracking ID in the browser, a login that accepted anything, hard-coded
dashboard and impact numbers. I kept your design and pages, and replaced the
pretending with a real **Flask (Python) backend** and a **SQLite database**.
Now accounts, submissions, tracking, drives and impact figures are stored and
calculated for real. The visible layout and styling are unchanged.

## 2. Project structure

```
E-Cycle-Full/
├── README.md              quick start
├── Explanation.md         this file
├── frontend/              your original pages (edited to call the API) + admin.html
│   ├── *.html, css/style.css
│   └── js/script.js       rewritten: fetch() calls instead of fake behaviour
└── backend/
    ├── app.py             Flask app: all API routes + serves the frontend
    ├── rules.py           recommendation rules + status lifecycle (no DB/Flask code)
    ├── db.py              DB connection, schema creation, first-run seed data
    ├── schema.sql         the database tables (SQLite)
    ├── schema.mysql.sql   reference translation for MySQL (untested, see §9)
    ├── init_db.py         one-command setup: DB + starter drives + admin account
    ├── requirements.txt   just Flask
    └── tests/test_api.py  21 automated tests
```

## 3. Architecture

```
 Browser (HTML + script.js)
        │  fetch("/api/...") with JSON, session cookie attached automatically
        ▼
 Flask app (app.py) ── validates input ── applies rules (rules.py)
        │
        ▼
 SQLite file (backend/data/ecycle.db): users, submissions, status_history,
                                       drives, drive_participants
```

Flask serves **both** the web pages and the API from one address
(`http://127.0.0.1:5000`). That means the browser treats them as the same site,
so login cookies just work and no CORS configuration is needed.

## 4. The flows, step by step

### 4.1 Register
1. User fills `register.html`; `handleRegister()` sends `POST /api/auth/register` as JSON.
2. The server checks every field: name 2-100 characters, valid email shape, phone
   10-13 digits, password 8-128 characters, address 5-500 characters.
3. The password is turned into a salted hash (`werkzeug.security`, scrypt/pbkdf2);
   **the plain password is never stored or logged**.
4. The row is inserted. The `email` column is `UNIQUE` and case-insensitive, so
   `Asha@x.com` and `asha@x.com` cannot both register. A duplicate returns HTTP 409.
5. The page shows "Account created → Login now".

### 4.2 Login / logout / staying logged in
1. `POST /api/auth/login` looks up the email and verifies the password hash.
2. On success the server stores only the user's id in a **signed session cookie**
   (`HttpOnly`, `SameSite=Lax`, 7-day lifetime) and the page redirects to the dashboard.
3. On every page load, `script.js` calls `GET /api/auth/me`. If someone is logged in,
   the navbar's Login/Register buttons become **Dashboard / Logout** (and an **Admin**
   link for admins). Logout clears the session.
4. Wrong email and wrong password return the *same* message ("Invalid email or password")
   and take about the same time, so an attacker cannot discover which emails are registered.

### 4.3 Submit e-waste (the core feature)
1. User fills `submit-ewaste.html` (logged in or not) → `POST /api/submissions`.
2. The server validates: category and condition must be from fixed lists, quantity a
   whole number 1-1000, location required, text lengths capped.
3. **The recommendation is decided on the server** by `rules.recommend()`:

   | Condition / flag               | Recommendation          |
   |--------------------------------|-------------------------|
   | Working                        | Reuse / Donate          |
   | Partially working              | Repair / Refurbish      |
   | Non-working                    | Recycle                 |
   | *Battery damaged/swollen box*  | **Specialized Handling** (overrides all of the above) |
   | Anything unexpected            | Manual Review           |

4. The row is saved with status `SUBMITTED`. A **tracking ID** like `EC-2026-0007` is
   generated from the row's own database id (see decision D4).
5. A first row is written to `status_history`, and the page shows the tracking ID,
   the recommendation, and a "Track Submission" button that opens the tracking page
   pre-filled.
6. If the user wasn't logged in, the submission has no owner (`user_id` is NULL) and
   the result page says so, suggesting they save the ID or register next time.

### 4.4 Track
1. User enters a tracking ID (or arrives from the button via `track.html?id=...`).
2. `GET /api/track/<id>` normalises it (trim, uppercase), checks its format, and looks it up.
3. The response contains the device type, quantity, recommendation, current status and
   **one entry per lifecycle stage** (done or pending, with the date it was reached),
   built from `status_history`. `script.js` draws the same dot timeline you designed.
4. The endpoint is public (the prototype's tracking worked without login) but **never
   returns personal data**: no owner, no location, no description.

The lifecycle is:
`SUBMITTED → VERIFIED → COLLECTION_SCHEDULED → COLLECTED → PROCESSED`

### 4.5 Dashboard
1. `dashboard.html` loads, then calls `GET /api/submissions/mine`.
2. If not logged in the server answers 401 and the page redirects to login.
3. Otherwise the server returns this user's submissions (newest first) and four counts,
   all calculated from the database:
   - **My Submissions**: all of the user's submissions
   - **Active Requests**: not yet `PROCESSED`
   - **Completed**: `PROCESSED`
   - **Certificates**: same as Completed, see decision D9
4. Each row links to its tracking page.

### 4.6 Community drives
1. `community.html` calls `GET /api/drives`. Each drive is marked **UPCOMING** or
   **COMPLETED** by comparing its date with today (never stored, so it can't go stale).
2. Visitors see **Login to Join**; logged-in users see **Join Drive**; after joining
   they see **Joined ✓**.
3. `POST /api/drives/<id>/join` rejects past drives (400) and double-joins (409).
   Double-joining is also impossible at the database level (composite primary key).

### 4.7 Impact page
`GET /api/impact` computes the figures live: total submissions; collected items
(sum of quantities whose status is `COLLECTED` or `PROCESSED`); participants (distinct
users who joined a drive); completed drives (drives dated before today); and the
count per recommendation. Your prototype labelled these as demo values; they are
now real. **On a fresh database they are all zero**, which is correct.

### 4.8 Admin (new)
Your prototype showed statuses like VERIFIED and COLLECTED but had no way to *change*
a status, so tracking could never progress. I added the minimum needed:
- `admin.html`: a table of all submissions, each with one button, e.g. **Mark VERIFIED**.
- `PATCH /api/admin/submissions/<id>/status` moves a submission **only to the next
  stage** and records it in `status_history`. Skipping ahead, going backwards, or
  changing a finished item returns 409.
- `POST /api/admin/drives` creates drives (API only, e.g. with `curl`).
- All `/api/admin/*` routes require the `admin` role (401 if logged out, 403 if not admin).

## 5. Database design

```
users 1───* submissions 1───* status_history
  │                 (user_id may be NULL = guest)
  └──* drive_participants *──1 drives
```

| Table | Purpose | Notable constraints |
|---|---|---|
| `users` | accounts | `email` UNIQUE NOCASE; `role` limited to user/admin; only a password *hash* |
| `submissions` | one e-waste request | `tracking_id` UNIQUE; `category`, `device_condition`, `status` restricted by CHECK; quantity 1-1000; `user_id` nullable |
| `status_history` | audit trail, powers the timeline | deleted automatically with its submission |
| `drives` | collection events | date stored as `YYYY-MM-DD` |
| `drive_participants` | who joined what | composite PK (drive_id, user_id) prevents duplicates |

The database enforces the important rules itself (CHECK constraints, UNIQUE keys,
foreign keys switched on with `PRAGMA foreign_keys`), so a bug in the Python code
still can't store a nonsense status or a duplicate account.

## 6. API reference

| Method & path | Who | Purpose |
|---|---|---|
| `POST /api/auth/register` | anyone | create account |
| `POST /api/auth/login` | anyone | start session |
| `POST /api/auth/logout` | anyone | end session |
| `GET /api/auth/me` | anyone | current user or `{"user": null}` |
| `POST /api/submissions` | anyone | submit e-waste; returns tracking ID + recommendation |
| `GET /api/submissions/mine` | logged in | dashboard stats + own submissions |
| `GET /api/track/<id>` | anyone | status timeline (no personal data) |
| `GET /api/drives` | anyone | list drives (adds `joined` if logged in) |
| `POST /api/drives/<id>/join` | logged in | join an upcoming drive |
| `GET /api/impact` | anyone | live platform totals |
| `GET /api/admin/submissions[?status=]` | admin | all submissions |
| `PATCH /api/admin/submissions/<id>/status` | admin | advance to next stage |
| `POST /api/admin/drives` | admin | create a drive |

Errors are always JSON: `{"error": "message", "field": "email"}` (`field` only for
validation errors), so the pages can show a clear message.

## 7. Design decisions and why

**D1. Flask + SQLite instead of PHP + MySQL.** Your README said PHP/MySQL was the
planned next phase. The environment I built this in has neither installed, so I could
not run or test that stack, and I did not want to hand you code I had never executed.
Flask + SQLite could be tested end to end. SQLite needs no database server, so you run
two commands instead of installing MySQL. The structure maps directly to MySQL (§9),
so nothing here blocks you from switching if your course requires it.

**D2. `frontend/` and `backend/` folders.** Flask serves the frontend, and serving a
folder that also holds `app.py` and the database file would let anyone download them.
Separate folders make that impossible. Cost: you open the site via Flask on port 5000,
not VS Code Live Server (a different port would break login cookies).

**D3. One origin for pages and API.** Avoids CORS entirely and lets the browser send the
session cookie automatically. It is also why the pages call `/api/...` with no hostname.

**D4. Tracking ID from the database row id.** The prototype used a random 4-digit number
(`EC-2026-` + 1000-9999): after only ~100 submissions a collision becomes likely, and a
collision would let two people see each other's status. Using the row id makes uniqueness
guaranteed, and it matches your placeholder `EC-2026-0001`. Trade-off: IDs are guessable,
so the track endpoint deliberately exposes no personal data (§4.4).

**D5. Recommendation logic on the server.** In the browser, anyone could edit the
JavaScript. Computed server-side, the stored recommendation is trustworthy and the rules
live in one small file (`rules.py`) that is easy to read and change.

**D6. Damaged-battery rule (small addition).** Your E-Waste Guide says a damaged or swollen
battery must not be handled by the user, but the submit form had no way to say so. I added
one checkbox. When ticked it overrides the condition-based result with "Specialized Handling".
This is the only new field on your forms.

**D7. Guest submissions allowed.** Your prototype let anyone submit without logging in, so I
kept it. Guest submissions can't be attached to an account afterwards (there is no proof of
ownership); the page tells the user this.

**D8. Strictly linear status flow.** One allowed next step keeps the data consistent and
the timeline meaningful. If your admins need to undo a mistake, that is an easy extension
(see §10), but silently allowing any jump would let the history contradict itself.

**D9. "Certificates" = processed items.** The prototype showed a Certificates tile but no
certificate feature exists. Rather than invent one or show a fake number, the tile counts
items that would be eligible (processed). If you build real certificates later, change one line.

**D10. Added a fifth stage, COLLECTED.** Your track page listed four stages but your dashboard
used COLLECTED as a status. The two disagreed, so the lifecycle now contains both.

**D11. Drive dates are relative to setup day.** Your prototype's drives were dated 20 and
27 September 2026, which are already in the past, so nobody could join them. The seed script
creates the same two drives 14 and 21 days ahead. Edit them or add your own via the admin API.

**D12. Session cookie, not tokens.** For a site where the same server serves the pages, a
signed `HttpOnly` cookie is simpler and safer than storing a token in `localStorage`, where
any injected script could read it.

**D13. Admin created by script, never by the website.** No sign-up form can create an admin.
`init_db.py` creates one; its password is random and printed once unless you set
`ECYCLE_ADMIN_PASSWORD`.

**D14. Dates and timezones.** Timestamps are stored in UTC; the browser formats them for the
viewer. Drive dates are plain dates compared with the server's local "today".

## 8. Security measures included

- Passwords hashed with a salt; same error for unknown email and wrong password.
- Every input validated on the server (the HTML `required` attributes are only a convenience).
- All database access uses **parameterised queries** (`?` placeholders), which prevents SQL injection.
- All user text is shown with `textContent`, never `innerHTML`, which prevents stored XSS.
  The browser test submitted a device named `<img src=x onerror=alert(1)>Phone`; it
  displays as literal text on the dashboard and admin pages.
- Write requests must be `application/json`, which cross-site HTML forms cannot send
  (a basic CSRF defence), plus `SameSite=Lax` cookies.
- Role checks on every admin route; users can only read their own submissions.
- Static file serving blocks `../` path tricks; request bodies are capped at 64 KB;
  responses carry `nosniff`, `X-Frame-Options: DENY`, and API replies are `no-store`.
- The session signing key comes from `ECYCLE_SECRET_KEY` or is generated once into
  `backend/data/.secret_key` (git-ignored).

## 9. Moving to PHP + MySQL later

`backend/schema.mysql.sql` is a hand-translated MySQL version of the same five tables.
**I have not run it**, so treat it as a starting point. The portable parts: the column
`device_condition` avoids the MySQL reserved word `CONDITION`, and the API contract
(§6) can be re-implemented route by route in PHP without touching the frontend.
In PHP use `password_hash()` / `password_verify()` and PDO prepared statements.

## 10. Known limitations and sensible next steps

- **No rate limiting** on login or submissions. Add Flask-Limiter before any public use.
- **No email** (verification, password reset, status notifications).
- **No pickup scheduling.** The "Request Collection" step from How It Works is represented
  only by the `COLLECTION_SCHEDULED` status; there is no date/time picker yet.
- **No certificate generation**, no pagination beyond the latest 100 (user) / 200 (admin) rows.
- **Admin UI is minimal**: status changes only; drive creation is API-only; no way to
  step a status back.
- **Guest submissions can't be claimed** by an account later.
- **Development server.** `python app.py` is for local use. For deployment use a production
  server (e.g. `gunicorn app:create_app()`), HTTPS, and set `ECYCLE_SECURE_COOKIES=1` and a
  fixed `ECYCLE_SECRET_KEY`.
- SQLite suits a college project and light traffic; heavy concurrent writes would call for
  MySQL/PostgreSQL.

## 11. How this was verified

- **21 automated tests** (`backend/tests/test_api.py`), all passing: validation, duplicate
  accounts, password hashing, login/logout, guest and logged-in submissions, per-user
  isolation, tracking privacy, the strict status flow, drive joining (duplicate, past,
  unknown), impact figures, admin-only access, and path-traversal blocking.
- **A scripted run through the real pages in headless Chromium**: guest submit → register →
  bad login → login → submit with the damaged-battery box and a malicious device name →
  dashboard counts → join a drive → admin advances status twice → public tracking timeline →
  unknown ID error → impact figures. Everything behaved as described above, and the
  only browser console errors were the two deliberate failures (bad password, unknown ID).
- Not verified: other browsers, mobile layouts of the new elements, and the MySQL schema.


## 10. Improvements and reliability notes

This upgraded version adds a lightweight health endpoint (`GET /api/health`) that checks both the Flask route and a database query. It returns only a generic status and does not disclose database paths or credentials. Security headers now include a restrictive referrer policy, a permissions policy that disables browser camera/microphone/location access for this site, and HSTS only when the request is already HTTPS. API responses remain `no-store` to reduce accidental caching of private data.

The e-waste submission API now requires `battery_damaged` to be a real JSON boolean. Previously, JavaScript/Python-style truthiness could make the string `"false"` behave like `true`, incorrectly forcing the “Specialized Handling” recommendation. The frontend now reports logout failures instead of silently leaving the user uncertain, and form messages are announced to assistive technology.

The test suite includes checks for the health endpoint, important security headers and strict battery-flag validation. Run it with `python -m unittest discover -s tests -v` from `backend/`. A successful Python syntax compilation alone does not replace running these tests; install the dependency listed in `requirements.txt` first.

## 11. Important limitations / next steps

- Tracking IDs are intentionally public lookup keys. The tracking response omits contact details and pickup location, but the ID should still be shared only with the person who needs it.
- The “Certificates” dashboard tile counts processed submissions; this prototype does not generate downloadable certificates.
- Admin creation of community drives is available through the protected API; a dedicated drive-management form can be added to the admin page.
- Authentication currently uses signed session cookies. For public deployment, configure HTTPS and `ECYCLE_SECURE_COOKIES=1`, set a strong persistent `ECYCLE_SECRET_KEY`, run behind a production WSGI server, back up the database, and add rate limiting, account recovery and operational monitoring.
- This release has not been penetration-tested. Review deployment settings and dependencies before exposing it to the public internet.


## Latest functional improvements

### Tracking journey history
The public tracking endpoint returns a chronological list of status changes, timestamps, and operational notes. It deliberately omits account identity, email, phone, location, and the private submission description. The tracking page displays this history below the stage timeline.

### Admin operations
The admin queue can be filtered by workflow status and manually refreshed. When advancing a submission, an administrator can add an optional note; if no note is entered, the backend uses the standard stage description. The admin page also includes a form to create community collection drives. The API validates drive dates server-side and rejects newly created drives dated in the past. Only accounts with the `admin` role can use these endpoints.

### Test coverage added
Automated tests now check that tracking history grows with the status workflow and that admins can create future drives but cannot create past drives. Run `python -m unittest discover -s tests -v` from the `backend` directory after installing `requirements.txt`.
